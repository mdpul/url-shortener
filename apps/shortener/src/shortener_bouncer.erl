-module(shortener_bouncer).

-include_lib("bouncer_proto/include/bouncer_decisions_thrift.hrl").
-include_lib("bouncer_proto/include/bouncer_context_v1_thrift.hrl").

%% API

-export([judge/2]).

%%

-type operation_id() :: binary().
-type user_id() :: binary().
-type id() :: shortener_slug:id().
-type owner() :: shortener_slug:owner().
-type woody_context() :: woody_context:ctx().

-type judge_context() :: #{
    user_id := user_id(),
    operation_id := operation_id(),
    id => id(),
    owner => owner()
}.

-define(APP, shortener).

-type service_name() :: atom().

-export_type([service_name/0]).
-export_type([judge_context/0]).

-spec judge(judge_context(), woody_context()) ->
    boolean().

judge(JudgeContext, WoodyContext) ->
    case judge_(JudgeContext, WoodyContext) of
        {ok, Judgement} ->
            Judgement;
        %% TODO mb 500 on error here (error only caused by miss config)
        _ ->
            false
    end.

-spec judge_(judge_context(), woody_context()) ->
    {ok, boolean()}
    | {error,
        {ruleset, notfound | invalid}
        | {context, invalid}}.

judge_(JudgeContext, WoodyContext) ->
    Args = collect_judge_context(JudgeContext, WoodyContext),
    case call_service(bouncer, 'Judge', [Args], WoodyContext) of
        {ok, Judgement} ->
            {ok, parse_judgement(Judgement)};
        {exception, #bdcs_RulesetNotFound{}} ->
            {error, {ruleset, notfound}};
        {exception, #bdcs_InvalidRuleset{}} ->
            {error, {ruleset, invalid}};
        {exception, #bdcs_InvalidContext{}} ->
            {error, {context, invalid}}
    end.

%%

collect_judge_context(JudgeContext = #{operation_id := ID, user_id := UserID}, WoodyContext) ->
    ContextFragment = #bctx_v1_ContextFragment{
        vsn = 1,
        auth = #bctx_v1_Auth{
            method = <<"SessionToken">>
        },
        user = collect_user_context(UserID, WoodyContext),
        requester = #bctx_v1_Requester{ip = <<"">>},
        shortener = #bctx_v1_ContextUrlShortener{op = #bctx_v1_UrlShortenerOperation{
            id = ID,
            shortened_url = #bctx_v1_ShortenedUrl{
                id = maps:get(id, JudgeContext, undefined),
                owner = #bctx_v1_Entity{
                    id = maps:get(owner, JudgeContext, undefined)
                }
            }
        }}
    },
    Type = {struct, struct, {bouncer_context_v1_thrift, 'ContextFragment'}},
    #{
        <<"api">> => #bctx_ContextFragment{
            type = v1_thrift_binary,
            content = serialize(Type, ContextFragment)
        }
    }.

collect_user_context(UserID, _WoodyContext) ->
    %% TODO add org managment call here
    #bctx_v1_User{
        id = UserID,
        orgs = [
            #bctx_v1_Organization{
                %% UserID = PartyID = OrganizationID
                id = UserID,
                owner = #bctx_v1_Entity{
                    %% User is organization owner
                    id = UserID
                }
            }
        ]
    }.

parse_judgement(#bdcs_Judgement{resolution = allowed}) ->
    true;
parse_judgement(#bdcs_Judgement{resolution = forbidden}) ->
    false.

%%

-spec serialize(_ThriftType, term()) -> binary().

serialize(Type, Data) ->
    {ok, Trans} = thrift_membuffer_transport:new(),
    {ok, Proto} = new_protocol(Trans),
    case thrift_protocol:write(Proto, {Type, Data}) of
        {NewProto, ok} ->
            {_, {ok, Result}} = thrift_protocol:close_transport(NewProto),
            Result;
        {_NewProto, {error, Reason}} ->
            erlang:error({thrift, {protocol, Reason}})
    end.

new_protocol(Trans) ->
    thrift_binary_protocol:new(Trans, [{strict_read, true}, {strict_write, true}]).

%%

-spec call_service(service_name(), woody:func(), [term()], woody_context:ctx()) ->
    woody:result().

call_service(ServiceName, Function, Args, Context) ->
    call_service(ServiceName, Function, Args, Context, scoper_woody_event_handler).

-spec call_service(service_name(), woody:func(), [term()], woody_context:ctx(), woody:ev_handler()) ->
    woody:result().

call_service(ServiceName, Function, Args, Context0, EventHandler) ->
    Deadline = get_service_deadline(ServiceName),
    Context1 = set_deadline(Deadline, Context0),
    Retry = get_service_retry(ServiceName, Function),
    call_service(ServiceName, Function, Args, Context1, EventHandler, Retry).

call_service(ServiceName, Function, Args, Context, EventHandler, Retry) ->
    Url = get_service_url(ServiceName),
    Service = get_service_modname(ServiceName),
    Request = {Service, Function, Args},
    try
        woody_client:call(
            Request,
            #{url => Url, event_handler => EventHandler},
            Context
        )
    catch
        error:{woody_error, {_Source, Class, _Details}} = Error
        when Class =:= resource_unavailable orelse Class =:= result_unknown
        ->
            NextRetry = apply_retry_strategy(Retry, Error, Context),
            call_service(ServiceName, Function, Args, Context, EventHandler, NextRetry)
    end.

apply_retry_strategy(Retry, Error, Context) ->
    apply_retry_step(genlib_retry:next_step(Retry), woody_context:get_deadline(Context), Error).

apply_retry_step(finish, _, Error) ->
    erlang:error(Error);
apply_retry_step({wait, Timeout, Retry}, undefined, _) ->
    ok = timer:sleep(Timeout),
    Retry;
apply_retry_step({wait, Timeout, Retry}, Deadline0, Error) ->
    Deadline1 = woody_deadline:from_unixtime_ms(
        woody_deadline:to_unixtime_ms(Deadline0) - Timeout
    ),
    case woody_deadline:is_reached(Deadline1) of
        true ->
            % no more time for retries
            erlang:error(Error);
        false ->
            ok = timer:sleep(Timeout),
            Retry
    end.

get_service_url(ServiceName) ->
    maps:get(ServiceName, genlib_app:env(?APP, service_urls)).

-spec get_service_modname(service_name()) -> woody:service().

get_service_modname(bouncer) ->
    {bouncer_decisions_thrift, 'Arbiter'}.

-spec get_service_deadline(service_name()) -> undefined | woody_deadline:deadline().

get_service_deadline(ServiceName) ->
    ServiceDeadlines = genlib_app:env(?APP, api_deadlines, #{}),
    case maps:get(ServiceName, ServiceDeadlines, undefined) of
        Timeout when is_integer(Timeout) andalso Timeout >= 0 ->
            woody_deadline:from_timeout(Timeout);
        undefined ->
            undefined
    end.

set_deadline(Deadline, Context) ->
    case woody_context:get_deadline(Context) of
        undefined ->
            woody_context:set_deadline(Deadline, Context);
        _AlreadySet ->
            Context
    end.

get_service_retry(ServiceName, Function) ->
    ServiceRetries = genlib_app:env(?APP, service_retries, #{}),
    FunctionReties = maps:get(ServiceName, ServiceRetries, #{}),
    DefaultRetry = maps:get('_', FunctionReties, finish),
    maps:get(Function, FunctionReties, DefaultRetry).
