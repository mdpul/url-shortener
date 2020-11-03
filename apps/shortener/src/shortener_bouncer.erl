-module(shortener_bouncer).

-include_lib("bouncer_proto/include/bouncer_decisions_thrift.hrl").
-include_lib("bouncer_proto/include/bouncer_context_v1_thrift.hrl").

%% API

-export([judge/2]).
-export([make_env_context_builder/0]).
-export([make_auth_context_builder/2]).
-export([make_user_context_builder/2]).
-export([make_requester_context_builder/1]).
-export([make_shortener_context_builder/3]).

%%

-define(APP, shortener).
-define(BLANK_CONTEXT, #bctx_v1_ContextFragment{vsn = 1}).

%%

-type operation_id() :: binary().
-type auth_method() :: binary().
-type timestamp() :: pos_integer().
-type ip() :: string() | undefined.
-type user_id() :: binary().
-type id() :: shortener_slug:id().
-type owner() :: shortener_slug:owner().
-type woody_context() :: woody_context:ctx().

-type context_fragment_id() :: binary().
-type context_fragment() :: bouncer_context_v1_thrift:'ContextFragment'().
-type context_builder() :: fun((context_fragment()) -> {context_fragment_id(), context_fragment()}).

-type judge_context() :: #{
    builders := [context_builder()]
}.

-type service_name() :: atom().

-export_type([service_name/0]).
-export_type([judge_context/0]).
-export_type([context_builder/0]).

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
    Context = collect_judge_context(JudgeContext),
    case call_service(bouncer, 'Judge', {<<"service/authz/api">>, Context}, WoodyContext) of
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

collect_judge_context(#{builders := Builders}) ->
    Type = {struct, struct, {bouncer_context_v1_thrift, 'ContextFragment'}},
    Fragments = lists:foldl(fun(Builder, Acc0) ->
        {FragmentID, Fragment} = Builder(?BLANK_CONTEXT),
        Acc0#{FragmentID => #bctx_ContextFragment{
            type = v1_thrift_binary,
            content = encode_context_fragment(Type, Fragment)
        }}
    end, #{}, Builders),
    #bdcs_Context{fragments = Fragments}.

%% Builders

-spec make_env_context_builder() ->
    context_builder().
make_env_context_builder() ->
    fun(BlankContext) ->
        {<<"env">>, BlankContext#bctx_v1_ContextFragment{
            env = #bctx_v1_Environment{
                now = genlib_rfc3339:format(genlib_time:unow(), second)
            }
        }}
    end.

-spec make_auth_context_builder(auth_method(), timestamp() | undefined) ->
    context_builder().
make_auth_context_builder(Method, Expiration) ->
    fun(BlankContext) ->
        {<<"auth">>, BlankContext#bctx_v1_ContextFragment{
            auth = #bctx_v1_Auth{
                method = Method,
                expiration = maybe_format_time(Expiration)
            }
        }}
    end.

maybe_format_time(undefined) ->
    undefined;
maybe_format_time(Expiration) ->
    genlib_rfc3339:format(Expiration, second).

-spec make_user_context_builder(user_id(), woody_context()) ->
    context_builder().
make_user_context_builder(UserID, _WoodyContext) ->
    %% TODO add org managment call here
    fun(BlankContext) ->
        {<<"user">>, BlankContext#bctx_v1_ContextFragment{
            user = #bctx_v1_User{
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
            }
        }}
    end.

-spec make_requester_context_builder(ip()) ->
    context_builder().
make_requester_context_builder(IP0) ->
    IP1 = case IP0 of
        undefined ->
            undefined;
        IP0 ->
            list_to_binary(IP0)
    end,
    fun(BlankContext) ->
        {<<"requester">>, BlankContext#bctx_v1_ContextFragment{
            requester = #bctx_v1_Requester{
                ip = IP1
            }
        }}
    end.

-spec make_shortener_context_builder(operation_id(), id() | undefined, owner() | undefined) ->
    context_builder().
make_shortener_context_builder(OperationID, ID, OwnerID) ->
    fun(BlankContext) ->
        {<<"shortener">>, BlankContext#bctx_v1_ContextFragment{
            shortener = #bctx_v1_ContextUrlShortener{op = #bctx_v1_UrlShortenerOperation{
                id = OperationID,
                shortened_url = #bctx_v1_ShortenedUrl{
                    id = ID,
                    owner = #bctx_v1_Entity{
                        id = OwnerID
                    }
                }
            }}
        }}
    end.

%%

parse_judgement(#bdcs_Judgement{resolution = allowed}) ->
    true;
parse_judgement(#bdcs_Judgement{resolution = forbidden}) ->
    false.

%%

encode_context_fragment(Type, ContextFragment) ->
    Codec = thrift_strict_binary_codec:new(),
    case thrift_strict_binary_codec:write(Codec, Type, ContextFragment) of
        {ok, Codec1} ->
            thrift_strict_binary_codec:close(Codec1)
    end.

%%

-spec call_service(service_name(), woody:func(), tuple(), woody_context:ctx()) ->
    woody:result().

call_service(ServiceName, Function, Args, Context) ->
    call_service(ServiceName, Function, Args, Context, scoper_woody_event_handler).

-spec call_service(service_name(), woody:func(), tuple(), woody_context:ctx(), woody:ev_handler()) ->
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
