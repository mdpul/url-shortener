-module(shortener_auth).

-export([authorize_api_key/2]).
-export([authorize_operation/4]).

-type context() :: shortener_authorizer_jwt:t().
-type claims() :: shortener_authorizer_jwt:claims().

-export_type([context/0]).
-export_type([claims/0]).

-spec authorize_api_key(swag_server:operation_id(), swag_server:api_key()) -> {true, Context :: context()} | false.
authorize_api_key(OperationID, ApiKey) ->
    case parse_api_key(ApiKey) of
        {ok, {Type, Credentials}} ->
            case authorize_api_key(OperationID, Type, Credentials) of
                {ok, Context} ->
                    {true, Context};
                {error, Error} ->
                    _ = log_auth_error(OperationID, Error),
                    false
            end;
        {error, Error} ->
            _ = log_auth_error(OperationID, Error),
            false
    end.

log_auth_error(OperationID, Error) ->
    logger:info("API Key authorization failed for ~p due to ~p", [OperationID, Error]).

-spec parse_api_key(swag_server:api_key()) -> {ok, {bearer, Credentials :: binary()}} | {error, Reason :: atom()}.
parse_api_key(ApiKey) ->
    case ApiKey of
        <<"Bearer ", Credentials/binary>> ->
            {ok, {bearer, Credentials}};
        _ ->
            {error, unsupported_auth_scheme}
    end.

-spec authorize_api_key(swag_server:operation_id(), Type :: atom(), Credentials :: binary()) ->
    {ok, context()} | {error, Reason :: atom()}.
authorize_api_key(_OperationID, bearer, Token) ->
    shortener_authorizer_jwt:verify(Token).

-spec authorize_operation(OperationID, Slug, Context, WoodyCtx) -> ok | {error, forbidden} when
    OperationID :: swag_server:operation_id(),
    Slug :: shortener_slug:slug() | no_slug,
    Context :: context(),
    WoodyCtx :: woody_context:ctx().
authorize_operation(OperationID, Slug, {{SubjectID, _ACL}, _Claims}, WoodyCtx) ->
    Owner = get_slug_owner(Slug),
    ID = get_slug_id(Slug),
    JudgeContext = #{
        user_id => SubjectID,
        operation_id => OperationID,
        id => ID,
        owner => Owner
    },
    case shortener_bouncer:judge(JudgeContext, WoodyCtx) of
        true ->
            ok;
        false ->
            {error, forbidden}
    end.

-spec get_slug_owner(shortener_slug:slug() | no_slug) -> shortener_slug:owner() | undefined.
get_slug_owner(no_slug) ->
    undefined;
get_slug_owner(#{owner := Owner}) ->
    Owner.

-spec get_slug_id(shortener_slug:slug() | no_slug) -> shortener_slug:id() | undefined.
get_slug_id(no_slug) ->
    undefined;
get_slug_id(#{id := ID}) ->
    ID.
