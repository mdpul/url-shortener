-module(shortener_general_SUITE).

-include_lib("bouncer_proto/include/bouncer_decisions_thrift.hrl").
-include_lib("bouncer_proto/include/bouncer_context_v1_thrift.hrl").

-export([init/1]).
-export([all/0]).
-export([groups/0]).
-export([init_per_suite/1]).
-export([end_per_suite/1]).
-export([init_per_group/2]).
-export([end_per_group/2]).
-export([init_per_testcase/2]).
-export([end_per_testcase/2]).

-export([failed_authorization/1]).
-export([insufficient_permissions/1]).
-export([readonly_permissions/1]).
-export([successful_redirect/1]).
-export([successful_delete/1]).
-export([fordidden_source_url/1]).
-export([url_expired/1]).
-export([always_unique_url/1]).

-export([health_check_passing/1]).

-export([woody_timeout_test/1]).

-export([unsupported_cors_method/1]).
-export([supported_cors_method/1]).
-export([unsupported_cors_header/1]).
-export([supported_cors_header/1]).

-behaviour(supervisor).

%% tests descriptions

-spec init([]) -> {ok, {supervisor:sup_flags(), [supervisor:child_spec()]}}.
init([]) ->
    {ok, {#{strategy => one_for_all, intensity => 1, period => 1}, []}}.

-type config() :: [{atom(), term()}].
-type test_case_name() :: atom().

-define(config(Key, C), (element(2, lists:keyfind(Key, 1, C)))).

-spec all() -> [test_case_name()].
all() ->
    [
        {group, general},
        {group, cors},
        woody_timeout_test,
        health_check_passing
    ].

-spec groups() -> [{atom(), list(), [test_case_name()]}].
groups() ->
    [
        {general, [], [
            failed_authorization,
            insufficient_permissions,
            readonly_permissions,

            successful_redirect,
            successful_delete,
            fordidden_source_url,
            url_expired,
            always_unique_url
        ]},
        {cors, [], [
            unsupported_cors_method,
            supported_cors_method,
            unsupported_cors_header,
            supported_cors_header
        ]}
    ].

-spec init_per_suite(config()) -> config().
init_per_suite(C) ->
    % _ = dbg:tracer(),
    % _ = dbg:p(all, c),
    % _ = dbg:tpl({shortener_swagger_server, '_', '_'}, x),
    Host = "url-shortener",
    Port = 8080,
    Netloc = Host ++ ":" ++ genlib:to_list(Port),
    Apps =
        genlib_app:start_application_with(scoper, [
            {storage, scoper_storage_logger}
        ]),
    [
        {suite_apps, Apps},
        {api_endpoint, "http://" ++ Netloc},
        {host, Host},
        {port, Port},
        {netloc, Netloc}
    ] ++ C.

-spec init_per_group(atom(), config()) -> config().
init_per_group(_Group, C) ->
    ShortenerApp =
        genlib_app:start_application_with(
            shortener,
            get_app_config(
                ?config(port, C),
                ?config(netloc, C),
                get_keysource("keys/local/private.pem", C)
            )
        ),
    [
        {shortener_app, ShortenerApp}
    ] ++ C.

-spec end_per_group(atom(), config()) -> _.
end_per_group(_Group, C) ->
    genlib_app:stop_unload_applications(?config(shortener_app, C)).

get_keysource(Key, C) ->
    filename:join(?config(data_dir, C), Key).

-spec end_per_suite(config()) -> term().
end_per_suite(C) ->
    genlib_app:stop_unload_applications(?config(suite_apps, C)).

-spec init_per_testcase(test_case_name(), config()) -> config().
init_per_testcase(_Name, C) ->
    [{test_sup, start_mocked_service_sup(?MODULE)} | C].

-spec end_per_testcase(test_case_name(), config()) -> config().
end_per_testcase(_Name, C) ->
    stop_mocked_service_sup(?config(test_sup, C)),
    ok.

%%

start_mocked_service_sup(Module) ->
    {ok, SupPid} = supervisor:start_link(Module, []),
    _ = unlink(SupPid),
    SupPid.

-spec stop_mocked_service_sup(pid()) -> _.
stop_mocked_service_sup(SupPid) ->
    exit(SupPid, shutdown).

%%

-spec failed_authorization(config()) -> _.
-spec insufficient_permissions(config()) -> _.
-spec readonly_permissions(config()) -> _.

-spec successful_redirect(config()) -> _.
-spec successful_delete(config()) -> _.
-spec fordidden_source_url(config()) -> _.
-spec url_expired(config()) -> _.
-spec always_unique_url(config()) -> _.

failed_authorization(C) ->
    Params = construct_params(<<"https://oops.io/">>),
    C1 = clean_api_auth_token(C),
    {ok, 401, _, _} = shorten_url(Params, C1),
    {ok, 401, _, _} = delete_shortened_url(<<"42">>, C1),
    {ok, 401, _, _} = get_shortened_url(<<"42">>, C1).

insufficient_permissions(C) ->
    mock_services(
        [
            {bouncer, fun('Judge', _) -> {ok, #bdcs_Judgement{resolution = forbidden}} end}
        ],
        C
    ),
    C1 = set_api_auth_token(insufficient_permissions, [], C),
    Params = construct_params(<<"https://oops.io/">>),
    {ok, 403, _, _} = shorten_url(Params, C1),
    {ok, 403, _, _} = delete_shortened_url(<<"42">>, C1),
    {ok, 403, _, _} = get_shortened_url(<<"42">>, C1).

readonly_permissions(C) ->
    mock_services(
        [
            {bouncer, fun('Judge', {_RulesetID, Fragments}) ->
                case get_operation_id(Fragments) of
                    <<"ShortenUrl">> ->
                        {ok, #bdcs_Judgement{resolution = allowed}};
                    <<"GetShortenedUrl">> ->
                        {ok, #bdcs_Judgement{resolution = allowed}};
                    <<"DeleteShortenedUrl">> ->
                        {ok, #bdcs_Judgement{resolution = forbidden}}
                end
            end}
        ],
        C
    ),
    C1 = set_api_auth_token(readonly_permissions, [read, write], C),
    Params = construct_params(<<"https://oops.io/">>),
    {ok, 201, _, #{<<"id">> := ID}} = shorten_url(Params, C1),
    C2 = set_api_auth_token(readonly_permissions, [read], C1),
    {ok, 200, _, #{<<"id">> := ID}} = get_shortened_url(ID, C2),
    {ok, 403, _, _} = delete_shortened_url(ID, C2).

successful_redirect(C) ->
    mock_services(
        [
            {bouncer, fun('Judge', _) -> {ok, #bdcs_Judgement{resolution = allowed}} end}
        ],
        C
    ),
    C1 = set_api_auth_token(successful_redirect, [read, write], C),
    SourceUrl = <<"https://example.com/">>,
    Params = construct_params(SourceUrl),
    {ok, 201, _, #{<<"id">> := ID, <<"shortenedUrl">> := ShortUrl}} = shorten_url(Params, C1),
    {ok, 200, _, #{<<"sourceUrl">> := SourceUrl, <<"shortenedUrl">> := ShortUrl}} = get_shortened_url(ID, C1),
    {ok, 301, Headers, _} = hackney:request(get, ShortUrl),
    {<<"location">>, SourceUrl} = lists:keyfind(<<"location">>, 1, Headers).

successful_delete(C) ->
    mock_services(
        [
            {bouncer, fun('Judge', _) -> {ok, #bdcs_Judgement{resolution = allowed}} end}
        ],
        C
    ),
    C1 = set_api_auth_token(successful_delete, [read, write], C),
    Params = construct_params(<<"https://oops.io/">>),
    {ok, 201, _, #{<<"id">> := ID, <<"shortenedUrl">> := ShortUrl}} = shorten_url(Params, C1),
    {ok, 204, _, _} = delete_shortened_url(ID, C1),
    {ok, 404, _, _} = get_shortened_url(ID, C1),
    {ok, 404, _, _} = hackney:request(get, ShortUrl).

fordidden_source_url(C) ->
    mock_services(
        [
            {bouncer, fun('Judge', _) -> {ok, #bdcs_Judgement{resolution = allowed}} end}
        ],
        C
    ),
    C1 = set_api_auth_token(fordidden_source_url, [read, write], C),
    {ok, 201, _, #{}} = shorten_url(construct_params(<<"http://localhost/hack?id=42">>), C1),
    {ok, 201, _, #{}} = shorten_url(construct_params(<<"https://localhost/hack?id=42">>), C1),
    {ok, 400, _, #{}} = shorten_url(construct_params(<<"http://example.io/">>), C1),
    {ok, 400, _, #{}} = shorten_url(construct_params(<<"http://local.domain/phpmyadmin">>), C1),
    {ok, 201, _, #{}} = shorten_url(construct_params(<<"ftp://ftp.hp.com/pub/hpcp/newsletter_july2003">>), C1).

url_expired(C) ->
    mock_services(
        [
            {bouncer, fun('Judge', _) -> {ok, #bdcs_Judgement{resolution = allowed}} end}
        ],
        C
    ),
    C1 = set_api_auth_token(url_expired, [read, write], C),
    Params = construct_params(<<"https://oops.io/">>, 1),
    {ok, 201, _, #{<<"id">> := ID, <<"shortenedUrl">> := ShortUrl}} = shorten_url(Params, C1),
    {ok, 200, _, #{<<"shortenedUrl">> := ShortUrl}} = get_shortened_url(ID, C1),
    ok = timer:sleep(2 * 1000),
    {ok, 404, _, _} = get_shortened_url(ID, C1),
    {ok, 404, _, _} = hackney:request(get, ShortUrl).

always_unique_url(C) ->
    mock_services(
        [
            {bouncer, fun('Judge', _) -> {ok, #bdcs_Judgement{resolution = allowed}} end}
        ],
        C
    ),
    C1 = set_api_auth_token(always_unique_url, [read, write], C),
    N = 42,
    Params = construct_params(<<"https://oops.io/">>, 3600),
    {IDs, ShortUrls} = lists:unzip([
        {ID, ShortUrl}
        || _ <- lists:seq(1, N),
           {ok, 201, _, #{<<"id">> := ID, <<"shortenedUrl">> := ShortUrl}} <- [shorten_url(Params, C1)]
    ]),
    N = length(lists:usort(IDs)),
    N = length(lists:usort(ShortUrls)).

%% cors
-spec unsupported_cors_method(config()) -> _.
-spec supported_cors_method(config()) -> _.
-spec unsupported_cors_header(config()) -> _.
-spec supported_cors_header(config()) -> _.

unsupported_cors_method(C) ->
    mock_services(
        [
            {bouncer, fun('Judge', _) -> {ok, #bdcs_Judgement{resolution = allowed}} end}
        ],
        C
    ),
    SourceUrl = <<"https://oops.io/">>,
    Params = construct_params(SourceUrl),
    C1 = set_api_auth_token(unsupported_cors_method, [read, write], C),
    {ok, 201, _, #{<<"shortenedUrl">> := ShortUrl}} = shorten_url(Params, C1),
    ReqHeaders = [{<<"origin">>, <<"localhost">>}, {<<"access-control-request-method">>, <<"PATCH">>}],
    {ok, 200, Headers, _} = hackney:request(options, ShortUrl, ReqHeaders),
    false = lists:member(<<"access-control-allow-methods">>, Headers).

supported_cors_method(C) ->
    mock_services(
        [
            {bouncer, fun('Judge', _) -> {ok, #bdcs_Judgement{resolution = allowed}} end}
        ],
        C
    ),
    SourceUrl = <<"https://oops.io/">>,
    Params = construct_params(SourceUrl),
    C1 = set_api_auth_token(supported_cors_method, [read, write], C),
    {ok, 201, _, #{<<"shortenedUrl">> := ShortUrl}} = shorten_url(Params, C1),
    ReqHeaders = [{<<"origin">>, <<"localhost">>}, {<<"access-control-request-method">>, <<"GET">>}],
    {ok, 200, Headers, _} = hackney:request(options, ShortUrl, ReqHeaders),
    {Allowed, _} = shortener_cors_policy:allowed_methods(undefined, undefined),
    {_, Returned} = lists:keyfind(<<"access-control-allow-methods">>, 1, Headers),
    Allowed = binary:split(Returned, <<",">>, [global]).

supported_cors_header(C) ->
    mock_services(
        [
            {bouncer, fun('Judge', _) -> {ok, #bdcs_Judgement{resolution = allowed}} end}
        ],
        C
    ),
    SourceUrl = <<"https://oops.io/">>,
    Params = construct_params(SourceUrl),
    C1 = set_api_auth_token(supported_cors_header, [read, write], C),
    {ok, 201, _, #{<<"shortenedUrl">> := ShortUrl}} = shorten_url(Params, C1),
    ReqHeaders = [
        {<<"origin">>, <<"localhost">>},
        {<<"access-control-request-method">>, <<"GET">>},
        {<<"access-control-request-headers">>, <<"content-type,authorization">>}
    ],
    {ok, 200, Headers, _} = hackney:request(options, ShortUrl, ReqHeaders),
    {Allowed, _} = shortener_cors_policy:allowed_headers(undefined, undefined),
    {_, Returned} = lists:keyfind(<<"access-control-allow-headers">>, 1, Headers),
    % truncate origin
    [_ | Allowed] = binary:split(Returned, <<",">>, [global]).

unsupported_cors_header(C) ->
    mock_services(
        [
            {bouncer, fun('Judge', _) -> {ok, #bdcs_Judgement{resolution = allowed}} end}
        ],
        C
    ),
    SourceUrl = <<"https://oops.io/">>,
    Params = construct_params(SourceUrl),
    C1 = set_api_auth_token(unsupported_cors_header, [read, write], C),
    {ok, 201, _, #{<<"shortenedUrl">> := ShortUrl}} = shorten_url(Params, C1),
    ReqHeaders = [
        {<<"origin">>, <<"localhost">>},
        {<<"access-control-request-method">>, <<"GET">>},
        {<<"access-control-request-headers">>, <<"content-type,42">>}
    ],
    {ok, 200, Headers, _} = hackney:request(options, ShortUrl, ReqHeaders),
    false = lists:member(<<"access-control-allow-headers">>, Headers),
    false = lists:member(<<"access-control-allow-credentials">>, Headers),
    false = lists:member(<<"access-control-allow-methods">>, Headers),
    false = lists:member(<<"access-control-allow-origin">>, Headers).

construct_params(SourceUrl) ->
    construct_params(SourceUrl, 3600).

construct_params(SourceUrl, Lifetime) ->
    #{
        <<"sourceUrl">> => SourceUrl,
        <<"expiresAt">> => format_ts(genlib_time:unow() + Lifetime)
    }.

%%
-spec woody_timeout_test(config()) -> _.
woody_timeout_test(C) ->
    Apps = genlib_app:start_application_with(
        shortener,
        get_app_config(
            ?config(port, C),
            ?config(netloc, C),
            get_keysource("keys/local/private.pem", C),
            <<"http://invalid_url:8022/v1/automaton">>
        )
    ),
    mock_services(
        [
            {bouncer, fun('Judge', _) -> {ok, #bdcs_Judgement{resolution = allowed}} end}
        ],
        C
    ),
    C2 = set_api_auth_token(woody_timeout_test, [read, write], C),
    SourceUrl = <<"https://example.com/">>,
    Params = construct_params(SourceUrl),
    {Time, {error, {invalid_response_code, 503}}} =
        timer:tc(fun() ->
            shorten_url(Params, C2)
        end),
    true = (Time >= 3000000),
    genlib_app:stop_unload_applications(Apps).

%%
-spec health_check_passing(config()) -> _.
health_check_passing(C) ->
    Apps = genlib_app:start_application_with(
        shortener,
        get_app_config(
            ?config(port, C),
            ?config(netloc, C),
            get_keysource("keys/local/private.pem", C)
        )
    ),
    Path = ?config(api_endpoint, C) ++ "/health",
    {ok, 200, _, Payload} = hackney:request(get, Path, [], <<>>, [with_body]),
    #{<<"service">> := <<"shortener">>} = jsx:decode(Payload, [return_maps]),
    genlib_app:stop_unload_applications(Apps).

%%
set_api_auth_token(Name, Permissions, C) ->
    UserID = genlib:to_binary(Name),
    ACL = construct_shortener_acl(Permissions),
    {ok, T} = shortener_authorizer_jwt:issue({{UserID, shortener_acl:from_list(ACL)}, #{}}, unlimited),
    lists:keystore(api_auth_token, 1, C, {api_auth_token, T}).

clean_api_auth_token(C) ->
    lists:keydelete(api_auth_token, 1, C).

construct_shortener_acl(Permissions) ->
    lists:map(fun(P) -> {['shortened-urls'], P} end, Permissions).

%%

shorten_url(ShortenedUrlParams, C) ->
    swag_client_shortener_api:shorten_url(
        ?config(api_endpoint, C),
        append_common_params(#{body => ShortenedUrlParams}, C)
    ).

delete_shortened_url(ID, C) ->
    swag_client_shortener_api:delete_shortened_url(
        ?config(api_endpoint, C),
        append_common_params(#{binding => #{<<"shortenedUrlID">> => ID}}, C)
    ).

get_shortened_url(ID, C) ->
    swag_client_shortener_api:get_shortened_url(
        ?config(api_endpoint, C),
        append_common_params(#{binding => #{<<"shortenedUrlID">> => ID}}, C)
    ).

append_common_params(Params, C) ->
    append_media_type(
        append_auth(
            append_request_id(
                maps:merge(#{binding => #{}, qs_val => #{}, header => #{}, body => #{}}, Params)
            ),
            C
        )
    ).

append_media_type(Params = #{header := Headers}) ->
    Params#{
        header => Headers#{
            <<"Accept">> => <<"application/json">>,
            <<"Content-Type">> => <<"application/json; charset=utf-8">>
        }
    }.

append_auth(Params = #{header := Headers}, C) ->
    case lists:keyfind(api_auth_token, 1, C) of
        {api_auth_token, AuthToken} ->
            Params#{header => Headers#{<<"Authorization">> => <<"Bearer ", AuthToken/binary>>}};
        _ ->
            Params
    end.

append_request_id(Params = #{header := Headers}) ->
    Params#{header => Headers#{<<"X-Request-ID">> => woody_context:new_req_id()}}.

format_ts(Ts) ->
    genlib_rfc3339:format(Ts, second).

get_operation_id(#bdcs_Context{
    fragments = #{
        <<"shortener">> := #bctx_ContextFragment{
            type = v1_thrift_binary,
            content = Fragment
        }
    }
}) ->
    case decode(Fragment) of
        {error, _} = Error ->
            error(Error);
        #bctx_v1_ContextFragment{
            shortener = #bctx_v1_ContextUrlShortener{op = #bctx_v1_UrlShortenerOperation{id = OperationID}}
        } ->
            OperationID
    end.

decode(Content) ->
    Type = {struct, struct, {bouncer_context_v1_thrift, 'ContextFragment'}},
    Codec = thrift_strict_binary_codec:new(Content),
    case thrift_strict_binary_codec:read(Codec, Type) of
        {ok, CtxThrift, Codec1} ->
            case thrift_strict_binary_codec:close(Codec1) of
                <<>> ->
                    CtxThrift;
                Leftovers ->
                    {error, {excess_binary_data, Leftovers}}
            end;
        Error ->
            Error
    end.

%%

-define(SHORTENER_IP, "::").
-define(SHORTENER_PORT, 8080).
-define(SHORTENER_HOST_NAME, "localhost").
-define(SHORTENER_URL, ?SHORTENER_HOST_NAME ++ ":" ++ integer_to_list(?SHORTENER_PORT)).

mock_services(Services, SupOrConfig) ->
    maps:map(fun set_cfg/2, mock_services_(Services, SupOrConfig)).

set_cfg(Service = bouncer, Url) ->
    {ok, Clients} = application:get_env(shortener, service_clients),
    #{Service := BouncerCfg} = Clients,
    ok = application:set_env(
        shortener,
        service_clients,
        Clients#{Service => BouncerCfg#{url => Url}}
    ).

mock_services_(Services, Config) when is_list(Config) ->
    mock_services_(Services, ?config(test_sup, Config));
mock_services_(Services, SupPid) when is_pid(SupPid) ->
    Name = lists:map(fun get_service_name/1, Services),

    Port = get_random_port(),
    {ok, IP} = inet:parse_address(?SHORTENER_IP),
    ChildSpec = woody_server:child_spec(
        {dummy, Name},
        #{
            ip => IP,
            port => Port,
            event_handler => scoper_woody_event_handler,
            handlers => lists:map(fun mock_service_handler/1, Services)
        }
    ),
    {ok, _} = supervisor:start_child(SupPid, ChildSpec),

    lists:foldl(
        fun(Service, Acc) ->
            ServiceName = get_service_name(Service),
            case ServiceName of
                bouncer ->
                    Acc#{ServiceName => make_url(ServiceName, Port)}
            end
        end,
        #{},
        Services
    ).

get_service_name({ServiceName, _Fun}) ->
    ServiceName;
get_service_name({ServiceName, _WoodyService, _Fun}) ->
    ServiceName.

mock_service_handler({ServiceName, Fun}) ->
    mock_service_handler(ServiceName, get_service_modname(ServiceName), Fun);
mock_service_handler({ServiceName, WoodyService, Fun}) ->
    mock_service_handler(ServiceName, WoodyService, Fun).

mock_service_handler(ServiceName, WoodyService, Fun) ->
    {make_path(ServiceName), {WoodyService, {dummy_service, #{function => Fun}}}}.

get_service_modname(bouncer) ->
    {bouncer_decisions_thrift, 'Arbiter'}.

% TODO not so failproof, ideally we need to bind socket first and then give to a ranch listener
get_random_port() ->
    rand:uniform(32768) + 32767.

make_url(ServiceName, Port) ->
    iolist_to_binary(["http://", ?SHORTENER_HOST_NAME, ":", integer_to_list(Port), make_path(ServiceName)]).

make_path(ServiceName) ->
    "/" ++ atom_to_list(ServiceName).

%%

get_app_config(Port, Netloc, PemFile) ->
    get_app_config(Port, Netloc, PemFile, <<"http://machinegun:8022/v1/automaton">>).

get_app_config(Port, Netloc, PemFile, AutomatonUrl) ->
    [
        {space_size, 8},
        {hash_algorithm, sha256},
        {api, #{
            ip => "::",
            port => Port,
            authorizer => #{
                signee => local,
                keyset => #{
                    local => {pem_file, PemFile}
                }
            },
            source_url_whitelist => [
                "https://*",
                "ftp://*",
                "http://localhost/*"
            ],
            short_url_template => #{
                scheme => http,
                netloc => Netloc,
                path => "/r/e/d/i/r/"
            }
        }},
        {processor, #{
            ip => "::",
            port => 8022
        }},
        {health_check, #{
            service => {erl_health, service, [<<"shortener">>]}
        }},
        {service_clients, #{
            automaton => #{
                url => AutomatonUrl,
                retries => #{
                    % function => retry strategy
                    % '_' work as "any"
                    % default value is 'finish'
                    % for more info look genlib_retry :: strategy()
                    % https://github.com/rbkmoney/genlib/blob/master/src/genlib_retry.erl#L19
                    'Start' => {linear, 3, 1000},
                    'GetMachine' => {linear, 3, 1000},
                    'Remove' => {linear, 3, 1000},
                    '_' => finish
                }
            },
            bouncer => #{
                url => <<"http://bouncer:8022/">>,
                retries => #{
                    % function => retry strategy
                    % '_' work as "any"
                    % default value is 'finish'
                    % for more info look genlib_retry :: strategy()
                    % https://github.com/rbkmoney/genlib/blob/master/src/genlib_retry.erl#L19
                    'Judge' => {linear, 3, 1000},
                    '_' => finish
                }
            }
        }}
    ].
