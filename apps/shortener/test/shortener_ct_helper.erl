-module(shortener_ct_helper).

-include_lib("common_test/include/ct.hrl").

-export([mock_services/2]).
-export([get_app_config/3]).
-export([get_app_config/4]).

-type config() :: [{atom(), any()}].

-define(SHORTENER_IP, "::").
-define(SHORTENER_PORT, 8080).
-define(SHORTENER_HOST_NAME, "localhost").
-define(SHORTENER_URL, ?SHORTENER_HOST_NAME ++ ":" ++ integer_to_list(?SHORTENER_PORT)).

-spec mock_services(list(), config()) -> _.
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
    {make_path(ServiceName), {WoodyService, {shortener_dummy_service, #{function => Fun}}}}.

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

-spec get_app_config(_, _, _) -> _.
get_app_config(Port, Netloc, PemFile) ->
    get_app_config(Port, Netloc, PemFile, <<"http://machinegun:8022/v1/automaton">>).

-spec get_app_config(_, _, _, _) -> _.
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
