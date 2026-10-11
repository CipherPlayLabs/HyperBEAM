%%% @doc `bridge@1.0': this node as one attestor of the PUSD bridge
%%% (paralith-mono products/bridge/BRIDGE_NATIVE.md).
%%%
%%% A background loop, started by the node's `start' hook, that on every pass:
%%%
%%%   1. reads PUSD's published `bridgeinfo' and `withdrawals';
%%%   2. scans Base (through `eth-client@1.0'), Solana and Sui for deposits and
%%%      releases since its cursors;
%%%   3. attests each unminted deposit with `Bridge-Mint';
%%%   4. signs each pending withdrawal for its chain with `Bridge-Sign';
%%%   5. acknowledges each release it saw with `Bridge-Released';
%%%   6. votes on each open membership proposal its operator approved
%%%      (`Attestor-Approve' on PUSD), signing the new set for every chain.
%%%
%%% Succession: when PUSD publishes a `successor' (its set voted to move), the
%%% node moves there, but only if the successor names this PUSD as its
%%% `predecessor' and holds the same set at the same epoch. Where it is is kept
%%% in the `follow-file', so a node that missed several moves walks the chain
%%% one hop per pass. The configured `pusd' is where that walk starts; setting
%%% a different one in the config restarts it from there.
%%%
%%% Every message is committed with the node's own wallet, so the node's address
%%% IS its AO attestor identity. Its Base, Solana and Sui keys live in the
%%% `keys-file', made on first start if absent. The node never pays chain gas:
%%% whoever claims a withdrawal submits the collected signatures.
%%%
%%% Proposals and approvals are made on PUSD by the node's operator, from any
%%% AO wallet; the node only ever signs. Endpoints, both read-only:
%%%   GET  /~bridge@1.0/keys      this node's four public keys, to join a set
%%%   GET  /~bridge@1.0/status    cursors, last pass, last error
%%%
%%% Configuration, under the node option `bridge':
%%%   pusd, pusd-node (the URL of the node that runs PUSD; omit when it is this
%%%   node), interval (ms), keys-file, state-file, follow-file,
%%%   base => #{ rpc, contract, chain-id, confirmations, from-block, log-range },
%%%   solana => #{ rpc, program, commitment }, sui => #{ rpc, package, bridge }
-module(dev_bridge).
-export([info/1, start/3, status/3, keys/3]).
-export([proposals_to_vote/2, successor_ok/3]).
-export([withdrawal_signature/4, minted/3]).
-include("include/hb.hrl").
-include_lib("eunit/include/eunit.hrl").

-define(NAME, {<<"bridge@1.0">>, loop}).
-define(RESEND_MS, 60000).

info(_) ->
    #{ exports => [<<"start">>, <<"status">>, <<"keys">>] }.

%%% Endpoints -----------------------------------------------------------------

%% @doc The node `start' hook: spawn the loop once, hand the node message back.
%% Never fails: a bridge problem must not stop the node from booting.
start(_Base, Req, Opts) ->
    NodeMsg = hb_maps:get(<<"body">>, Req, Opts, Opts),
    try
        case config(NodeMsg) of
            #{ <<"pusd">> := _ } = Cfg ->
                case hb_name:lookup(?NAME) of
                    Pid when is_pid(Pid) -> ok;
                    _ ->
                        Pid = spawn(fun() -> init(Cfg, NodeMsg) end),
                        hb_name:register(?NAME, Pid)
                end;
            _ ->
                ?event(bridge, {not_configured})
        end
    catch C:R:T -> ?event(bridge, {start_failed, C, R, T})
    end,
    {ok, #{ <<"body">> => NodeMsg }}.

status(_Base, _Req, _Opts) ->
    case call(status) of
        {ok, S} -> {ok, json(S)};
        Error -> Error
    end.

keys(_Base, _Req, _Opts) ->
    case call(keys) of
        {ok, K} -> {ok, json(K)};
        Error -> Error
    end.

call(Msg) ->
    case hb_name:lookup(?NAME) of
        Pid when is_pid(Pid) ->
            Ref = make_ref(),
            Pid ! {Msg, self(), Ref},
            receive {Ref, Reply} -> Reply after 60000 -> {error, timeout} end;
        _ ->
            {error, <<"The bridge loop is not running on this node">>}
    end.

json(Term) ->
    #{ <<"content-type">> => <<"application/json">>, <<"body">> => hb_json:encode(Term) }.

config(Opts) ->
    case hb_opts:get(bridge, #{}, Opts) of
        Cfg when is_map(Cfg) -> Cfg;
        _ -> #{}
    end.

%%% The loop ------------------------------------------------------------------

init(Cfg0, Opts) ->
    Cfg = load_follow(Cfg0),
    Keys = load_keys(maps:get(<<"keys-file">>, Cfg, <<"bridge-keys.json">>)),
    Me = hb_util:human_id(ar_wallet:to_address(hb_opts:get(priv_wallet, no_viable_wallet, Opts))),
    St = #{
        cfg => Cfg, opts => Opts, keys => Keys, me => Me,
        cursors => load_cursors(Cfg), deposits => #{}, releases => #{}, sent => #{},
        last_pass => 0, last_error => null, member => false, namespace => 0
    },
    ?event(bridge, {started, {ao, Me}}),
    self() ! pass,
    loop(St).

loop(St) ->
    receive
        pass ->
            St2 = try pass(St)
                  catch C:R:T ->
                      ?event(bridge, {pass_failed, C, R, T}),
                      St#{ last_error => iolist_to_binary(io_lib:format("~p:~p", [C, R])) }
                  end,
            erlang:send_after(hb_util:int(maps:get(<<"interval">>, maps:get(cfg, St), 5000)), self(), pass),
            loop(St2);
        {status, From, Ref} ->
            From ! {Ref, {ok, status_view(St)}},
            loop(St);
        {keys, From, Ref} ->
            From ! {Ref, {ok, public_keys(St)}},
            loop(St)
    end.

pass(St) ->
    Info = published(<<"bridgeinfo">>, St),
    case maps:get(<<"successor">>, Info, <<>>) of
        Succ when is_binary(Succ), byte_size(Succ) =:= 43 -> follow(Succ, Info, St);
        _ -> attest(Info, St)
    end.

attest(Info, St = #{ cfg := Cfg, me := Me }) ->
    Withdrawals = case published(<<"withdrawals">>, St) of L when is_list(L) -> L; _ -> [] end,
    Member = lists:any(fun(A) -> maps:get(<<"ao">>, A, <<>>) =:= Me end,
        maps:get(<<"attestors">>, Info, [])),
    case Member of
        false ->
            St#{ member => false, last_pass => os:system_time(millisecond) };
        true ->
            {Found, Cursors} = scan(Cfg, maps:get(cursors, St), maps:get(opts, St)),
            save_cursors(Cfg, Cursors),
            Ns = hb_util:int(maps:get(<<"namespace">>, Info, 0)),
            St1 = remember(Found, St#{ cursors => Cursors, member => true, namespace => Ns }),
            St2 = attest_deposits(Info, St1),
            St3 = sign_withdrawals(Withdrawals, St2),
            St4 = acknowledge(Withdrawals, St3),
            St5 = lists:foldl(
                fun(P, S) ->
                    Id = hb_util:int(maps:get(<<"id">>, P)),
                    once(<<"vote:", (integer_to_binary(Id))/binary>>, S, fun() -> vote(P, S) end)
                end, St4, proposals_to_vote(Info, Me)),
            St5#{ last_pass => os:system_time(millisecond), last_error => null }
    end.

%% Every chain that is configured, each failing on its own.
scan(Cfg, Cursors, Opts) ->
    lists:foldl(
        fun(Chain, {Acc, Cur}) ->
            case maps:get(Chain, Cfg, undefined) of
                undefined -> {Acc, Cur};
                C ->
                    case scan_chain(Chain, C, maps:get(Chain, Cur, undefined), Opts) of
                        {ok, Events, Next} -> {Acc ++ Events, Cur#{ Chain => Next }};
                        Error -> ?event(bridge, {scan_failed, Chain, Error}), {Acc, Cur}
                    end
            end
        end, {[], Cursors}, [<<"base">>, <<"solana">>, <<"sui">>]).

scan_chain(<<"base">>, C, Cursor, Opts) ->
    {ok, Head} = hb_bridge_chains:base_head(C, Opts),
    Safe = Head - hb_util:int(maps:get(<<"confirmations">>, C, 12)),
    From = case Cursor of undefined -> hb_util:int(maps:get(<<"from-block">>, C, Safe)); N -> N + 1 end,
    To = min(Safe, From + hb_util:int(maps:get(<<"log-range">>, C, 2000)) - 1),
    case To < From of
        true -> {ok, [], Cursor};
        false ->
            case hb_bridge_chains:base_scan(C, From, To, Opts) of
                {ok, Events} -> {ok, Events, To};
                Error -> Error
            end
    end;
scan_chain(<<"solana">>, C, Cursor, Opts) ->
    Until = case Cursor of undefined -> undefined; null -> undefined; S -> S end,
    hb_bridge_chains:solana_scan(C, Until, Opts);
scan_chain(<<"sui">>, C, Cursor, Opts) ->
    Cur = case Cursor of
        #{ <<"deposit">> := D, <<"released">> := R } -> #{ deposit => undef(D), released => undef(R) };
        _ -> #{}
    end,
    case hb_bridge_chains:sui_scan(C, Cur, Opts) of
        {ok, Events, #{ deposit := D2, released := R2 }} ->
            {ok, Events, #{ <<"deposit">> => null_if(D2), <<"released">> => null_if(R2) }};
        Error -> Error
    end.

undef(null) -> undefined;
undef(X) -> X.
null_if(undefined) -> null;
null_if(X) -> X.

%% Deposits wait here until PUSD shows them minted; releases until the
%% withdrawal is no longer pending.
remember(Found, St = #{ deposits := D, releases := R }) ->
    lists:foldl(
        fun(E = #{ kind := deposit, chain := Chain, nonce := N }, S) ->
                S#{ deposits := (maps:get(deposits, S))#{ deposit_id(Chain, N) => E } };
           (E = #{ kind := released }, S) ->
                case local_withdrawal(maps:get(id, E), S) of
                    false -> S;
                    Id -> S#{ releases := (maps:get(releases, S))#{ Id => E } }
                end
        end, St#{ deposits := D, releases := R }, Found).

attest_deposits(Info, St = #{ deposits := Deps }) ->
    maps:fold(
        fun(Id, #{ chain := Chain, nonce := N } = E, S) ->
            case minted(Info, Chain, N) of
                true -> S#{ deposits := maps:remove(Id, maps:get(deposits, S)) };
                false ->
                    once(Id, S, fun() ->
                        send(#{
                            <<"action">> => <<"Bridge-Mint">>,
                            <<"depositid">> => Id, <<"chain">> => Chain,
                            <<"token">> => maps:get(token, E), <<"recipient">> => maps:get(recipient, E),
                            <<"quantity">> => maps:get(amount, E), <<"sourcetx">> => maps:get(tx, E, <<>>)
                        }, S)
                    end)
            end
        end, St, Deps).

sign_withdrawals(Withdrawals, St = #{ me := Me }) ->
    lists:foldl(
        fun(W, S) ->
            Sigs = maps:get(<<"sigs">>, W, #{}),
            Pending = maps:get(<<"status">>, W, <<>>) =:= <<"pending">>,
            Signed = is_map(Sigs) andalso maps:is_key(Me, Sigs),
            Id = maps:get(<<"id">>, W),
            case Pending andalso not Signed of
                false -> S;
                true ->
                    once(<<"sign:", Id/binary>>, S, fun() ->
                        Sig = withdrawal_signature(W, maps:get(cfg, S), maps:get(keys, S),
                            maps:get(namespace, S)),
                        send(#{ <<"action">> => <<"Bridge-Sign">>, <<"withdrawalid">> => Id,
                            <<"signature">> => Sig }, S)
                    end)
            end
        end, St, Withdrawals).

acknowledge(Withdrawals, St = #{ releases := Rel }) ->
    Pending = maps:from_list([{maps:get(<<"id">>, W), true} || W <- Withdrawals,
        maps:get(<<"status">>, W, <<>>) =:= <<"pending">>]),
    maps:fold(
        fun(Id, E, S) ->
            case maps:is_key(Id, Pending) of
                false -> S#{ releases := maps:remove(Id, maps:get(releases, S)) };
                true ->
                    once(<<"ack:", Id/binary>>, S, fun() ->
                        send(#{ <<"action">> => <<"Bridge-Released">>, <<"withdrawalid">> => Id,
                            <<"desttx">> => maps:get(tx, E, <<>>) }, S)
                    end)
            end
        end, St, Rel).

%% Send at most once per RESEND_MS per key: PUSD is idempotent, but every
%% message is a slot.
once(Key, St = #{ sent := Sent }, Fun) ->
    Now = os:system_time(millisecond),
    case Now - maps:get(Key, Sent, 0) < ?RESEND_MS of
        true -> St;
        false ->
            Fun(),
            St#{ sent := Sent#{ Key => Now } }
    end.

%%% Signatures ----------------------------------------------------------------

%% @doc This node's signature over one withdrawal's release on its chain, as
%% 0x-hex. The chain's withdrawal id carries PUSD's namespace in the high word.
withdrawal_signature(W, Cfg, Keys, Namespace) ->
    Chain = maps:get(<<"chain">>, W),
    C = maps:get(Chain, Cfg),
    Id = (Namespace bsl 32) bor hb_util:int(maps:get(<<"id">>, W)),
    Token = maps:get(<<"token">>, W),
    To = maps:get(<<"to">>, W),
    Amount = maps:get(<<"amount">>, W),
    Sig = case Chain of
        <<"base">> ->
            hb_bridge_sign:base_sign(
                hb_bridge_sign:base_release(hb_util:int(maps:get(<<"chain-id">>, C)),
                    maps:get(<<"contract">>, C), Id, Token, To, Amount),
                maps:get(base, Keys));
        <<"solana">> ->
            hb_bridge_sign:ed25519_sign(
                hb_bridge_sign:solana_release(maps:get(<<"program">>, C), Id, Token, To, Amount),
                maps:get(solana, Keys));
        <<"sui">> ->
            hb_bridge_sign:ed25519_sign(
                hb_bridge_sign:sui_release(maps:get(<<"bridge">>, C), Id, Token, To, Amount),
                maps:get(sui, Keys))
    end,
    <<"0x", (hb_bridge_sign:hex(Sig))/binary>>.

%% @doc Open proposals this node's operator approved and it has not voted on.
proposals_to_vote(Info, Me) ->
    [P || P <- maps:get(<<"proposals">>, Info, []),
        maps:get(<<"status">>, P, <<>>) =:= <<"open">>,
        maps:get(Me, maps:get(<<"approvals">>, P, #{}), false) =:= true,
        not maps:is_key(Me, maps:get(<<"votes">>, P, #{}))].

%% The vote IS the chain authorisation: this node's signature over the
%% proposal's whole set, at its epoch, for each chain. A migration changes no
%% chain, so its vote carries nothing but the proposal.
vote(#{ <<"op">> := <<"migrate">> } = P, St) ->
    send(#{ <<"action">> => <<"Attestor-Vote">>,
        <<"proposalid">> => integer_to_binary(hb_util:int(maps:get(<<"id">>, P))) }, St);
vote(P, St = #{ cfg := Cfg, keys := Keys }) ->
    Id = hb_util:int(maps:get(<<"id">>, P)),
    Set = maps:get(<<"set">>, P),
    Epoch = hb_util:int(maps:get(<<"epoch">>, P)),
    Field = fun(K) -> [maps:get(K, M) || M <- Set] end,
    Hex = fun(S) -> <<"0x", (hb_bridge_sign:hex(S))/binary>> end,
    B = maps:get(<<"base">>, Cfg), Sol = maps:get(<<"solana">>, Cfg), Sui = maps:get(<<"sui">>, Cfg),
    send(#{
        <<"action">> => <<"Attestor-Vote">>, <<"proposalid">> => integer_to_binary(Id),
        <<"basesig">> => Hex(hb_bridge_sign:base_sign(
            hb_bridge_sign:base_attestors(hb_util:int(maps:get(<<"chain-id">>, B)),
                maps:get(<<"contract">>, B), Epoch, Field(<<"base">>)), maps:get(base, Keys))),
        <<"solanasig">> => Hex(hb_bridge_sign:ed25519_sign(
            hb_bridge_sign:solana_attestors(maps:get(<<"program">>, Sol), Epoch, Field(<<"solana">>)),
            maps:get(solana, Keys))),
        <<"suisig">> => Hex(hb_bridge_sign:ed25519_sign(
            hb_bridge_sign:sui_attestors(maps:get(<<"bridge">>, Sui), Epoch, Field(<<"sui">>)),
            maps:get(sui, Keys)))
    }, St).

%%% Succession ----------------------------------------------------------------

%% Move to the successor if it checks out; otherwise stay, say why, and keep
%% attesting here (this PUSD still owes its pending withdrawals).
follow(Succ, Info, St = #{ cfg := Cfg }) ->
    Here = maps:get(<<"pusd">>, Cfg),
    Next = published(<<"bridgeinfo">>, St#{ cfg := Cfg#{ <<"pusd">> => Succ } }),
    case successor_ok(Info, Next, Here) of
        true ->
            Cfg2 = Cfg#{ <<"pusd">> => Succ },
            save_follow(Cfg2),
            ?event(bridge, {followed, {from, Here}, {to, Succ}}),
            St#{ cfg := Cfg2, deposits := #{}, releases := #{}, sent := #{}, namespace := 0,
                last_pass := os:system_time(millisecond), last_error := null };
        {false, Why} ->
            St2 = attest(Info, St),
            St2#{ last_error := <<"not following ", Succ/binary, ": ", Why/binary>> }
    end.

%% @doc Does `Next' (the successor's bridgeinfo) carry on from `Info' (the
%% bridgeinfo of `Here')? It must name `Here' back and hold the same members,
%% keys and epoch: the set that voted to move is the set that arrives.
successor_ok(Info, Next, Here) ->
    Members = fun(I) ->
        [[maps:get(K, M, <<>>) || K <- [<<"ao">>, <<"base">>, <<"solana">>, <<"sui">>]]
            || M <- maps:get(<<"attestors">>, I, [])]
    end,
    Epoch = fun(I) -> hb_util:int(maps:get(<<"epoch">>, I, -1)) end,
    case {Next =:= #{}, maps:get(<<"predecessor">>, Next, <<>>) =:= Here,
            Members(Next) =:= Members(Info), Epoch(Next) =:= Epoch(Info)} of
        {true, _, _, _} -> {false, <<"its bridgeinfo cannot be read">>};
        {_, false, _, _} -> {false, <<"it does not name this PUSD">>};
        {_, _, false, _} -> {false, <<"its set differs">>};
        {_, _, _, false} -> {false, <<"its epoch differs">>};
        _ -> true
    end.

follow_file(Cfg) -> maps:get(<<"follow-file">>, Cfg, <<"bridge-follow.json">>).

%% The configured PUSD, or where the node has followed it to since.
load_follow(Cfg) ->
    Genesis = maps:get(<<"pusd">>, Cfg),
    case file:read_file(follow_file(Cfg)) of
        {ok, Bin} ->
            case catch hb_json:decode(Bin) of
                #{ <<"genesis">> := Genesis, <<"pusd">> := Pusd } -> Cfg#{ <<"pusd">> => Pusd,
                    <<"genesis">> => Genesis };
                _ -> Cfg#{ <<"genesis">> => Genesis }
            end;
        _ -> Cfg#{ <<"genesis">> => Genesis }
    end.

save_follow(Cfg) ->
    File = follow_file(Cfg),
    Tmp = <<File/binary, ".tmp">>,
    ok = file:write_file(Tmp, hb_json:encode(#{ <<"genesis">> => maps:get(<<"genesis">>, Cfg),
        <<"pusd">> => maps:get(<<"pusd">>, Cfg) })),
    ok = file:rename(Tmp, File).

%%% AO ------------------------------------------------------------------------

%% Commit with the node's wallet and schedule onto PUSD: locally as dev_push
%% does when PUSD runs here, else by posting the signed message to the
%% scheduler of the node that runs it, as any wallet client does.
send(Tags, #{ cfg := Cfg, opts := Opts }) ->
    Pusd = maps:get(<<"pusd">>, Cfg),
    Res = case maps:get(<<"pusd-node">>, Cfg, undefined) of
        undefined ->
            Signed = hb_message:commit(Tags#{ <<"target">> => Pusd }, Opts, <<"httpsig@1.0">>),
            {ok, _} = hb_cache:write(Signed, Opts),
            {ok, Proc} = hb_cache:read(Pusd, Opts),
            hb_ao:resolve({as, <<"process@1.0">>, Proc},
                #{ <<"path">> => <<"schedule">>, <<"method">> => <<"POST">>, <<"body">> => Signed }, Opts);
        Node ->
            % `subject: self' or the scheduler schedules the request body.
            Signed = hb_message:commit(Tags#{ <<"target">> => Pusd, <<"type">> => <<"Message">>,
                <<"subject">> => <<"self">> }, Opts, <<"httpsig@1.0">>),
            hb_http:post(Node, <<"/", Pusd/binary, "~process@1.0/schedule">>, Signed, Opts)
    end,
    ?event(bridge, {sent, maps:get(<<"action">>, Tags), Res}),
    Res.

%% A published key as decoded JSON, or #{} when absent (the node answers a
%% missing key with its HTML page, never with an error).
published(Key, #{ cfg := Cfg, opts := Opts }) ->
    Pusd = maps:get(<<"pusd">>, Cfg),
    case maps:get(<<"pusd-node">>, Cfg, undefined) of
        undefined ->
            {ok, Proc} = hb_cache:read(Pusd, Opts),
            json_value(hb_ao:get(<<"now/", Key/binary>>, Proc, not_found, Opts));
        Node ->
            Url = <<Node/binary, "/", Pusd/binary, "~process@1.0/now/", Key/binary>>,
            case hb_bridge_chains:get_body(Url, Opts) of
                {ok, Body} -> json_value(Body);
                _ -> #{}
            end
    end.

%% A published value as decoded JSON. It may arrive as JSON text, as JSON text
%% inside a JSON string, or wrapped in a `body'; an HTML page means absent.
json_value(V) when is_map(V), is_map_key(<<"body">>, V) -> json_value(maps:get(<<"body">>, V));
json_value(V) when is_map(V); is_list(V) -> V;
json_value(<<"<", _/binary>>) -> #{};
json_value(Bin) when is_binary(Bin) ->
    case catch hb_json:decode(Bin) of
        S when is_binary(S) -> json_value(S);
        V when is_map(V); is_list(V) -> json_value(V);
        _ -> #{}
    end;
json_value(_) -> #{}.

%% @doc Has PUSD minted `<chain>:<nonce>'? Its published watermark says.
minted(Info, Chain, Nonce) ->
    P = maps:get(Chain, maps:get(<<"processed">>, Info, #{}), #{}),
    Nonce =< hb_util:int(maps:get(<<"floor">>, P, 0))
        orelse lists:member(Nonce, [hb_util:int(N) || N <- maps:get(<<"above">>, P, [])]).

deposit_id(Chain, N) -> <<Chain/binary, ":", (integer_to_binary(N))/binary>>.

%% A chain withdrawal id is PUSD's only if its high word is PUSD's namespace,
%% which PUSD publishes in `bridgeinfo'.
local_withdrawal(ChainId, #{ namespace := Ns }) ->
    case ChainId bsr 32 of
        Ns -> integer_to_binary(ChainId band 16#FFFFFFFF);
        _ -> false
    end.

%%% Keys and state on disk ----------------------------------------------------

%% The chain keys, made on first start. Hex 32-byte secrets.
load_keys(File) ->
    case file:read_file(File) of
        {ok, Bin} ->
            K = hb_json:decode(Bin),
            #{ base => unhex(maps:get(<<"base">>, K)), solana => unhex(maps:get(<<"solana">>, K)),
               sui => unhex(maps:get(<<"sui">>, K)) };
        {error, enoent} ->
            K = #{ base => crypto:strong_rand_bytes(32), solana => crypto:strong_rand_bytes(32),
                   sui => crypto:strong_rand_bytes(32) },
            ok = file:write_file(File, hb_json:encode(maps:from_list(
                [{atom_to_binary(N), hb_bridge_sign:hex(V)} || {N, V} <- maps:to_list(K)]))),
            _ = file:change_mode(File, 8#600),
            K
    end.

unhex(<<"0x", H/binary>>) -> hb_bridge_sign:unhex(H);
unhex(H) -> hb_bridge_sign:unhex(H).

public_keys(#{ me := Me, keys := K }) ->
    #{
        <<"ao">> => Me,
        <<"base">> => hb_bridge_sign:base_address(maps:get(base, K)),
        <<"solana">> => hb_bridge_sign:base58_encode(hb_bridge_sign:ed25519_public(maps:get(solana, K))),
        <<"sui">> => <<"0x", (hb_bridge_sign:hex(hb_bridge_sign:ed25519_public(maps:get(sui, K))))/binary>>
    }.

load_cursors(Cfg) ->
    case file:read_file(maps:get(<<"state-file">>, Cfg, <<"bridge-state.json">>)) of
        {ok, Bin} -> hb_json:decode(Bin);
        _ -> #{}
    end.

save_cursors(Cfg, Cursors) ->
    File = maps:get(<<"state-file">>, Cfg, <<"bridge-state.json">>),
    Tmp = <<File/binary, ".tmp">>,
    ok = file:write_file(Tmp, hb_json:encode(Cursors)),
    ok = file:rename(Tmp, File).

status_view(St) ->
    #{
        <<"ao">> => maps:get(me, St),
        <<"pusd">> => maps:get(<<"pusd">>, maps:get(cfg, St)),
        <<"member">> => maps:get(member, St),
        <<"cursors">> => maps:get(cursors, St),
        <<"waiting-deposits">> => maps:size(maps:get(deposits, St)),
        <<"waiting-acks">> => maps:size(maps:get(releases, St)),
        <<"last-pass">> => maps:get(last_pass, St),
        <<"last-error">> => maps:get(last_error, St)
    }.

%%% Tests ---------------------------------------------------------------------

proposals_to_vote_test() ->
    Me = <<"me">>,
    P = fun(Id, Status, Appr, Votes) -> #{ <<"id">> => Id, <<"status">> => Status,
        <<"approvals">> => Appr, <<"votes">> => Votes } end,
    Info = #{ <<"proposals">> => [
        P(1, <<"open">>, #{ Me => true }, #{}),
        P(2, <<"open">>, #{ <<"other">> => true }, #{}),
        P(3, <<"open">>, #{ Me => true }, #{ Me => #{} }),
        P(4, <<"applied">>, #{ Me => true }, #{})
    ] },
    ?assertEqual([1], [maps:get(<<"id">>, X) || X <- proposals_to_vote(Info, Me)]).

successor_ok_test() ->
    Here = <<"here">>,
    Set = [#{ <<"ao">> => <<"a">>, <<"base">> => <<"0x1">>, <<"solana">> => <<"S">>, <<"sui">> => <<"0x2">>,
        <<"operator">> => <<"o">> }],
    Info = #{ <<"attestors">> => Set, <<"epoch">> => 3, <<"successor">> => <<"next">> },
    Next = #{ <<"attestors">> => Set, <<"epoch">> => 3, <<"predecessor">> => Here },
    ?assertEqual(true, successor_ok(Info, Next, Here)),
    ?assertMatch({false, _}, successor_ok(Info, #{}, Here)),
    ?assertMatch({false, _}, successor_ok(Info, Next#{ <<"predecessor">> => <<"other">> }, Here)),
    ?assertMatch({false, _}, successor_ok(Info, maps:remove(<<"predecessor">>, Next), Here)),
    ?assertMatch({false, _}, successor_ok(Info, Next#{ <<"epoch">> => 4 }, Here)),
    Other = [(hd(Set))#{ <<"sui">> => <<"0x3">> }],
    ?assertMatch({false, _}, successor_ok(Info, Next#{ <<"attestors">> => Other }, Here)),
    % An operator is not part of what the chains check.
    Moved = [(hd(Set))#{ <<"operator">> => <<"p">> }],
    ?assertEqual(true, successor_ok(Info, Next#{ <<"attestors">> => Moved }, Here)).

follow_file_test() ->
    Dir = <<"/tmp/bridge-follow-test">>,
    _ = file:make_dir(Dir),
    File = <<Dir/binary, "/follow.json">>,
    _ = file:delete(File),
    Cfg = #{ <<"pusd">> => <<"g">>, <<"follow-file">> => File },
    ?assertEqual(<<"g">>, maps:get(<<"pusd">>, load_follow(Cfg))),
    save_follow((load_follow(Cfg))#{ <<"pusd">> => <<"n">> }),
    ?assertEqual(<<"n">>, maps:get(<<"pusd">>, load_follow(Cfg))),
    % A different configured PUSD restarts the walk from there.
    ?assertEqual(<<"h">>, maps:get(<<"pusd">>, load_follow(Cfg#{ <<"pusd">> => <<"h">> }))).

json_value_test() ->
    Info = #{ <<"epoch">> => 2 },
    Text = hb_json:encode(Info),
    ?assertEqual(Info, json_value(Text)),
    ?assertEqual(Info, json_value(hb_json:encode(Text))),
    ?assertEqual(Info, json_value(#{ <<"body">> => Text })),
    ?assertEqual(#{}, json_value(<<"<!doctype html><html>">>)),
    ?assertEqual(#{}, json_value(not_found)).

minted_test() ->
    Info = #{ <<"processed">> => #{ <<"base">> => #{ <<"floor">> => 5, <<"above">> => [7, 9] } } },
    ?assert(minted(Info, <<"base">>, 5)),
    ?assert(minted(Info, <<"base">>, 7)),
    ?assertNot(minted(Info, <<"base">>, 6)),
    ?assertNot(minted(Info, <<"sui">>, 1)).

local_withdrawal_test() ->
    St = #{ namespace => 300 },
    ?assertEqual(<<"7">>, local_withdrawal((300 bsl 32) bor 7, St)),
    ?assertEqual(false, local_withdrawal((299 bsl 32) bor 7, St)).

%% The signature a node posts for a Base withdrawal is the one the contract
%% recovers: the same vector hb_bridge_sign checks against viem.
withdrawal_signature_base_test() ->
    W = #{ <<"id">> => <<"7">>, <<"chain">> => <<"base">>,
        <<"token">> => <<"0x2222222222222222222222222222222222222222">>,
        <<"to">> => <<"0x3333333333333333333333333333333333333333">>, <<"amount">> => <<"1234567">> },
    Cfg = #{ <<"base">> => #{ <<"chain-id">> => 8453,
        <<"contract">> => <<"0x1111111111111111111111111111111111111111">> } },
    ?assertEqual(
        <<"0x78338d741889a13ef8a5523422e3a9827f958407e44e028613ec426bb6ea4a00",
          "2ac282b54427fc3c6b5b2e80ec6cd10288c4bf425443d5f163e6b343eaca773d1c">>,
        withdrawal_signature(W, Cfg, #{ base => binary:copy(<<1>>, 32) }, 5)).
