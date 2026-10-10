%%% @doc What the PUSD bridge's chain contracts have emitted: deposits to
%%% attest, and releases to acknowledge. One scanner per chain, each taking a
%%% cursor and returning what it found plus the next cursor.
%%%
%%%   Base    `eth-client@1.0' get-data over a confirmed block range
%%%   Solana  getSignaturesForAddress + getTransaction, Anchor event logs
%%%   Sui     suix_queryEvents by Move event type
%%%
%%% JSON-RPC goes through `relay@1.0', the node's own HTTP client. A deposit is
%%% `#{chain, nonce, token, recipient, amount, tx}' and a release is
%%% `#{chain, id, tx}', with `id' the chain's (namespaced) withdrawal id.
-module(hb_bridge_chains).
-export([rpc/4, base_head/2, base_scan/4, solana_scan/3, sui_scan/3]).
-export([anchor_events/2]).
-include_lib("eunit/include/eunit.hrl").

-define(DEPOSIT_SIG, <<"Deposit(uint64,address,address,uint256,string)">>).
-define(RELEASED_SIG, <<"Released(uint64,address,address,uint256)">>).
-define(PAGE, 100).

%% @doc One JSON-RPC call through relay@1.0; the decoded `result'.
rpc(Url, Method, Params, Opts) ->
    Req = #{
        <<"device">> => <<"relay@1.0">>,
        <<"method">> => <<"POST">>,
        <<"path">> => Url,
        <<"content-type">> => <<"application/json">>,
        <<"body">> => hb_json:encode(#{
            <<"jsonrpc">> => <<"2.0">>, <<"id">> => 1,
            <<"method">> => Method, <<"params">> => Params
        })
    },
    case hb_ao:resolve(Req, <<"call">>, Opts) of
        {ok, Res} ->
            Body = hb_maps:get(<<"body">>, Res, <<>>, Opts),
            case catch hb_json:decode(Body) of
                #{ <<"result">> := Result } -> {ok, Result};
                #{ <<"error">> := Error } -> {error, {rpc, Method, Error}};
                Other -> {error, {rpc, Method, Other}}
            end;
        Error ->
            {error, {rpc, Method, Error}}
    end.

%%% Base ----------------------------------------------------------------------

%% @doc The latest block number, through eth-client's passthrough.
base_head(Cfg, Opts) ->
    case eth_client(<<"rpc">>, Cfg, #{ <<"rpc-method">> => <<"eth_blockNumber">> }, Opts) of
        {ok, #{ <<"body">> := <<"0x", Hex/binary>> }} -> {ok, binary_to_integer(Hex, 16)};
        {ok, #{ <<"body">> := Body }} when is_binary(Body) ->
            {ok, binary_to_integer(string:trim(Body, both, "\""), 10)};
        Other -> {error, {base_head, Other}}
    end.

%% @doc Deposits and releases in blocks `From..To', decoded by eth-client.
base_scan(Cfg, From, To, Opts) ->
    Req = #{
        <<"contract">> => maps:get(<<"contract">>, Cfg),
        <<"event-signature">> => <<?DEPOSIT_SIG/binary, ",", ?RELEASED_SIG/binary>>,
        <<"mode">> => <<"range">>,
        <<"from-block">> => hex_block(From),
        <<"to-block">> => hex_block(To)
    },
    case eth_client(<<"get-data">>, Cfg, Req, Opts) of
        {ok, #{ <<"body">> := #{ <<"data">> := Data } }} ->
            Events = case Data of
                Bin when is_binary(Bin) -> hb_json:decode(Bin);
                List -> List
            end,
            {ok, lists:filtermap(fun base_event/1, Events)};
        Other ->
            {error, {base_scan, Other}}
    end.

base_event(#{ <<"event">> := <<"Deposit">>, <<"removed">> := false,
        <<"args">> := [Nonce, Token, _From, Amount, Ao] } = E) ->
    {true, #{ kind => deposit, chain => <<"base">>, nonce => binary_to_integer(Nonce),
        token => Token, recipient => Ao, amount => Amount,
        tx => maps:get(<<"transaction-hash">>, E, <<>>) }};
base_event(#{ <<"event">> := <<"Released">>, <<"removed">> := false,
        <<"args">> := [Id | _] } = E) ->
    {true, #{ kind => released, chain => <<"base">>, id => binary_to_integer(Id),
        tx => maps:get(<<"transaction-hash">>, E, <<>>) }};
base_event(_) ->
    false.

eth_client(Path, Cfg, Req, Opts) ->
    hb_ao:resolve(
        #{ <<"device">> => <<"eth-client@1.0">> },
        Req#{ <<"path">> => Path, <<"rpc-url">> => maps:get(<<"rpc">>, Cfg) },
        Opts
    ).

hex_block(N) -> <<"0x", (integer_to_binary(N, 16))/binary>>.

%%% Solana --------------------------------------------------------------------

%% @doc Everything the program logged after signature `Until' (undefined:
%% from the start), oldest first, and the newest signature seen.
solana_scan(Cfg, Until, Opts) ->
    Url = maps:get(<<"rpc">>, Cfg),
    Program = maps:get(<<"program">>, Cfg),
    Commitment = maps:get(<<"commitment">>, Cfg, <<"confirmed">>),
    case solana_signatures(Url, Program, Until, undefined, Commitment, [], Opts) of
        {ok, []} ->
            {ok, [], Until};
        {ok, Sigs} ->
            % Newest first from the node; process oldest first.
            Ordered = lists:reverse(Sigs),
            case solana_events(Url, Program, Commitment, Ordered, [], Opts) of
                {ok, Found} -> {ok, Found, maps:get(<<"signature">>, hd(Sigs))};
                Error -> Error
            end;
        Error ->
            Error
    end.

solana_signatures(Url, Program, Until, Before, Commitment, Acc, Opts) ->
    Cfg0 = #{ <<"limit">> => ?PAGE, <<"commitment">> => Commitment },
    Cfg1 = case Until of undefined -> Cfg0; _ -> Cfg0#{ <<"until">> => Until } end,
    Cfg2 = case Before of undefined -> Cfg1; _ -> Cfg1#{ <<"before">> => Before } end,
    case rpc(Url, <<"getSignaturesForAddress">>, [Program, Cfg2], Opts) of
        {ok, Page} when length(Page) < ?PAGE -> {ok, Acc ++ Page};
        {ok, Page} ->
            Last = maps:get(<<"signature">>, lists:last(Page)),
            solana_signatures(Url, Program, Until, Last, Commitment, Acc ++ Page, Opts);
        Error -> Error
    end.

solana_events(_Url, _Program, _Commitment, [], Acc, _Opts) ->
    {ok, lists:reverse(Acc)};
solana_events(Url, Program, Commitment, [#{ <<"err">> := Err } | Rest], Acc, Opts) when Err =/= null ->
    solana_events(Url, Program, Commitment, Rest, Acc, Opts);
solana_events(Url, Program, Commitment, [#{ <<"signature">> := Sig } | Rest], Acc, Opts) ->
    Params = [Sig, #{ <<"encoding">> => <<"json">>, <<"commitment">> => Commitment,
        <<"maxSupportedTransactionVersion">> => 0 }],
    case rpc(Url, <<"getTransaction">>, Params, Opts) of
        {ok, #{ <<"meta">> := #{ <<"logMessages">> := Logs } }} ->
            Found = [E#{ tx => Sig } || E <- anchor_events(Program, Logs)],
            solana_events(Url, Program, Commitment, Rest, lists:reverse(Found) ++ Acc, Opts);
        {ok, _} ->
            solana_events(Url, Program, Commitment, Rest, Acc, Opts);
        Error ->
            Error
    end.

%% @doc The bridge events in one transaction's logs. A `Program data:' line
%% counts only while OUR program is the one executing: any program can log
%% that text, so the invocation stack decides whose event it is.
anchor_events(Program, Logs) ->
    Deposit = discriminator(<<"DepositEvent">>),
    Released = discriminator(<<"ReleasedEvent">>),
    {_, Found} = lists:foldl(
        fun(Line, {Stack, Acc}) ->
            case binary:split(Line, <<" ">>, [global]) of
                [<<"Program">>, Id, <<"invoke">> | _] -> {[Id | Stack], Acc};
                [<<"Program">>, Id, Result | _] when Result =:= <<"success">>; Result =:= <<"failed:">> ->
                    {case Stack of [Id | S] -> S; S -> S end, Acc};
                [<<"Program">>, <<"data:">>, B64] when Stack =/= [], hd(Stack) =:= Program ->
                    case anchor_event(base64:decode(B64), Deposit, Released) of
                        false -> {Stack, Acc};
                        Event -> {Stack, [Event | Acc]}
                    end;
                _ -> {Stack, Acc}
            end
        end, {[], []}, Logs),
    lists:reverse(Found).

anchor_event(<<D:8/binary, Nonce:64/little, Mint:32/binary, _From:32/binary,
        Amount:64/little, Len:32/little, Ao:Len/binary>>, D, _) ->
    #{ kind => deposit, chain => <<"solana">>, nonce => Nonce,
        token => hb_bridge_sign:base58_encode(Mint), recipient => Ao,
        amount => integer_to_binary(Amount) };
anchor_event(<<R:8/binary, Id:64/little, _/binary>>, _, R) ->
    #{ kind => released, chain => <<"solana">>, id => Id };
anchor_event(_, _, _) ->
    false.

discriminator(Name) ->
    <<D:8/binary, _/binary>> = crypto:hash(sha256, <<"event:", Name/binary>>),
    D.

%%% Sui -----------------------------------------------------------------------

%% @doc Deposits and releases after `Cursors' (`#{deposit, released}' event
%% ids, undefined: from the start), and the advanced cursors.
sui_scan(Cfg, Cursors, Opts) ->
    Pkg = maps:get(<<"package">>, Cfg),
    maybe
        {ok, Deps, DC} ?= sui_events(Cfg, <<Pkg/binary, "::para_bridge::DepositEvent">>,
            maps:get(deposit, Cursors, undefined), [], Opts),
        {ok, Rels, RC} ?= sui_events(Cfg, <<Pkg/binary, "::para_bridge::ReleasedEvent">>,
            maps:get(released, Cursors, undefined), [], Opts),
        {ok, [sui_deposit(E) || E <- Deps] ++ [sui_released(E) || E <- Rels],
            #{ deposit => DC, released => RC }}
    end.

sui_events(Cfg, Type, Cursor, Acc, Opts) ->
    C = case Cursor of undefined -> null; _ -> Cursor end,
    Params = [#{ <<"MoveEventType">> => Type }, C, ?PAGE, false],
    case rpc(maps:get(<<"rpc">>, Cfg), <<"suix_queryEvents">>, Params, Opts) of
        {ok, #{ <<"data">> := Data, <<"hasNextPage">> := More } = Page} ->
            Next = case maps:get(<<"nextCursor">>, Page, null) of null -> Cursor; N -> N end,
            case More of
                true -> sui_events(Cfg, Type, Next, Acc ++ Data, Opts);
                false -> {ok, Acc ++ Data, Next}
            end;
        Error ->
            Error
    end.

sui_deposit(#{ <<"parsedJson">> := J, <<"id">> := #{ <<"txDigest">> := Tx } }) ->
    #{ kind => deposit, chain => <<"sui">>, nonce => int(maps:get(<<"nonce">>, J)),
        token => maps:get(<<"coin_type">>, J), recipient => maps:get(<<"ao_recipient">>, J),
        amount => bin(maps:get(<<"amount">>, J)), tx => Tx }.

sui_released(#{ <<"parsedJson">> := J, <<"id">> := #{ <<"txDigest">> := Tx } }) ->
    #{ kind => released, chain => <<"sui">>, id => int(maps:get(<<"withdrawal_id">>, J)), tx => Tx }.

%% Sui JSON writes u64 as a string.
int(N) when is_integer(N) -> N;
int(N) when is_binary(N) -> binary_to_integer(N).
bin(N) when is_integer(N) -> integer_to_binary(N);
bin(N) when is_binary(N) -> N.

%%% Tests ---------------------------------------------------------------------

-define(PROG, <<"thXGuX413NPvD7zPrSv658UmVEwdki2Tu3zhbU6LoiM">>).

deposit_bytes(Nonce, Amount, Ao) ->
    <<(discriminator(<<"DepositEvent">>))/binary, Nonce:64/little, (binary:copy(<<1>>, 32))/binary,
      (binary:copy(<<2>>, 32))/binary, Amount:64/little, (byte_size(Ao)):32/little, Ao/binary>>.

anchor_events_test() ->
    Ao = <<"abcdefghijklmnopqrstuvwxyzABCDEFGHIJ0123-_Z">>,
    Data = <<"Program data: ", (base64:encode(deposit_bytes(5, 2500, Ao)))/binary>>,
    Logs = [
        <<"Program ", ?PROG/binary, " invoke [1]">>,
        <<"Program log: Instruction: Deposit">>,
        Data,
        <<"Program ", ?PROG/binary, " success">>
    ],
    ?assertMatch([#{ kind := deposit, nonce := 5, amount := <<"2500">>, recipient := Ao }],
        anchor_events(?PROG, Logs)).

%% Another program logging our event's bytes is not our event.
anchor_events_ignores_other_programs_test() ->
    Forged = <<"Program data: ",
        (base64:encode(deposit_bytes(9, 1, <<"abcdefghijklmnopqrstuvwxyzABCDEFGHIJ0123-_Z">>)))/binary>>,
    Logs = [
        <<"Program ", ?PROG/binary, " invoke [1]">>,
        <<"Program Evil111111111111111111111111111111111 invoke [2]">>,
        Forged,
        <<"Program Evil111111111111111111111111111111111 success">>,
        <<"Program ", ?PROG/binary, " success">>,
        Forged
    ],
    ?assertEqual([], anchor_events(?PROG, Logs)).
