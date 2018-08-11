%%--------------------------------------------------------------------
%% Copyright (c) 2013-2018 EMQ Enterprise, Inc. (http://emqtt.io)
%%
%% Licensed under the Apache License, Version 2.0 (the "License");
%% you may not use this file except in compliance with the License.
%% You may obtain a copy of the License at
%%
%%     http://www.apache.org/licenses/LICENSE-2.0
%%
%% Unless required by applicable law or agreed to in writing, software
%% distributed under the License is distributed on an "AS IS" BASIS,
%% WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
%% See the License for the specific language governing permissions and
%% limitations under the License.
%%--------------------------------------------------------------------

-module(emq_auth_redis).

-behaviour(emqttd_auth_mod).

-include("emq_auth_redis.hrl").

-include_lib("emqttd/include/emqttd.hrl").

-export([init/1, check/3, description/0]).

-define(UNDEFINED(S), (S =:= undefined)).

-record(state, {auth_cmd, super_cmd, hash_type}).

-define(EMPTY(Username), (Username =:= undefined orelse Username =:= <<>>)).

-define(LOG(Level, Format, Args),
    lager:Level("MQTT-SN(ASLEEP-TIMER): " ++ Format, Args)).

init({AuthCmd, SuperCmd, HashType}) ->
    {ok, #state{auth_cmd = AuthCmd, super_cmd = SuperCmd, hash_type = HashType}}.

check(#mqtt_client{username = Username}, Password, _State)
    when ?UNDEFINED(Username) ->
    {error, username_or_password_undefined};

check(Client, Password, #state{auth_cmd  = AuthCmd,
                               super_cmd = SuperCmd,
                               hash_type = HashType}) ->
    Passwd = if ?EMPTY(Password) -> 
             <<"">>;
	     true ->
             Password 
      end,   
   Result = case emq_auth_redis_cli:q(AuthCmd, Client) of
                {ok, PassHash} when is_binary(PassHash) ->
                    check_pass(PassHash, Passwd, HashType);  
                {ok, [undefined|_]} ->
                    ignore;
                {ok, [PassHash]} ->
                    check_pass(PassHash, Passwd, HashType);
                {ok, [PassHash, Salt|_]} ->
                    check_pass(PassHash, Salt, Passwd, HashType);
                {error, Reason} ->
                    {error, Reason}
             end,
    ?LOG(error,"result=~p",[Result]),
	case Result of ok -> {ok, is_superuser(SuperCmd, Client)}; Error -> Error end.

check_pass(PassHash, Passwd, HashType) ->
    check_pass(PassHash, hash(HashType, Passwd)).
check_pass(PassHash, Salt, Passwd, {pbkdf2, Macfun, Iterations, Dklen}) ->
  check_pass(PassHash, hash(pbkdf2, {Salt, Passwd, Macfun, Iterations, Dklen}));
check_pass(PassHash, Salt, Passwd, {salt, bcrypt}) ->
    check_pass(PassHash, hash(bcrypt, {Salt, Passwd}));
check_pass(PassHash, Salt, Passwd, {salt, HashType}) ->
    check_pass(PassHash, hash(HashType, <<Salt/binary, Passwd/binary>>));
check_pass(PassHash, Salt, Passwd, {HashType, salt}) ->
    check_pass(PassHash, hash(HashType, <<Passwd/binary, Salt/binary>>)).

check_pass(PassHash, PassHash) -> ok;
check_pass(_, _)               -> {error, password_error}.

description() -> "Authentication with Redis".

hash(Type, Passwd) -> emqttd_auth_mod:passwd_hash(Type, Passwd).

-spec(is_superuser(undefined | list(), mqtt_client()) -> boolean()).
is_superuser(undefined, _Client) ->
    false;
is_superuser(SuperCmd, Client) ->
    case emq_auth_redis_cli:q(SuperCmd, Client) of
        {ok, undefined} -> false;
        {ok, <<"1">>}   -> true;
        {ok, _Other}    -> false;
        {error, _Error} -> false
    end.

