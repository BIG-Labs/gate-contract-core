use std::collections::HashMap;

use cosmwasm_std::{
    entry_point, to_binary, Addr, Binary, Coin, CosmosMsg, Deps, StdResult, Uint128, WasmMsg,
};
use cosmwasm_std::{DepsMut, Env, MessageInfo, Response};
use gate_pkg::{is_gate_addr, load_gate_addr, save_gate_addr};
use rhaki_cw_plus::coin::vec_coins_to_hashmap;

use account_icg_pkg::{
    definitions::{MsgToExecuteInfo, ReplaceValueType},
    msgs::{ConfigResponse, ExecuteMsg, InstantiateMsg, QueryMsg},
};

use crate::error::ContractError;
use crate::function::{query_token_balance, substitute_key_in_value_into_comsos_msg};
use crate::state::BALANCES;

#[entry_point]
pub fn instantiate(
    deps: DepsMut,
    _env: Env,
    info: MessageInfo,
    _msg: InstantiateMsg,
) -> Result<Response, ContractError> {
    save_gate_addr(deps.storage, &info.sender)?;
    Ok(Response::new())
}

#[entry_point]
pub fn execute(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    msg: ExecuteMsg,
) -> Result<Response, ContractError> {
    match msg {
        ExecuteMsg::ExecuteMsgs { msgs } => execute_msgs(deps, env, info.sender, msgs, info.funds),
        ExecuteMsg::PrivateExecuteMsg(msg) => run_private_execute_msg(deps, env, msg, info.sender),
    }
}

#[entry_point]
pub fn query(deps: Deps, _env: Env, msg: QueryMsg) -> StdResult<Binary> {
    match msg {
        QueryMsg::Config {} => to_binary(&qy_config(deps)?),
    }
}

fn run_private_execute_msg(
    deps: DepsMut,
    env: Env,
    msg: MsgToExecuteInfo,
    sender: Addr,
) -> Result<Response, ContractError> {
    if sender != env.contract.address {
        return Err(ContractError::Unauthorized {});
    }

    let msg = substitute_key_in_value_into_comsos_msg(
        deps.storage,
        &deps.querier,
        &env,
        &msg.msg,
        msg.replaces_infos.clone(),
    )?;

    Ok(Response::new().add_message(msg))
}

#[allow(irrefutable_let_patterns)]
fn execute_msgs(
    deps: DepsMut,
    env: Env,
    sender: Addr,
    msgs: Vec<MsgToExecuteInfo>,
    coins: Vec<Coin>,
) -> Result<Response, ContractError> {
    is_gate_addr(deps.storage, &deps.querier, &sender)?;

    let mut balances: HashMap<String, Uint128> = HashMap::new();

    let coins = vec_coins_to_hashmap(coins)?;

    let c_msgs: Vec<CosmosMsg> = msgs
        .into_iter()
        .map(|msg| {
            for replace in &msg.replaces_infos {
                if let ReplaceValueType::TokenAmount(token_info) = &replace.value {
                    if let std::collections::hash_map::Entry::Vacant(e) =
                        balances.entry(token_info.as_string())
                    {
                        let mut amount =
                            query_token_balance(&deps.querier, token_info, &env.contract.address);

                        if let Some(received_amount) = coins.get(&token_info.as_string()) {
                            amount -= received_amount.to_owned()
                        }

                        e.insert(amount);
                    }
                }
            }

            CosmosMsg::Wasm(WasmMsg::Execute {
                contract_addr: env.contract.address.to_string(),
                msg: to_binary(&ExecuteMsg::PrivateExecuteMsg(msg)).unwrap(),
                funds: vec![],
            })
        })
        .collect();

    BALANCES.save(deps.storage, &balances)?;

    Ok(Response::new().add_messages(c_msgs))
}

fn qy_config(deps: Deps) -> StdResult<ConfigResponse> {
    Ok(ConfigResponse {
        gate_address: load_gate_addr(deps.storage)?.0,
    })
}
