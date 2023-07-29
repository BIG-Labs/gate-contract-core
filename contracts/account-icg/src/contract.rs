use std::collections::HashMap;

use cosmwasm_std::{
    entry_point, to_binary, Addr, Binary, Coin, CosmosMsg, Deps, StdResult, Uint128, WasmMsg,
};
use cosmwasm_std::{DepsMut, Env, MessageInfo, Response};
use gate_pkg::{is_gate_addr, save_gate_addr};

use crate::error::ContractError;
use crate::function::{avaiable_amount, query_token_balance, replace_amount, vec_coins_to_hashmap};
use crate::msgs::{ExecuteMsg, InstantiateMsg, MsgToExecuteInfo, QueryMsg};
use crate::state::{BALANCES, EXTERNAL_OWNERS, LOCAL_OWNERS};

#[entry_point]
pub fn instantiate(
    deps: DepsMut,
    _env: Env,
    info: MessageInfo,
    msg: InstantiateMsg,
) -> Result<Response, ContractError> {
    save_gate_addr(deps.storage, &info.sender)?;
    EXTERNAL_OWNERS.save(deps.storage, &msg.external_owners)?;
    LOCAL_OWNERS.save(deps.storage, &msg.local_owners)?;
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
        ExecuteMsg::ExecuteMsgs { msgs } => {
            run_execute_msgs(deps, env, msgs, info.sender, info.funds)
        }
        ExecuteMsg::GateExecuteMsgs { sender, msgs } => {
            run_gate_execute_msgs(deps, env, msgs, info.sender, sender, info.funds)
        }
        ExecuteMsg::PrivateExecuteMsg(msg) => run_private_execute_msg(deps, env, msg, info.sender),
    }
}

#[entry_point]
pub fn query(_deps: Deps, _env: Env, _msg: QueryMsg) -> StdResult<Binary> {
    todo!()
}

fn run_execute_msgs(
    deps: DepsMut,
    env: Env,
    msgs: Vec<MsgToExecuteInfo>,
    sender: Addr,
    coins: Vec<Coin>,
) -> Result<Response, ContractError> {
    if !LOCAL_OWNERS.load(deps.storage)?.contains(&sender) {
        return Err(ContractError::Unauthorized {});
    }

    Ok(handle_msgs(deps, env, msgs, coins)?.add_attribute("action", "execute_msgs"))
}

fn run_gate_execute_msgs(
    deps: DepsMut,
    env: Env,
    msgs: Vec<MsgToExecuteInfo>,
    gate: Addr,
    sender: (String, String),
    coins: Vec<Coin>,
) -> Result<Response, ContractError> {
    is_gate_addr(deps.storage, &deps.querier, &gate)?;

    if !EXTERNAL_OWNERS.load(deps.storage)?.contains(&sender) {
        return Err(ContractError::Unauthorized {});
    };

    Ok(handle_msgs(deps, env, msgs, coins)?.add_attribute("action", "gate_execute_msgs"))
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

    let mut c_msg = msg.msg;

    for replace_info in msg.replaces_infos {
        c_msg = replace_amount(
            c_msg,
            &replace_info,
            avaiable_amount(&env, deps.storage, &deps.querier, &replace_info.token_info)?,
        )?;
    }

    Ok(Response::new().add_message(c_msg))
}

fn handle_msgs(
    deps: DepsMut,
    env: Env,
    msgs: Vec<MsgToExecuteInfo>,
    coins: Vec<Coin>,
) -> Result<Response, ContractError> {
    let mut balances: HashMap<String, Uint128> = HashMap::new();

    let coins = vec_coins_to_hashmap(coins)?;

    let c_msgs: Vec<CosmosMsg> = msgs
        .into_iter()
        .map(|msg| {
            for replace in &msg.replaces_infos {
                if !balances.contains_key(&replace.token_info.as_string()) {
                    let mut amount = query_token_balance(
                        &deps.querier,
                        &replace.token_info,
                        &env.contract.address,
                    );

                    if let Some(received_amount) = coins.get(&replace.token_info.as_string()) {
                        amount -= received_amount.to_owned()
                    }

                    balances.insert(replace.token_info.as_string(), amount);
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
