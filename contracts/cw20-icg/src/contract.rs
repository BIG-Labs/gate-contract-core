#[cfg(not(feature = "library"))]
use cosmwasm_std::entry_point;
use cosmwasm_std::{
    from_binary, to_binary, Addr, Binary, Coin, CosmosMsg, Deps, DepsMut, Env, MessageInfo,
    Response, StdError, StdResult, Storage, Uint128, WasmMsg,
};

use cw2::set_contract_version;
use cw20::Cw20ReceiveMsg;
use cw20_base::{
    contract::{create_accounts, execute as cw20_execute, query as cw20_query},
    msg::{ExecuteMsg as BaseCw20ExecuteMsg, MigrateMsg, QueryMsg as BaseCw20QueryMsg},
    state::{MinterData, TokenInfo, BALANCES, TOKEN_INFO},
    ContractError,
};
use cw20_icg_pkg::{Cw20GateMsgType, ExecuteMsg, InstantiateMsg, QueryMsg};
use gate_pkg::{
    is_gate_addr, load_gate_addr, save_gate_addr, ExecuteMsg as GateExecuteMsg, GateMsg,
    GateRequest, Permission,
};

use crate::state::CHAINS_CONTRACT;

// version info for migration info
const CONTRACT_NAME: &str = "crates.io:cw20-icg";
const CONTRACT_VERSION: &str = env!("CARGO_PKG_VERSION");

// --- ENTRY POINTS ---

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn instantiate(
    mut deps: DepsMut,
    _env: Env,
    _info: MessageInfo,
    msg: InstantiateMsg,
) -> Result<Response, ContractError> {
    set_contract_version(deps.storage, CONTRACT_NAME, CONTRACT_VERSION)?;
    // check valid token info
    msg.validate()?;

    // create initial accounts
    let total_supply = create_accounts(&mut deps, &msg.initial_balances)?;

    if let Some(limit) = msg.get_cap() {
        if total_supply > limit {
            return Err(ContractError::Std(StdError::generic_err(
                "Initial supply greater than cap",
            )));
        }
    }

    let mint = match msg.mint {
        Some(m) => Some(MinterData {
            minter: deps.api.addr_validate(&m.minter)?,
            cap: m.cap,
        }),
        None => None,
    };

    // store token info
    let data = TokenInfo {
        name: msg.name,
        symbol: msg.symbol,
        decimals: msg.decimals,
        total_supply,
        mint,
    };

    TOKEN_INFO.save(deps.storage, &data)?;
    Ok(Response::default())
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn execute(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    msg: ExecuteMsg,
) -> Result<Response, ContractError> {
    match msg {
        // --- NEW EXECUTE MSGS ---
        ExecuteMsg::RegisterGate { contract } => run_register_gate(deps, info.sender, contract),
        ExecuteMsg::GateSetPermission { contract, chain } => {
            run_gate_set_permission(deps, info.sender, contract, chain)
        }
        ExecuteMsg::GateBridge {
            chain,
            remote_receiver,
            amount,
        } => run_gate_bridge(
            deps,
            info.funds,
            info.sender,
            chain,
            remote_receiver,
            amount,
        ),
        ExecuteMsg::GateBridgeAndExecute {
            chain,
            remote_receiver,
            amount,
            remote_contract,
            msg,
        } => run_gate_bridge_and_execute(
            deps,
            info.sender,
            chain,
            remote_receiver,
            amount,
            remote_contract,
            msg,
        ),
        // --- GATE MSGS ---
        ExecuteMsg::ReceiveGateMsg(msg) => gate_receive_msg(deps, info, msg),
        // --- BASE EXECUTE MSGS ---
        _ => {
            let msg: BaseCw20ExecuteMsg = from_binary(&to_binary(&msg)?)?;

            cw20_execute(deps, env, info, msg)
        }
    }
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn query(deps: Deps, env: Env, msg: QueryMsg) -> StdResult<Binary> {
    match msg {
        QueryMsg::RemoteContract { chain } => to_binary(&qy_remote_contract(deps, chain).unwrap()),
        QueryMsg::Gate {} => to_binary(&load_gate_addr(deps.storage)?.0),
        _ => {
            let msg: BaseCw20QueryMsg = from_binary(&to_binary(&msg)?)?;
            cw20_query(deps, env, msg)
        }
    }
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn migrate(_deps: DepsMut, _env: Env, _msg: MigrateMsg) -> Result<Response, ContractError> {
    Ok(Response::new())
}

// --- RUN ---

fn gate_receive_msg(
    deps: DepsMut,
    info: MessageInfo,
    msg: GateMsg,
) -> Result<Response, ContractError> {
    match msg {
        GateMsg::RequestFailed { request } => run_gate_revert_msg(deps, info.sender, request),
        GateMsg::ReceivedMsg { sender, msg } => {
            run_gate_receive_msg(deps, info.sender, sender, msg)
        }
        _ => Err(ContractError::Std(StdError::generic_err(format!(
            "{:?} not implemented on cw20-icg",
            msg
        )))),
    }
}

fn run_register_gate(
    deps: DepsMut,
    sender: Addr,
    contract_gate: Addr,
) -> Result<Response, ContractError> {
    only_minter(deps.as_ref(), sender)?;

    save_gate_addr(deps.storage, &contract_gate)?;

    Ok(Response::new()
        .add_attribute("action", "register_gate")
        .add_attribute("value", &contract_gate))
}

fn run_gate_set_permission(
    deps: DepsMut,
    sender: Addr,
    contract: String,
    chain: String,
) -> Result<Response, ContractError> {
    only_minter(deps.as_ref(), sender)?;

    CHAINS_CONTRACT.save(deps.storage, chain.clone(), &contract)?;

    let msg = CosmosMsg::Wasm(cosmwasm_std::WasmMsg::Execute {
        contract_addr: load_gate_addr(deps.storage)?.0.to_string(),
        msg: to_binary(&GateExecuteMsg::SetPermission {
            permission: Permission::Permissioned {
                addresses: vec![contract.clone()],
            },
            chain,
        })?,
        funds: vec![],
    });

    Ok(Response::new()
        .add_message(msg)
        .add_attribute("action", "register_remote_contract")
        .add_attribute("value", contract))
}

fn run_gate_bridge(
    deps: DepsMut,
    coin: Vec<Coin>,
    sender: Addr,
    chain: String,
    remote_receiver: String,
    amount: Uint128,
) -> Result<Response, ContractError> {
    lower_balance(deps.storage, sender.clone(), amount)?;

    let msg = CosmosMsg::Wasm(WasmMsg::Execute {
        contract_addr: load_gate_addr(deps.storage)?.0.to_string(),
        msg: to_binary(&GateExecuteMsg::SendRequests {
            requests: vec![GateRequest::SendMsg {
                msg: to_binary(&Cw20GateMsgType::Bridge {
                    sender: sender.to_string(),
                    receiver: remote_receiver.clone(),
                    amount,
                })?,
                to_contract: CHAINS_CONTRACT.load(deps.storage, chain.clone())?,
                send_native: None,
            }],
            chain,
            timeout: None,
        })?,
        funds: coin,
    });

    Ok(Response::new()
        .add_message(msg)
        .add_attribute("action", "gate_bridge")
        .add_attribute("sender", sender)
        .add_attribute("remote_receiver", remote_receiver)
        .add_attribute("amount", amount))
}

fn run_gate_bridge_and_execute(
    deps: DepsMut,
    sender: Addr,
    chain: String,
    remote_receiver: String,
    amount: Uint128,
    remote_contract: String,
    b_msg: Binary,
) -> Result<Response, ContractError> {
    lower_balance(deps.storage, sender.clone(), amount)?;

    let msg = CosmosMsg::Wasm(WasmMsg::Execute {
        contract_addr: load_gate_addr(deps.storage)?.0.to_string(),
        msg: to_binary(&GateExecuteMsg::SendRequests {
            requests: vec![GateRequest::SendMsg {
                msg: to_binary(&Cw20GateMsgType::BridgeAndExecute {
                    sender: sender.to_string(),
                    receiver: remote_receiver.clone(),
                    amount,
                    to_contract: remote_contract.clone(),
                    msg: b_msg.clone(),
                })?,
                to_contract: CHAINS_CONTRACT.load(deps.storage, chain.clone())?,
                send_native: None,
            }],
            chain,
            timeout: None,
        })?,
        funds: vec![],
    });

    Ok(Response::new()
        .add_message(msg)
        .add_attribute("action", "gate_bridge_and_execute")
        .add_attribute("sender", sender)
        .add_attribute("remote_receiver", remote_receiver)
        .add_attribute("remote_contract", remote_contract)
        .add_attribute("msg", b_msg.to_string())
        .add_attribute("amount", amount))
}

fn run_gate_receive_msg(
    deps: DepsMut,
    gate: Addr,
    _remote_cw20_contract: String,
    msg: Binary,
) -> Result<Response, ContractError> {
    // The gate is alredy checking if the remote_cw20_contract has been registered by this local contract
    is_gate_addr(deps.storage, &deps.querier, &gate)?;

    let (address_token_receiver, amount, res) = match from_binary(&msg)? {
        Cw20GateMsgType::Bridge {
            sender,
            receiver,
            amount,
        } => (
            deps.api.addr_validate(&receiver)?,
            amount,
            Response::new()
                .add_attribute("action", "gate_receive_bridge")
                .add_attribute("from", sender)
                .add_attribute("to", receiver.clone())
                .add_attribute("amount", amount),
        ),
        Cw20GateMsgType::BridgeAndExecute {
            sender,
            receiver,
            amount,
            to_contract,
            msg,
        } => (
            deps.api.addr_validate(&to_contract)?,
            amount,
            Response::new()
                .add_attribute("action", "gate_receive_bridge_and_execute")
                .add_attribute("from", sender)
                .add_attribute("to", receiver.clone())
                .add_attribute("amount", amount)
                .add_attribute("to_contract", to_contract.clone())
                .add_message(
                    Cw20ReceiveMsg {
                        sender: receiver,
                        amount,
                        msg,
                    }
                    .into_cosmos_msg(to_contract.clone())?,
                ),
        ),
    };

    increase_balance(deps.storage, address_token_receiver, amount)?;

    Ok(res)
}

fn run_gate_revert_msg(
    deps: DepsMut,
    gate: Addr,
    request: GateRequest,
) -> Result<Response, ContractError> {
    is_gate_addr(deps.storage, &deps.querier, &gate)?;

    match request {
        GateRequest::SendMsg { msg, .. } => {
            let (address, amount) = match from_binary(&msg)? {
                Cw20GateMsgType::Bridge { sender, amount, .. } => {
                    (deps.api.addr_validate(&sender)?, amount)
                }
                Cw20GateMsgType::BridgeAndExecute { sender, amount, .. } => {
                    (deps.api.addr_validate(&sender)?, amount)
                }
            };

            increase_balance(deps.storage, address.clone(), amount)?;

            let res = Response::new()
                .add_attribute("action", "gate_revert_bridge")
                .add_attribute("sender", address)
                .add_attribute("reminted_amount", amount);
            Ok(res)
        }
        _ => Err(ContractError::Std(StdError::GenericErr {
            msg: "Request not handled".to_string(),
        })),
    }
}

// --- QUERIES ---

fn qy_remote_contract(deps: Deps, chain: String) -> Result<String, ContractError> {
    Ok(CHAINS_CONTRACT.load(deps.storage, chain)?)
}

fn only_minter(deps: Deps, address: Addr) -> Result<(), ContractError> {
    let minter = TOKEN_INFO.load(deps.storage)?.mint;

    match minter {
        Some(minter) => {
            if minter.minter != address {
                Err(ContractError::Unauthorized {})
            } else {
                Ok(())
            }
        }
        None => Err(ContractError::Unauthorized {}),
    }
}

fn lower_balance(storage: &mut dyn Storage, address: Addr, amount: Uint128) -> StdResult<()> {
    BALANCES.update(
        storage,
        &address,
        |balance: Option<Uint128>| -> StdResult<_> {
            Ok(balance.unwrap_or_default().checked_sub(amount)?)
        },
    )?;
    // reduce total_supply
    TOKEN_INFO.update(storage, |mut info| -> StdResult<_> {
        info.total_supply = info.total_supply.checked_sub(amount)?;
        Ok(info)
    })?;

    Ok(())
}

fn increase_balance(
    storage: &mut dyn Storage,
    address: Addr,
    amount: Uint128,
) -> Result<(), ContractError> {
    let mut config = TOKEN_INFO.load(storage)?;

    // update supply and enforce cap
    config.total_supply += amount;
    if let Some(limit) = config.get_cap() {
        if config.total_supply > limit {
            return Err(ContractError::CannotExceedCap {});
        }
    }
    TOKEN_INFO.save(storage, &config)?;

    // add amount to recipient balance
    BALANCES.update(
        storage,
        &address,
        |balance: Option<Uint128>| -> StdResult<_> { Ok(balance.unwrap_or_default() + amount) },
    )?;

    Ok(())
}
