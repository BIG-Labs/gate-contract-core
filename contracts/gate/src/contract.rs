use cosmwasm_std::entry_point;
use cosmwasm_std::{
    to_binary, wasm_instantiate, Binary, Deps, DepsMut, Env, MessageInfo, Reply, Response,
    StdResult, SubMsg,
};
use cw20::MinterResponse;
use gate_pkg::{Config, ExecuteMsg, QueryMsg};

use cw20_icg_pkg::InstantiateMsg as Cw20InstantiateMsg;

use crate::error::ContractError;
use crate::queries::{qy_channel_info, qy_config, qy_permission};
use crate::state::{
    IBCLifecycleComplete, InstantiateMsg, MigrateMsg, RegisteringVoucherChain, ReplyID, SudoMsg,
    BUFFER_PACKETS, BUFFER_QUERIES_RESPONSE, CONIFG, IS_REGISTERING, LAST_FAILED_KEY_GENERATED,
    VOUCHER_REGISTERING_CHAIN,
};
use crate::{on_dest, on_src};

#[entry_point]
pub fn instantiate(
    deps: DepsMut,
    env: Env,
    _info: MessageInfo,
    msg: InstantiateMsg,
) -> Result<Response, ContractError> {
    let config = Config {
        controller: msg.controller,
        default_timeout: msg.default_timeout,
        default_gas_limit: msg.default_gas_limit,
        cw20_icg_code_id: msg.cw20_icg_code_id,
        account_icg_code_id: msg.account_icg_code_id,
        voucher_contract: None,
        base_denom: msg.base_denom,
        max_gas_amount_per_revert: msg.max_gas_amount_per_revert,
        index_account: 0,
    };

    CONIFG.save(deps.storage, &config)?;

    BUFFER_PACKETS.save(deps.storage, &None)?;

    IS_REGISTERING.save(deps.storage, &false)?;

    VOUCHER_REGISTERING_CHAIN.save(deps.storage, &Some(RegisteringVoucherChain::Local))?;

    BUFFER_QUERIES_RESPONSE.save(deps.storage, &vec![])?;

    LAST_FAILED_KEY_GENERATED.save(deps.storage, &(env.block.height, 0))?;

    // Create voucher token
    let sub_msg = SubMsg::reply_on_success(
        wasm_instantiate(
            msg.cw20_icg_code_id,
            &Cw20InstantiateMsg {
                name: "voucher-fee-gate-local".to_string(),
                symbol: "VFG".to_string(),
                decimals: 6,
                initial_balances: vec![],
                mint: Some(MinterResponse {
                    minter: env.contract.address.to_string(),
                    cap: None,
                }),
            },
            vec![],
            String::from("Voucher fee gate local"),
        )?,
        ReplyID::InitToken.repr(),
    );

    Ok(Response::new()
        .add_submessage(sub_msg)
        .add_attribute("cw20_icg_token_id", msg.cw20_icg_code_id.to_string()))
}

#[entry_point]
pub fn execute(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    msg: ExecuteMsg,
) -> Result<Response, ContractError> {
    match msg {
        ExecuteMsg::Receive(cw20_receive_msg) => {
            on_src::run_cw20_receive_msg(deps, info.sender, cw20_receive_msg)
        }
        ExecuteMsg::SendRequests {
            requests,
            chain,
            timeout,
        } => on_src::run_handle_requests(
            deps,
            env,
            info.funds,
            info.sender,
            requests,
            chain,
            timeout,
        ),
        ExecuteMsg::RegisterChainAndChannel {
            chain,
            src_channel,
            base_denom,
        } => on_src::run_register_remote_chain_and_channel(
            deps,
            env,
            info.sender,
            chain,
            src_channel,
            base_denom,
        ),
        ExecuteMsg::SetVoucherPermission {
            chain,
            local_voucher_contract,
            remote_voucher_contract,
        } => on_src::run_set_voucher_permission(
            deps,
            info.sender,
            chain,
            local_voucher_contract,
            remote_voucher_contract,
        ),
        ExecuteMsg::SetPermission { permission, chain } => {
            on_src::run_set_permission(deps, info.sender, permission, chain)
        }

        ExecuteMsg::SetPermissionFromAdmin {
            contract,
            permission,
            chain,
        } => on_src::run_set_permission_from_admin(deps, info.sender, contract, permission, chain),
        ExecuteMsg::CollectRequests { to_contract, msg } => {
            on_src::run_collect_msgs(deps, env, info.funds, info.sender, to_contract, msg)
        }
        ExecuteMsg::PrivateSendCollectedMsgs => {
            on_src::run_private_send_collected_msgs(deps, env, info.sender)
        }

        ExecuteMsg::PrivateRemoteExecuteRequests {
            from_chain,
            requests_infos,
            native_denom,
        } => on_dest::run_private_remote_execute_requests(
            deps,
            env,
            info.sender,
            requests_infos,
            from_chain,
            native_denom,
        ),

        ExecuteMsg::PrivateRemoteExecuteQuery {
            queries,
            from_contract,
            callback_msg,
        } => on_dest::run_private_remote_execute_query(
            deps,
            env,
            info.sender,
            queries,
            from_contract,
            callback_msg,
        ),

        ExecuteMsg::IbcHook(ibc_hook_msg) => on_dest::run_ibc_hook(deps, env, ibc_hook_msg),

        ExecuteMsg::GateAccount(msg) => {
            on_src::run_gate_account_msg(deps, env, info.sender, info.funds, msg)
        }
    }
}

#[entry_point]
pub fn query(deps: Deps, _env: Env, msg: QueryMsg) -> StdResult<Binary> {
    match msg {
        QueryMsg::Permission { contract, chain } => {
            to_binary(&qy_permission(deps, contract, chain).unwrap())
        }
        QueryMsg::ChannelInfo { chain } => to_binary(&qy_channel_info(deps, chain).unwrap()),
        QueryMsg::Config {} => to_binary(&qy_config(deps).unwrap()),
    }
}

#[entry_point]
pub fn reply(deps: DepsMut, env: Env, reply: Reply) -> Result<Response, ContractError> {
    match ReplyID::from_repr(reply.id) {
        Some(ReplyID::ExecuteRequest) => on_dest::reply_execute_request(deps, reply.result),
        Some(ReplyID::AckContract) => on_src::reply_ack_contract(deps, reply.result),
        Some(ReplyID::InitToken) => on_src::reply_init_token(deps, env, reply),
        Some(ReplyID::MintVoucher) => Ok(Response::new()),
        Some(ReplyID::SendIbcHookPacket) => on_src::reply_send_ibc_packet(deps, env, reply.result),
        None => Err(ContractError::InvalidIdReply { id: reply.id }),
    }
}

#[entry_point]
pub fn sudo(deps: DepsMut, env: Env, msg: SudoMsg) -> Result<Response, ContractError> {
    match msg {
        SudoMsg::IBCLifecycleComplete(ack) => match ack {
            IBCLifecycleComplete::IBCAck {
                success,
                channel,
                sequence,
                ack,
            } => {
                if success {
                    on_src::sudo_ack_ok(deps, channel, sequence)
                } else {
                    on_src::sudo_on_ack_failed(deps, env, channel, sequence, ack)
                }
            }
            IBCLifecycleComplete::IBCTimeout { channel, sequence } => {
                on_src::sudo_on_ack_failed(deps, env, channel, sequence, "timeout".to_string())
            }
        },
    }
}

#[entry_point]
pub fn migrate(_deps: DepsMut, _env: Env, _msg: MigrateMsg) -> Result<Response, ContractError> {
    Ok(Response::new())
}
