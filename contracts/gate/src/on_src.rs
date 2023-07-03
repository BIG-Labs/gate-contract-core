use cosmwasm_std::{
    from_binary, to_binary, wasm_instantiate, Addr, BankMsg, Binary, Coin, CosmosMsg, DepsMut, Env,
    IbcBasicResponse, IbcMsg, IbcPacketAckMsg, IbcPacketTimeoutMsg, Response, StdError, StdResult,
    Storage, SubMsg, SubMsgResponse, SubMsgResult, Uint128, WasmMsg,
};
use cw20::{Cw20ReceiveMsg, MinterResponse};
use gate_pkg::{
    lowest_timeout, merge_send_native, Config, ExecuteMsg, GateMsg, GateRequest, GateRequestsInfo,
    IbcHookMsg, PacketPath, Permission, QueryRequestInfoResponse,
};
use prost::Message as ProstMessage;
use protobuf::Message as ProtoMessage;
use schemars::_serde_json::to_string_pretty;

use crate::{
    error::ContractError,
    extra::{
        msg_transfer::{MsgTransfer, MsgTransferResponse},
        response::MsgInstantiateContractResponse,
    },
    functions::{
        get_base_denom, get_channel_from_chain, get_remote_gate_addr_from_chain, is_controller,
        merge_fee,
    },
    state::{
        Cw20MsgType, ForwardField, GateAck, GateAckType, GatePacket, GatePacketInfo, MemoField,
        PacketSavedKey, RegisteringVoucherChain, ReplyID, RequestsPacket, WasmField,
        BUFFER_PACKETS, CHAIN_REGISTERED_CHANNELS, CHANNEL_INFO, CONIFG, IS_REGISTERING,
        LAST_FAILED_KEY_GENERATED, PACKET_IBC_HOOK_AWAITING_ACK, PACKET_IBC_HOOK_AWAITING_REPLY,
        REGISTERED_CONTRACTS, VOUCHER_REGISTERING_CHAIN,
    },
};

use cw20_icg_pkg::{ExecuteMsg as Cw20ExecuteMsg, InstantiateMsg as Cw20InstantiateMsg};

// --- EXECUTE MSG ---

/// Match the `binary` `msg` of `Cw20ExecuteMsg` with `Cw20MsgType`
pub fn run_cw20_receive_msg(
    deps: DepsMut,
    cw20_contract: Addr,
    msg: Cw20ReceiveMsg,
) -> Result<Response, ContractError> {
    match from_binary(&msg.msg)? {
        Cw20MsgType::RedeemVoucher {} => {
            redeem_voucher(deps, cw20_contract, msg.sender, msg.amount)
        }
    }
}

/// The contract recive a `Request` from a contrat to be forwarded on a remote chain.
/// There are two situation here:
/// - If the contract has the variabile `IS_REGISTERING`, a `GatePacketInfo` is created and stored in the contract.
/// - Else we send the packet directly
pub fn run_handle_requests(
    deps: DepsMut,
    env: Env,
    funds: Vec<Coin>,
    sender: Addr,
    requests: Vec<GateRequest>,
    chain: String,
    timeout: Option<u64>,
) -> Result<Response, ContractError> {
    let base_denom = get_base_denom(deps.storage)?;

    let requests_info = GateRequestsInfo::new(requests, sender.to_string(), funds, base_denom)?;

    if IS_REGISTERING.load(deps.storage)? {
        store_request_info(deps, requests_info, chain, timeout)
    } else {
        send_packet(
            deps,
            env,
            RequestsPacket {
                requests_infos: vec![requests_info.clone()],
                fee: requests_info.fee,
                send_native: requests_info.send_native,
                from_chain: None,
                to_chain: chain,
            },
            timeout,
        )
    }
}

/// The contract start to `store` instad to `send` the `Request` if received.
/// Similar to flash loans: two messages are returned:
/// - The first is forwarded to the requested contract, which in turn will be able to enter one or more `Requests` from him or from other contracts that will be saved;
/// - The second to this contract to `send` a single packet containing all `Requests` stored and fired them to the destination chain
pub fn run_collect_msgs(
    deps: DepsMut,
    env: Env,
    funds: Vec<Coin>,
    sender: Addr,
    to_contract: Addr,
    msg: Binary,
) -> Result<Response, ContractError> {
    // Check the `to_contract` address is not the gate itself in order to avoid to call private execute msgs.
    if to_contract == env.contract.address {
        return Err(ContractError::Unauthorized {});
    }

    IS_REGISTERING.save(deps.storage, &true)?;

    let msg = GateMsg::CollectRequests { sender, msg }.into_cosmos_msg(to_contract, funds)?;

    let callback_msg = CosmosMsg::Wasm(WasmMsg::Execute {
        contract_addr: env.contract.address.to_string(),
        msg: to_binary(&ExecuteMsg::PrivateSendCollectedMsgs)?,
        funds: vec![],
    });

    Ok(Response::new()
        .add_message(msg)
        .add_message(callback_msg)
        .add_attribute("action", "collect_msgs"))
}

/// Second message fired from `run_collect_msgs`
/// All stored `Requests` are fired.
/// This function can be called only by the contract
pub fn run_private_send_collected_msgs(
    deps: DepsMut,
    env: Env,
    sender: Addr,
) -> Result<Response, ContractError> {
    if sender != env.contract.address {
        return Err(ContractError::Unauthorized {});
    };

    let packet_info: Option<GatePacketInfo> = BUFFER_PACKETS.load(deps.storage)?;

    match packet_info {
        Some(packet_info) => send_packet(deps, env, packet_info.packet, packet_info.timeout),
        None => Err(ContractError::NoRequestReceivedOnCollectedMsgs {}),
    }
}

/// The contract save one valid channel opened and link it to the specified chain
pub fn run_register_remote_chain_and_channel(
    deps: DepsMut,
    env: Env,
    controller: Addr,
    chain: String,
    src_channel: String,
    base_denom: String,
) -> Result<Response, ContractError> {
    is_controller(deps.as_ref(), controller)?;

    let mut channel_info = CHANNEL_INFO.load(deps.storage, src_channel)?;
    channel_info.base_denom = Some(base_denom);

    let config = CONIFG.load(deps.storage)?;

    // Create voucher token
    let sub_msg = SubMsg::reply_on_success(
        wasm_instantiate(
            config.cw20_icg_code_id,
            &Cw20InstantiateMsg {
                name: format!("voucher-fee-gate-{}", chain),
                symbol: "VFG".to_string(),
                decimals: 6,
                initial_balances: vec![],
                mint: Some(MinterResponse {
                    minter: env.contract.address.to_string(),
                    cap: None,
                }),
            },
            vec![],
            format!("Voucher fee gate {}", chain),
        )?,
        ReplyID::InitToken.repr(),
    );

    VOUCHER_REGISTERING_CHAIN.save(
        deps.storage,
        &Some(RegisteringVoucherChain::Chain {
            name: chain.to_string(),
        }),
    )?;

    CHAIN_REGISTERED_CHANNELS().save(deps.storage, chain.clone(), &channel_info)?;

    Ok(Response::new()
        .add_submessage(sub_msg)
        .add_attribute("action", "register_remote_chain_and_port")
        .add_attribute("chain", chain)
        .add_attribute("src_channel", &channel_info.src_channel_id)
        .add_attribute("dest_channel", &channel_info.dest_channel_id)
        .add_attribute("dest_port", &channel_info.dest_channel_id))
}

/// Set permission for a local contract from the contract directly
/// It can be:
/// - `Permission::Permissionless` (the contract accept to receive msg from any remote contracts)
/// - `Permission::Permissioned` (the contract accept to receive msg only from specifics contracts)
pub fn run_set_permission(
    deps: DepsMut,
    sender: Addr,
    permission: Permission,
    chain: String,
) -> Result<Response, ContractError> {
    save_permission(deps.storage, sender.clone(), permission, chain.clone())?;

    Ok(Response::new()
        .add_attribute("action", "set_permission")
        .add_attribute("contract", sender.to_string())
        .add_attribute("chain", chain))
}

/// Set permission for a local contract by the admin of the contract
/// It can be:
/// - `Permission::Permissionless` (the contract accept to receive msg from any remote contracts)
/// - `Permission::Permissioned` (the contract accept to receive msg only from specifics contracts)
pub fn run_set_permission_from_admin(
    deps: DepsMut,
    sender: Addr,
    contract: Addr,
    permission: Permission,
    chain: String,
) -> Result<Response, ContractError> {
    match deps
        .querier
        .query_wasm_contract_info(contract.clone())?
        .admin
    {
        Some(admin) => {
            if admin != sender {
                Err(ContractError::Unauthorized {})
            } else {
                save_permission(deps.storage, contract.clone(), permission, chain.clone())?;

                // Check if the remote contract is alredy registered for the local contract
                Ok(Response::new()
                    .add_attribute("action", "set_permission_from_admin")
                    .add_attribute("admin", admin)
                    .add_attribute("contract", contract.to_string())
                    .add_attribute("chain", chain))
            }
        }
        None => Err(ContractError::ContractWithoutAdmin {
            contract: contract.to_string(),
        }),
    }
}

/// Set the `Permission` for the voucher contract token
pub fn run_set_voucher_permission(
    deps: DepsMut,
    controller: Addr,
    chain: String,
    local_voucher_contract: Addr,
    remote_voucher_contract: String,
) -> Result<Response, ContractError> {
    is_controller(deps.as_ref(), controller)?;

    let msg = CosmosMsg::Wasm(WasmMsg::Execute {
        contract_addr: local_voucher_contract.to_string(),
        msg: to_binary(&Cw20ExecuteMsg::GateSetPermission {
            contract: remote_voucher_contract,
            chain,
        })?,
        funds: vec![],
    });

    Ok(Response::new().add_message(msg))
}

// --- REPLY ---

/// Reply when we send `RequestFailed` msg to the sender contract
pub fn reply_ack_contract(_deps: DepsMut, result: SubMsgResult) -> Result<Response, ContractError> {
    match result {
        SubMsgResult::Ok(_) => Ok(Response::new()), // This should never happens since `ReplyOn::Error`
        SubMsgResult::Err(err) => Ok(Response::new()
            .add_attribute("ack_contract", "failed")
            .add_attribute("reason", err)),
    }
}

/// Reply on init a voucher
pub fn reply_init_token(
    deps: DepsMut,
    env: Env,
    result: SubMsgResult,
) -> Result<Response, ContractError> {
    match result {
        // if `Ok`, get the contract address of cw20 token and save it
        SubMsgResult::Ok(sub_response) => {
            let data = sub_response.data.unwrap();
            let res: MsgInstantiateContractResponse =
                ProtoMessage::parse_from_bytes(data.as_slice()).map_err(|_| {
                    StdError::parse_err("MsgInstantiateContractResponse", "failed to parse data")
                })?;

            match VOUCHER_REGISTERING_CHAIN.load(deps.storage).unwrap() {
                Some(value) => {
                    match value {
                        RegisteringVoucherChain::Local => {
                            CONIFG.update(
                                deps.storage,
                                |mut current| -> Result<Config, ContractError> {
                                    current.voucher_contract = Some(res.contract_address.clone());
                                    Ok(current)
                                },
                            )?;
                        }

                        RegisteringVoucherChain::Chain { name } => {
                            let mut chain_info =
                                CHAIN_REGISTERED_CHANNELS().load(deps.storage, name.clone())?;
                            chain_info.voucher_contract = Some(res.contract_address.clone());

                            CHAIN_REGISTERED_CHANNELS().save(deps.storage, name, &chain_info)?;
                        }
                    }
                    Ok(
                        Response::new().add_message(CosmosMsg::Wasm(WasmMsg::Execute {
                            contract_addr: res.contract_address,
                            msg: to_binary(&Cw20ExecuteMsg::RegisterGate {
                                contract: env.contract.address,
                            })?,
                            funds: vec![],
                        })),
                    )
                }
                None => Err(ContractError::Std(StdError::generic_err(
                    "VOUCHER_REGISTERING_CHAIN not setted, this shouldn't happen",
                ))),
            }
        }
        SubMsgResult::Err(err) => Err(ContractError::InitializeCw20Fails { err }),
    }
}

/// Reply when we send a ics20 transfer packer
pub fn reply_send_ibc_packet(
    deps: DepsMut,
    env: Env,
    result: SubMsgResult,
) -> Result<Response, ContractError> {
    match result {
        SubMsgResult::Ok(response) => Ok(reply_send_ibc_packet_ok(deps.storage, response)
            .unwrap_or_else(|err| {
                reply_send_ibc_packet_err(deps.storage, env, err.to_string()).unwrap()
            })),
        SubMsgResult::Err(err) => reply_send_ibc_packet_err(deps.storage, env, err),
    }
}

/// Ok Reply when we send a ics20 transfer packer.
/// The contract parse the response and save the `sequence` + `channel-id` for load the packet when `ibc_callback` will be triggered on sudo.
fn reply_send_ibc_packet_ok(
    storage: &mut dyn Storage,
    response: SubMsgResponse,
) -> Result<Response, StdError> {
    let SubMsgResponse{data: Some(data),..} = response else {
        return Err(StdError::generic_err( format!("failed reply: {:?}", response) ))
    };

    let response = MsgTransferResponse::decode(&data[..])
        .map_err(|_| StdError::generic_err(format!("could not decode response: {data}")))?;

    let (packet, dest_key) = PACKET_IBC_HOOK_AWAITING_REPLY.load(storage)?;

    let channel = packet.send_native.clone().unwrap().get_first_channel();

    PACKET_IBC_HOOK_AWAITING_ACK.save(
        storage,
        (channel.clone(), response.sequence),
        &(packet, dest_key),
    )?;

    Ok(Response::new()
        .add_attribute("action", "ics-20 packet stored")
        .add_attribute("channel", channel)
        .add_attribute("sequence", response.sequence.to_string()))
}

/// Err Reply when we send a ics20 transfer packer.
/// THIS SHOULDN'T NEVER HAPPEN.
/// Proceed like when the contract receive the sudo_ack as failed, requesting the cancellation of the packet on destination chain
fn reply_send_ibc_packet_err(
    storage: &mut dyn Storage,
    env: Env,
    err: String,
) -> Result<Response, ContractError> {
    let (packet, dest_key) = PACKET_IBC_HOOK_AWAITING_REPLY.load(storage)?;

    // Save the packet creating a unique key since the packet is failed before the assignment of a channel-id sequence
    let src_key = create_unique_src_key(storage, &env)?;

    PACKET_IBC_HOOK_AWAITING_ACK.save(
        storage,
        (src_key.channel.clone(), src_key.sequence),
        &(packet.clone(), dest_key.clone()),
    )?;

    let ibc_msg = IbcMsg::SendPacket {
        channel_id: get_channel_from_chain(storage, &packet.to_chain)?,
        data: to_binary(&GatePacket::RemoveStoredPacket {
            dest_key: dest_key.clone(),
            src_key: src_key.clone(),
        })?,
        timeout: env
            .block
            .time
            .plus_seconds(CONIFG.load(storage)?.default_timeout)
            .into(),
    };

    Ok(Response::new()
        .add_message(ibc_msg)
        .add_attribute("action", "reply_send_ibc_packet_err")
        .add_attribute("error", err)
        .add_attribute("next_action", "remove_stored_packet")
        .add_attribute("key_src_channel", src_key.channel)
        .add_attribute("key_src_sequence", src_key.sequence.to_string())
        .add_attribute("key_dest_channel", dest_key.channel)
        .add_attribute("key_dest_sequence", dest_key.sequence.to_string()))
}

// --- ACK ---

/// Packet receive, store or execute it based on `SendNativeInfo`
pub fn run_on_ack_receive(
    deps: DepsMut,
    env: Env,
    msg: IbcPacketAckMsg,
) -> Result<IbcBasicResponse, ContractError> {
    let gate_ack: GateAck = from_binary(&msg.acknowledgement.data)?;

    let mut res = match gate_ack.ack {
        GateAckType::EmptyResult => on_ack_empty_result(),
        GateAckType::Error(err) => on_ack_error(
            deps.storage,
            from_binary::<GatePacket>(&msg.original_packet.data)?
                .as_request_packet()
                .unwrap(),
            err,
        ),
        GateAckType::QueryResult(queries_response) => on_ack_query_result(queries_response),
        GateAckType::NativeSendRequest {
            dest_key,
            gate_packet,
        } => on_ack_native_send_request(deps.storage, env, dest_key, *gate_packet),
        GateAckType::RemoveStoredPacket { src_key, removed } => {
            on_ack_remove_store_packet(deps.storage, src_key, removed)
        }
    }?;

    if let Some(coin) = gate_ack.coin {
        let config = CONIFG.load(deps.storage)?;

        res.messages.insert(
            0,
            SubMsg::reply_on_error(
                CosmosMsg::Wasm(WasmMsg::Execute {
                    contract_addr: config.voucher_contract.unwrap(),
                    msg: to_binary(&Cw20ExecuteMsg::Mint {
                        recipient: msg.relayer.to_string(),
                        amount: coin.amount,
                    })?,
                    funds: vec![],
                }),
                ReplyID::MintVoucher.repr(),
            ),
        );
    }

    Ok(res)
}

/// Packet timeout, if:
/// - `GatePacket::RequestPacket` => Revert the request (see `on_ack_error`).
/// - `GatePacket::RemoveStoredPacket` => Resend the packet (see `sudo_on_ack_failed`)
pub fn run_on_ack_timeout(
    deps: DepsMut,
    env: Env,
    msg: IbcPacketTimeoutMsg,
) -> Result<IbcBasicResponse, ContractError> {
    match from_binary::<GatePacket>(&msg.packet.data)? {
        GatePacket::RequestPacket(packet) => {
            on_ack_error(deps.storage, *packet, "timeout".to_string())
        }

        // Retry to send a packet to remove the stored packet
        GatePacket::RemoveStoredPacket { src_key, .. } => Ok(IbcBasicResponse::new()
            .add_submessages(
                sudo_on_ack_failed(
                    deps,
                    env,
                    src_key.channel,
                    src_key.sequence,
                    "timeout".to_string(),
                )
                .unwrap()
                .messages,
            )
            .add_attribute("action", "acknowledge")
            .add_attribute("success", "false")
            .add_attribute("error", "timeout")),
    }
}

/// `Ok`, nothing to do
fn on_ack_empty_result() -> Result<IbcBasicResponse, ContractError> {
    Ok(IbcBasicResponse::new()
        .add_attribute("action", "on_ack_empty_result")
        .add_attribute("state", "success")
        .add_attribute("ack_type", "empty_result"))
}

/// Packet failed or timedout.
/// Send a `RequestFailed` to the sender contract.
fn on_ack_error(
    storage: &mut dyn Storage,
    packet: RequestsPacket,
    err: String,
) -> Result<IbcBasicResponse, ContractError> {
    let sub_msgs = create_revert_sub_msgs(storage, packet)?;
    // submsg.gas_limit = gas_limit;

    // similar event messages like ibctransfer module
    Ok(IbcBasicResponse::new()
        .add_submessages(sub_msgs)
        .add_attribute("action", "acknowledge")
        .add_attribute("success", "false")
        .add_attribute("error", err))
}

/// Send a `QueryResponse` msg to every contract that send a `GateRequest::Query`
fn on_ack_query_result(
    queries_response: Vec<QueryRequestInfoResponse>,
) -> Result<IbcBasicResponse, ContractError> {
    let mut sub_msgs: Vec<SubMsg> = vec![];

    for query_response in queries_response {
        sub_msgs.push(SubMsg::reply_on_error(
            GateMsg::QueryResponse {
                queries: query_response.queries,
                callback_msg: query_response.callback_msg,
            }
            .into_cosmos_msg(query_response.from_contract, vec![])?,
            ReplyID::AckContract.repr(),
        ));
    }

    Ok(IbcBasicResponse::new()
        .add_submessages(sub_msgs)
        .add_attribute("action", "acknowledge")
        .add_attribute("success", "true")
        .add_attribute("ack_type", "query_result"))
}

/// Packet with `Requests` has been stored as pending on destination chain.
/// The contract send a ics-20 transfer packet with `ibc hook` on `memo` to destination `gate`.
/// The `ibc hook` will trigger the execution of the stored packet.
fn on_ack_native_send_request(
    storage: &mut dyn Storage,
    env: Env,
    dest_key: PacketSavedKey,
    gate_packet: RequestsPacket,
) -> Result<IbcBasicResponse, ContractError> {
    let mut forward: Option<ForwardField<ExecuteMsg>> = None;

    let mut send_native_info = gate_packet.clone().send_native.unwrap();

    let remote_gate_contract = get_remote_gate_addr_from_chain(storage, &gate_packet.to_chain)?;

    let wasm_field = Some(WasmField {
        contract: remote_gate_contract.clone(),
        msg: ExecuteMsg::IbcHook(IbcHookMsg::ExecutePendingRequest {
            channel: dest_key.channel.clone(),
            sequence: dest_key.sequence,
        }),
    });

    let (memo, channel, receiver) = if !send_native_info.path_middle_forward.is_empty() {
        // The first path will be the destination of the packet, so we remove it from the forward
        let first_packet_path = send_native_info.path_middle_forward.remove(0);

        // Push a new PacketPath that rappresent the path to the destination chain
        send_native_info.path_middle_forward.push(PacketPath {
            channel_id: send_native_info.channel_id,
            address: remote_gate_contract,
        });

        for (i, path) in send_native_info
            .path_middle_forward
            .clone()
            .into_iter()
            .enumerate()
        {
            let next = if i == send_native_info.path_middle_forward.len() - 1 {
                Some(Box::new(MemoField {
                    forward: None,
                    wasm: wasm_field.clone(),
                    ibc_callback: None,
                }))
            } else {
                None
            };

            let next_forward = Some(ForwardField::<ExecuteMsg> {
                receiver: path.address,
                port: "transfer".to_string(),
                channel: path.channel_id,
                next,
            });

            match forward {
                Some(mut current_forward) => {
                    current_forward.next = Some(Box::new(MemoField {
                        forward: next_forward,
                        wasm: None,
                        ibc_callback: None,
                    }));
                    forward = Some(current_forward)
                }
                None => forward = next_forward,
            }
        }

        (
            MemoField {
                forward,
                wasm: None,
                ibc_callback: Some(env.contract.address.to_string()),
            },
            first_packet_path.channel_id,
            first_packet_path.address,
        )
    } else {
        (
            MemoField {
                forward: None,
                wasm: wasm_field,
                ibc_callback: Some(env.contract.address.to_string()),
            },
            send_native_info.channel_id,
            remote_gate_contract,
        )
    };

    let msg = MsgTransfer {
        source_port: "transfer".to_string(),
        source_channel: channel,
        token: Some(send_native_info.coin.into()),
        sender: env.contract.address.to_string(),
        receiver,
        timeout_height: None,
        timeout_timestamp: Some(
            env.block
                .time
                .plus_seconds(
                    send_native_info
                        .timeout
                        .unwrap_or(CONIFG.load(storage)?.default_timeout),
                )
                .nanos(),
        ),
        memo: to_string_pretty(&memo).unwrap(),
    };

    PACKET_IBC_HOOK_AWAITING_REPLY.save(storage, &(gate_packet, dest_key))?;

    Ok(IbcBasicResponse::new()
        .add_submessage(SubMsg::reply_always(msg, ReplyID::SendIbcHookPacket.repr())))
}

/// Ack of packet that should remove a stored packet on destination chain.
/// If the packet:
/// - has been removed: The contract will send a RevertRequest to every contract that have sent a request.
/// - has **NOT** been removed: Someone else manually triggered the packet on destination chain. Since the request has been executed, we don't need to revert.
fn on_ack_remove_store_packet(
    storage: &mut dyn Storage,
    src_key: PacketSavedKey,
    removed: bool,
) -> Result<IbcBasicResponse, ContractError> {
    match removed {
        true => {
            let packet = PACKET_IBC_HOOK_AWAITING_ACK
                .load(storage, (src_key.channel.clone(), src_key.sequence))?
                .0;

            let sub_msgs = create_revert_sub_msgs(storage, packet)?;

            PACKET_IBC_HOOK_AWAITING_ACK.remove(storage, (src_key.channel, src_key.sequence));

            Ok(IbcBasicResponse::new()
                .add_submessages(sub_msgs)
                .add_attribute("action", "on_ack_remove_store_packet")
                .add_attribute("removed", "true"))
        }
        false => Ok(IbcBasicResponse::new()
            .add_attribute("action", "on_ack_remove_store_packet")
            .add_attribute("removed", "false")),
    }
}

// --- SUDO ---

/// `Ok` on `ibc_callback` of ics-20 transfer packet.
pub fn sudo_ack_ok(
    deps: DepsMut,
    channel: String,
    sequence: u64,
) -> Result<Response, ContractError> {
    PACKET_IBC_HOOK_AWAITING_ACK.remove(deps.storage, (channel, sequence));
    Ok(Response::new()
        .add_attribute("action", "ibc_hook_ack")
        .add_attribute("success", "true"))
}

/// `Err` on `ibc_callback` of ics-20 transfer packet.
/// Send a gate packet to dest in order to remove the saved packet before revert.
/// This because the contract, before revert, must be sure that the packet has not been executed during the reverting
pub fn sudo_on_ack_failed(
    deps: DepsMut,
    env: Env,
    channel: String,
    sequence: u64,
    err: String,
) -> Result<Response, ContractError> {
    let (packet, dest_key) =
        PACKET_IBC_HOOK_AWAITING_ACK.load(deps.storage, (channel.clone(), sequence))?;

    let ibc_msg = IbcMsg::SendPacket {
        channel_id: get_channel_from_chain(deps.storage, &packet.to_chain)?,
        data: to_binary(&GatePacket::RemoveStoredPacket {
            dest_key: dest_key.clone(),
            src_key: PacketSavedKey {
                channel: channel.clone(),
                sequence,
            },
        })?,
        timeout: env
            .block
            .time
            .plus_seconds(CONIFG.load(deps.storage)?.default_timeout)
            .into(),
    };

    Ok(Response::new()
        .add_message(ibc_msg)
        .add_attribute("action", "sudo_on_ack_failed")
        .add_attribute("error", err)
        .add_attribute("next_action", "remove_stored_packet")
        .add_attribute("key_src_channel", channel)
        .add_attribute("key_src_sequence", sequence.to_string())
        .add_attribute("key_dest_channel", dest_key.channel)
        .add_attribute("key_dest_sequence", dest_key.sequence.to_string()))
}

// --- FUNCTIONS ---

/// Create a list of `RequestFailed`
fn create_revert_sub_msgs(
    storage: &mut dyn Storage,
    packet: RequestsPacket,
) -> StdResult<Vec<SubMsg>> {
    let mut sub_msgs: Vec<SubMsg> = vec![];

    let max_gas_amount = CONIFG.load(storage)?.max_gas_amount_per_revert;

    for requests_info in packet.requests_infos {
        for request in requests_info.requests {
            let funds = match request.send_native() {
                Some(send_native) => vec![send_native.coin],
                None => vec![],
            };

            let mut sub_msg = SubMsg::reply_on_error(
                GateMsg::RequestFailed { request }
                    .into_cosmos_msg(requests_info.sender.clone(), funds)?,
                ReplyID::AckContract.repr(),
            );

            sub_msg.gas_limit = Some(max_gas_amount);

            sub_msgs.push(sub_msg);
        }
    }

    Ok(sub_msgs)
}

/// Reedem native coin and burn voucher
fn redeem_voucher(
    deps: DepsMut,
    cw20_contract: Addr,
    sender: String,
    amount: Uint128,
) -> Result<Response, ContractError> {
    let config = CONIFG.load(deps.storage)?;

    if cw20_contract != config.voucher_contract.clone().unwrap() {
        return Err(ContractError::WrongVoucherAddres {
            expected: config.voucher_contract.unwrap(),
            received: cw20_contract.to_string(),
        });
    }

    let msg_burn = CosmosMsg::Wasm(WasmMsg::Execute {
        contract_addr: cw20_contract.to_string(),
        msg: to_binary(&Cw20ExecuteMsg::Burn { amount })?,
        funds: vec![],
    });

    let msg_send = CosmosMsg::Bank(BankMsg::Send {
        to_address: sender,
        amount: vec![Coin {
            denom: config.base_denom,
            amount,
        }],
    });

    Ok(Response::new()
        .add_message(msg_burn)
        .add_message(msg_send)
        .add_attribute("action", "reedem_voucher")
        .add_attribute("amount", amount))
}

/// Save `Permission` type for a specific `(contract, chain)`
fn save_permission(
    storage: &mut dyn Storage,
    contract: Addr,
    permission: Permission,
    chain: String,
) -> Result<(), ContractError> {
    // Check if the chain is registered
    if !CHAIN_REGISTERED_CHANNELS().has(storage, chain.clone()) {
        return Err(ContractError::ChainNotFound { chain });
    }

    REGISTERED_CONTRACTS.save(storage, (contract.to_string(), chain), &permission)?;

    Ok(())
}

/// Send all store packets to remote chain as single packet
fn send_packet(
    deps: DepsMut,
    env: Env,
    mut packet: RequestsPacket,
    timeout: Option<u64>,
) -> Result<Response, ContractError> {
    let channel = get_channel_from_chain(deps.storage, &packet.to_chain)?;

    BUFFER_PACKETS.save(deps.storage, &None)?;

    IS_REGISTERING.save(deps.storage, &false)?;

    let timeout = timeout.unwrap_or(CONIFG.load(deps.storage)?.default_timeout);

    // timeout is in nanoseconds
    let timeout = env.block.time.plus_seconds(timeout);

    if let Some(fee) = packet.fee {
        if fee.amount == Uint128::one() {
            packet.fee = None
        } else {
            packet.fee = Some(Coin {
                denom: fee.denom,
                amount: fee.amount / Uint128::from(2_u128),
            })
        }
    }

    // prepare ibc message
    let ibc_msg = IbcMsg::SendPacket {
        channel_id: channel,
        data: to_binary(&GatePacket::RequestPacket(Box::new(packet.clone())))?,
        timeout: timeout.into(),
    };

    // send responses\
    let res = Response::new()
        .add_message(ibc_msg)
        .add_attribute("action", "send_msg")
        .add_attribute("amount_msg", packet.requests_infos.len().to_string());

    Ok(res)
}

/// Store a msg received as packet
fn store_request_info(
    deps: DepsMut,
    request_info: GateRequestsInfo,
    to_chain: String,
    timeout: Option<u64>,
) -> Result<Response, ContractError> {
    BUFFER_PACKETS.update(deps.storage, |optioned_info| match optioned_info {
        Some(mut info) => {
            if info.packet.to_chain != to_chain {
                return Err(StdError::GenericErr {
                    msg: "Chain destination must be the same for all msgs".to_string(),
                });
            }

            info.timeout = lowest_timeout(info.timeout, timeout)?;

            info.packet.fee = merge_fee(&info.packet.fee, &request_info.fee)?;

            info.packet.send_native =
                merge_send_native(&info.packet.send_native, &request_info.send_native)?;

            info.packet.requests_infos.push(request_info);

            Ok(Some(info))
        }
        None => Ok(Some(GatePacketInfo {
            packet: RequestsPacket {
                requests_infos: vec![request_info.clone()],
                fee: request_info.fee,
                send_native: request_info.send_native,
                from_chain: None,
                to_chain,
            },
            timeout,
        })),
    })?;

    let res = Response::new().add_attribute("action", "store_packet");

    Ok(res)
}

/// In case the `MsgTransfer` fails on Reply (this should never happen), create a unique key to store the packet.
fn create_unique_src_key(storage: &mut dyn Storage, env: &Env) -> StdResult<PacketSavedKey> {
    let (mut height, mut idx) = LAST_FAILED_KEY_GENERATED.load(storage)?;

    if env.block.height != height {
        height = env.block.height;
        idx = 0;
    } else {
        idx += 1;
    }

    LAST_FAILED_KEY_GENERATED.save(storage, &(height, idx))?;

    Ok(PacketSavedKey {
        channel: height.to_string(),
        sequence: idx,
    })
}
