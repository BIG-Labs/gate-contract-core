use cosmwasm_std::{
    attr, from_binary, to_binary, Addr, Attribute, Binary, Coin, ContractResult, CosmosMsg,
    DepsMut, Empty, Env, IbcPacket, IbcReceiveResponse, QueryRequest, Response, StdResult, Storage,
    SubMsg, SubMsgResult, SystemResult, WasmMsg,
};
use cw20::Cw20ExecuteMsg;
use gate_pkg::{
    ExecuteMsg, GateMsg, GateQueryResponse, GateRequest, GateRequestsInfo, IbcHookMsg,
    QueryRequestInfoResponse,
};

use crate::{
    error::ContractError,
    functions::{
        get_chain_and_channel_info_from_registered_channel, remote_contract_is_registered,
    },
    state::{
        GateAck, GateAckType, GatePacket, PacketSavedKey, ReplyID, RequestsPacket,
        BUFFER_QUERIES_RESPONSE, PENDING_PACKETS, RECEIVED_FEE,
    },
};

// --- RUN ---

/// `GatePacket` received, based on `GatePacket` type:
/// - `GatePacket::RequestPacket`: gate execute all `Requests` or save the packet if `send_native` is present.
/// - `GatePacket::RemoveStoredPacket`: remove the stored key.
pub fn run_ibc_packet_receive(
    storage: &mut dyn Storage,
    env: Env,
    ibc_packet: IbcPacket,
    relayer: Addr,
) -> Result<IbcReceiveResponse, ContractError> {
    let (chain, channel_info) = get_chain_and_channel_info_from_registered_channel(
        storage,
        ibc_packet.dest.channel_id.clone(),
    )?;

    match from_binary::<GatePacket>(&ibc_packet.data)? {
        GatePacket::RequestPacket(packet) => handle_requests_packet(
            storage,
            env,
            *packet,
            chain,
            ibc_packet,
            channel_info.voucher_contract.unwrap(),
            relayer,
        ),
        GatePacket::RemoveStoredPacket { dest_key, src_key } => {
            handle_remove_stored_packet(storage, dest_key, src_key)
        }
    }
}

/// Handle `GatePacket::RequestPacket`
fn handle_requests_packet(
    storage: &mut dyn Storage,
    env: Env,
    mut packet: RequestsPacket,
    chain: String,
    ibc_packet: IbcPacket,
    voucher_contract: String,
    relayer: Addr,
) -> Result<IbcReceiveResponse, ContractError> {
    packet.from_chain = Some(chain);

    RECEIVED_FEE.save(storage, &packet.fee)?;

    let mut res = if packet.send_native.is_some() {
        store_pending_gate_packet(
            storage,
            ibc_packet.sequence,
            ibc_packet.dest.channel_id,
            packet.clone(),
        )?
    } else {
        IbcReceiveResponse::new()
            .add_submessage(create_execute_packet_submsg(env, packet.clone(), false)?)
            .add_attribute("action", "executed_gate_packet")
            .add_attribute("success", "true")
    };

    if let Some(fee) = packet.fee {
        res.messages.insert(
            0,
            SubMsg::reply_on_error(
                CosmosMsg::Wasm(WasmMsg::Execute {
                    contract_addr: voucher_contract,
                    msg: to_binary(&Cw20ExecuteMsg::Mint {
                        recipient: relayer.to_string(),
                        amount: fee.amount,
                    })?,
                    funds: vec![],
                }),
                ReplyID::MintVoucher.repr(),
            ),
        );
    };

    Ok(res)
}

/// Handle `GatePacket::RemoveStoredPacket`.
/// Ack will be setted, specify if the packet has been found or not.
fn handle_remove_stored_packet(
    storage: &mut dyn Storage,
    dest_key: PacketSavedKey,
    src_key: PacketSavedKey,
) -> Result<IbcReceiveResponse, ContractError> {
    let (ack, removed) =
        match PENDING_PACKETS.load(storage, (dest_key.channel.clone(), dest_key.sequence)) {
            Ok(_) => {
                PENDING_PACKETS.remove(storage, (dest_key.channel, dest_key.sequence));
                (set_ack_packet_removed(src_key, true), true)
            }
            Err(_) => (set_ack_packet_removed(src_key, false), false),
        };

    Ok(IbcReceiveResponse::new().set_ack(ack).add_attributes(vec![
        attr("action", "remove_stored_packet"),
        attr("removed", removed.to_string()),
    ]))
}

/// Create a `PrivateRemoteExecuteRequests` msg.
///
/// If this function is called from:
/// - `run_ibc_packet_receive`: setted as `SubMsg` with `Reply`;
/// - `ibc_hook`: setted as std `Msg` without `Reply`
pub fn create_execute_packet_submsg(
    env: Env,
    gate_packet: RequestsPacket,
    from_ibc_hook: bool,
) -> Result<SubMsg, ContractError> {
    let msg = CosmosMsg::Wasm(WasmMsg::Execute {
        contract_addr: env.contract.address.to_string(),
        msg: to_binary(&ExecuteMsg::PrivateRemoteExecuteRequests {
            requests_infos: gate_packet.requests_infos,
            from_chain: gate_packet.from_chain.unwrap(),
            native_denom: if let Some(send_native) = gate_packet.send_native {
                Some(send_native.dest_denom)
            } else {
                None
            },
        })?,
        funds: vec![],
    });

    if from_ibc_hook {
        Ok(SubMsg::new(msg))
    } else {
        Ok(SubMsg::reply_always(msg, ReplyID::ExecuteRequest.repr()))
    }
}

/// Packet received with `send_native`.
/// We save the packet in the contract and
pub fn store_pending_gate_packet(
    storage: &mut dyn Storage,
    sequence: u64,
    channel: String,
    gate_packet: RequestsPacket,
) -> Result<IbcReceiveResponse, ContractError> {
    PENDING_PACKETS.update(
        storage,
        (channel.clone(), sequence),
        |packet| match packet {
            Some(_) => Err(ContractError::PacketAlredyInPending {
                sequence,
                channel: channel.clone(),
            }),
            None => Ok(gate_packet.clone()),
        },
    )?;

    Ok(IbcReceiveResponse::new()
        .set_ack(set_ack_send_native_request(
            storage,
            sequence,
            channel.clone(),
            gate_packet,
        ))
        .add_attribute("action", "store_pending_gate_packet")
        .add_attribute("channel", channel)
        .add_attribute("sequence", sequence.to_string())
        .add_attribute("success", "true"))
}

/// Execute all `Requests` in the packet
pub fn run_private_remote_execute_requests(
    deps: DepsMut,
    env: Env,
    sender: Addr,
    requests_infos: Vec<GateRequestsInfo>,
    from_chain: String,
    native_denom: Option<String>,
) -> Result<Response, ContractError> {
    if sender != env.contract.address {
        return Err(ContractError::Unauthorized {});
    };

    BUFFER_QUERIES_RESPONSE.save(deps.storage, &vec![])?;

    let mut msgs: Vec<CosmosMsg> = vec![];

    for request_info in requests_infos {
        for request in request_info.requests {
            match request.clone() {
                GateRequest::SendMsg {
                    msg, to_contract, ..
                } => {
                    remote_contract_is_registered(
                        deps.as_ref(),
                        to_contract.clone(),
                        request_info.sender.clone(),
                        from_chain.clone(),
                    )?;

                    let funds = match request.send_native() {
                        Some(send_native) => match native_denom {
                            Some(ref native_denom) => {
                                vec![Coin {
                                    denom: native_denom.clone(),
                                    amount: send_native.coin.amount,
                                }]
                            }
                            None => {
                                return Err(ContractError::NoCoinWithPacket {
                                    expected: Coin {
                                        denom: send_native.coin.denom,
                                        amount: send_native.coin.amount,
                                    },
                                })
                            }
                        },
                        None => vec![],
                    };
                    msgs.push(
                        GateMsg::ReceivedMsg {
                            sender: request_info.sender.clone(),
                            msg: msg.clone(),
                        }
                        .into_cosmos_msg(to_contract.clone(), funds)?,
                    );
                }
                GateRequest::Query {
                    queries,
                    callback_msg,
                } => msgs.push(CosmosMsg::Wasm(WasmMsg::Execute {
                    contract_addr: env.contract.address.to_string(),
                    msg: to_binary(&ExecuteMsg::PrivateRemoteExecuteQuery {
                        queries,
                        from_contract: request_info.sender.clone(),
                        callback_msg,
                    })?,
                    funds: vec![],
                })),
            }
        }
    }

    Ok(Response::new()
        .add_messages(msgs)
        .add_attribute("action", "executing_packets"))
}

/// Execute `queries` requested and store the result
pub fn run_private_remote_execute_query(
    deps: DepsMut,
    env: Env,
    sender: Addr,
    queries: Vec<QueryRequest<Empty>>,
    from_contract: String,
    callback_msg: Option<Binary>,
) -> Result<Response, ContractError> {
    if sender != env.contract.address {
        return Err(ContractError::Unauthorized {});
    };

    let mut query_request_info_response = QueryRequestInfoResponse {
        queries: vec![],
        from_contract,
        callback_msg,
    };

    let mut attributes: Vec<Attribute> = vec![];

    for query in queries {
        let res = &deps.querier.raw_query(&to_binary(&query)?);

        let response = if let SystemResult::Ok(ContractResult::Ok(res)) = res {
            res.to_owned()
        } else {
            return Err(ContractError::QueryFailed {});
        };

        query_request_info_response.queries.push(GateQueryResponse {
            request: query,
            response: response.clone(),
        });

        attributes.push(Attribute {
            key: "action".to_string(),
            value: "query_performed".to_string(),
        })
    }

    update_buffer_queries(deps.storage, query_request_info_response);

    Ok(Response::new().add_attributes(attributes))
}

// --- IBC HOOK

/// `ibc hook` triggered, execute store `Packet`
pub fn run_ibc_hook(
    deps: DepsMut,
    env: Env,
    ibc_hook_msg: IbcHookMsg,
) -> Result<Response, ContractError> {
    match ibc_hook_msg {
        IbcHookMsg::ExecutePendingRequest { channel, sequence } => {
            let pending_packet = PENDING_PACKETS.load(deps.storage, (channel.clone(), sequence))?;
            PENDING_PACKETS.remove(deps.storage, (channel, sequence));
            // Ok(Response::new().add_attribute("ibc_hook_status", "ok"))
            Ok(Response::new()
                .add_submessage(create_execute_packet_submsg(env, pending_packet, true)?)
                .add_attribute("action", "ibc_hook"))
        }
    }
}

// --- REPLY ---

/// `Reply` of `PrivateRemoteExecuteRequests`.
/// Set the data of `Response` with the acknowledge based on `SubMsgResult`:
/// - `Ok` => `GateAckType::EmptyResult` if not queries were requested, else `GateAckType::QueryResult`;
/// - `Err` => `GateAckType::Error`
pub fn reply_execute_request(
    deps: DepsMut,
    result: SubMsgResult,
) -> Result<Response, ContractError> {
    match result {
        SubMsgResult::Ok(_) => Ok(Response::new()
            .set_data(set_ack_success(deps.storage))
            .add_attribute("receive_status", "success")),
        SubMsgResult::Err(err) => Ok(Response::new()
            .set_data(set_ack_fail(deps.storage, err.clone()))
            .add_attribute("receive_status", "failed")
            .add_attribute("receive_reason", err)),
    }
}

// --- SET ACK ---

/// `PrivateRemoteExecuteRequests` passed.
fn set_ack_success(storage: &mut dyn Storage) -> Binary {
    let queries = BUFFER_QUERIES_RESPONSE.load(storage).unwrap();

    if queries.is_empty() {
        to_binary(&GateAck {
            coin: RECEIVED_FEE.load(storage).unwrap_or(None),
            ack: GateAckType::EmptyResult,
        })
        .unwrap()
    } else {
        to_binary(&GateAck {
            coin: RECEIVED_FEE.load(storage).unwrap_or(None),
            ack: GateAckType::QueryResult(queries),
        })
        .unwrap()
    }
}

/// `PrivateRemoteExecuteRequests` failed.
pub fn set_ack_fail(storage: &dyn Storage, err: String) -> Binary {
    let res = GateAck {
        coin: RECEIVED_FEE.load(storage).unwrap_or(None),
        ack: GateAckType::Error(err),
    };
    to_binary(&res).unwrap()
}

/// Contract receive a `Packet` with `Requests` and a `send_native_info`.
/// The contract return an `ack` with the `key` of the stored `packet`.
pub fn set_ack_send_native_request(
    storage: &dyn Storage,
    sequence: u64,
    channel: String,
    gate_packet: RequestsPacket,
) -> Binary {
    let res = GateAck {
        coin: RECEIVED_FEE.load(storage).unwrap_or(None),
        ack: GateAckType::NativeSendRequest {
            dest_key: PacketSavedKey { channel, sequence },
            gate_packet: Box::new(gate_packet),
        },
    };
    to_binary(&res).unwrap()
}

/// Set on ack if the `Packet` has been removed or not
pub fn set_ack_packet_removed(src_key: PacketSavedKey, removed: bool) -> Binary {
    to_binary(&GateAck {
        coin: None,
        ack: GateAckType::RemoveStoredPacket { src_key, removed },
    })
    .unwrap()
}
// --- FUNCTIONS ---

/// Update `BUFFER_QUERIES_RESPONSE` with new query result
fn update_buffer_queries(storage: &mut dyn Storage, query_result: QueryRequestInfoResponse) {
    BUFFER_QUERIES_RESPONSE
        .update(
            storage,
            |mut queries| -> StdResult<Vec<QueryRequestInfoResponse>> {
                queries.push(query_result);
                Ok(queries)
            },
        )
        .unwrap();
}
