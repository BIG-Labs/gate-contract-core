use std::str::FromStr;

use cosmwasm_std::{
    from_binary, testing::mock_info, to_binary, Addr, BankMsg, Binary, Coin, ContractInfoResponse,
    CosmosMsg, Decimal, IbcAcknowledgement, IbcEndpoint, IbcMsg, IbcPacket, IbcPacketAckMsg,
    IbcPacketReceiveMsg, IbcPacketTimeoutMsg, IbcTimeout, IbcTimeoutBlock, QueryRequest, Reply,
    ReplyOn, Response, StdError, SubMsg, SubMsgResponse, SubMsgResult, Uint128, WasmMsg, WasmQuery,
};
use cw20::{Cw20ExecuteMsg, Cw20ReceiveMsg};
use gate_pkg::{
    merge_send_native, ChannelInfo, ExecuteMsg, GateMsg, GateQueryResponse, GateRequest,
    GateRequestsInfo, IbcHookMsg, PacketPath, Permission, QueryMsg, QueryRequestInfoResponse,
    ReceiverExecuteMsg, SendNativeInfo,
};
use schemars::_serde_json::to_string_pretty;

use cw20_icg_pkg::ExecuteMsg as Cw20IcgExecuteMsg;

use crate::{
    contract::{execute, query, reply},
    error::ContractError,
    extra::msg_transfer::MsgTransfer,
    functions::merge_fee,
    ibc::{ibc_packet_ack, ibc_packet_receive, ibc_packet_timeout},
    state::{
        Cw20MsgType, ForwardField, GateAck, GateAckType, GatePacket, IBCLifecycleComplete,
        MemoField, PacketSavedKey, ReplyID, RequestsPacket, SudoMsg, WasmField,
    },
    tests::{
        mock_querier::QueryMsgOracle,
        test_helper::{
            create_msg_transfer_reponse_encoded, gate_timeout, get_wasm_port_id, halving_fee,
            merge_fee_with_send_native, ResponseType, SubMsgType, CONNECTION, CONTROLLER,
            DEFAULT_TIMEOUT, LOCAL_BASE_DENOM, LOCAL_CONTRACT, LOCAL_GATE, LOCAL_VOUCHER,
            LOCAL_VOUCHER_OF_REMOTE, MAX_GAS_AMOUNT_PER_REVERT, REMOTE_BASE_DENOM, REMOTE_CHANNEL,
            REMOTE_CONTRACT, REMOTE_GATE, REMOTE_RELAYER, REMOTE_VOUCHER_OF_LOCAL,
        },
    },
};

use super::test_helper::{
    initialize_gate, GatesManager, LOCAL_CHAIN, LOCAL_CHANNEL, LOCAL_RELAYER, REMOTE_CHAIN,
    REMOTE_CONTRACT_HACK,
};

// --- SRC CHAIN ---

#[test]
fn channel_creation() {
    let (mut deps, env) = initialize_gate().unwrap();

    // --- Register chain and channel ---

    let msg = ExecuteMsg::RegisterChainAndChannel {
        chain: REMOTE_CHAIN.to_string(),
        src_channel: LOCAL_CHANNEL.to_string(),
        base_denom: "remote_base_denom".to_string(),
    };

    // Try fail from random address
    let res = execute(
        deps.as_mut(),
        env.clone(),
        mock_info("random_address", &[]),
        msg,
    );

    if res.is_ok() {
        panic!("Should return Error")
    }

    // --- Check if the channel created by `initialize_gate` has been saved properly

    let msg = QueryMsg::ChannelInfo {
        chain: REMOTE_CHAIN.to_string(),
    };

    let res = query(deps.as_ref(), env, msg).unwrap();

    let channel_info: ChannelInfo = from_binary(&res).unwrap();

    assert_eq!(
        channel_info,
        ChannelInfo {
            src_channel_id: LOCAL_CHANNEL.to_string(),
            dest_port_id: get_wasm_port_id(REMOTE_GATE),
            dest_channel_id: REMOTE_CHANNEL.to_string(),
            connection_id: CONNECTION.to_string(),
            base_denom: Some(REMOTE_BASE_DENOM.to_string()),
            voucher_contract: Some(LOCAL_VOUCHER_OF_REMOTE.to_string())
        }
    )
}

#[test]
fn permission() {
    let (mut deps, env) = initialize_gate().unwrap();

    // Assert default permission

    let msg = QueryMsg::Permission {
        contract: Addr::unchecked(LOCAL_CONTRACT),
        chain: REMOTE_CHAIN.to_string(),
    };

    let res = query(deps.as_ref(), env.clone(), msg).unwrap();

    let res_response: Permission = from_binary(&res).unwrap();

    assert_eq!(
        res_response,
        Permission::Permissioned {
            addresses: vec![REMOTE_CONTRACT.to_string()]
        }
    );

    // Set permission from admin

    let c_1 = "contract_1";
    let c_1_admin = "contract_1_admin";

    let mut contract_info = ContractInfoResponse::default();
    contract_info.admin = Some(c_1_admin.to_string());

    deps.querier
        .set_contract_info(c_1.to_string(), contract_info);

    let msg = ExecuteMsg::SetPermissionFromAdmin {
        contract: Addr::unchecked(c_1),
        permission: Permission::Permissionless {},
        chain: REMOTE_CHAIN.to_string(),
    };

    execute(deps.as_mut(), env.clone(), mock_info(c_1_admin, &[]), msg).unwrap();

    // Set permission from non admin

    let msg = ExecuteMsg::SetPermissionFromAdmin {
        contract: Addr::unchecked(c_1),
        permission: Permission::Permissionless {},
        chain: REMOTE_CHAIN.to_string(),
    };

    let res = execute(
        deps.as_mut(),
        env.clone(),
        mock_info("fake_admin", &[]),
        msg,
    );

    assert_eq!(
        res.unwrap_err().to_string(),
        ContractError::Unauthorized {}.to_string()
    );

    // Set permission for a contract without admin

    let c_2 = "contract_1";

    deps.querier
        .set_contract_info(c_2.to_string(), ContractInfoResponse::default());

    let msg = ExecuteMsg::SetPermissionFromAdmin {
        contract: Addr::unchecked(c_2),
        permission: Permission::Permissionless {},
        chain: REMOTE_CHAIN.to_string(),
    };

    let res = execute(
        deps.as_mut(),
        env.clone(),
        mock_info("fake_admin", &[]),
        msg,
    );

    assert_eq!(
        res.unwrap_err().to_string(),
        ContractError::ContractWithoutAdmin {
            contract: c_2.to_string()
        }
        .to_string()
    );

    // Voucher

    let msg = ExecuteMsg::SetVoucherPermission {
        chain: REMOTE_CHAIN.to_string(),
        local_voucher_contract: Addr::unchecked(LOCAL_VOUCHER),
        remote_voucher_contract: REMOTE_VOUCHER_OF_LOCAL.to_string(),
    };

    let res = execute(deps.as_mut(), env, mock_info(CONTROLLER, &[]), msg).unwrap();

    assert_eq!(
        res.messages,
        [SubMsg {
            id: 0,
            gas_limit: None,
            reply_on: ReplyOn::Never,
            msg: CosmosMsg::Wasm(WasmMsg::Execute {
                contract_addr: LOCAL_VOUCHER.to_string(),
                msg: to_binary(&Cw20IcgExecuteMsg::GateSetPermission {
                    contract: REMOTE_VOUCHER_OF_LOCAL.to_string(),
                    chain: REMOTE_CHAIN.to_string()
                })
                .unwrap(),
                funds: vec![]
            })
        }]
    )
}

#[test]
fn send_single_msg_request_no_native_with_fee() {
    let fee = Coin {
        denom: LOCAL_BASE_DENOM.to_string(),
        amount: Uint128::from(100_u128),
    };

    let (mut deps, env) = initialize_gate().unwrap();

    // Send Message to remote contract with some fee

    let msg = ExecuteMsg::SendRequests {
        requests: vec![GateRequest::SendMsg {
            msg: Binary::default(),
            to_contract: REMOTE_CONTRACT.to_string(),
            send_native: None,
        }],
        chain: REMOTE_CHAIN.to_string(),
        timeout: None,
    };

    let res = execute(
        deps.as_mut(),
        env,
        mock_info(LOCAL_CONTRACT, &[fee.clone()]),
        msg,
    )
    .unwrap();

    // Assert the packet created

    if let CosmosMsg::Ibc(IbcMsg::SendPacket {
        channel_id,
        data,
        timeout: _,
    }) = res.messages.first().unwrap().clone().msg
    {
        let packet = from_binary::<GatePacket>(&data)
            .unwrap()
            .as_request_packet()
            .unwrap();

        assert_eq!(
            packet,
            RequestsPacket {
                requests_infos: vec![GateRequestsInfo::new(
                    vec![GateRequest::SendMsg {
                        msg: Binary::default(),
                        to_contract: REMOTE_CONTRACT.to_string(),
                        send_native: None,
                    }],
                    LOCAL_CONTRACT.to_string(),
                    vec![fee.clone()],
                    LOCAL_BASE_DENOM.to_string(),
                )
                .unwrap()],
                fee: Some(Coin {
                    denom: LOCAL_BASE_DENOM.to_string(),
                    amount: fee.amount / Uint128::from(2_u128)
                }),
                send_native: None,
                from_chain: None,
                to_chain: REMOTE_CHAIN.to_string()
            }
        );

        assert_eq!(channel_id, LOCAL_CHANNEL.to_string());

        assert_eq!(
            packet.requests_infos.first().unwrap().clone().fee.unwrap(),
            fee
        );
        assert_eq!(
            packet.requests_infos.first().unwrap().clone().send_native,
            None
        )
    } else {
        panic!("Type should be IbcMsg::SendPacket")
    }
}

#[test]
fn redeem_voucher() {
    let fee_amount = Uint128::from(50_u128);

    let (mut deps, env) = initialize_gate().unwrap();

    let msg = ExecuteMsg::Receive(Cw20ReceiveMsg {
        sender: LOCAL_RELAYER.to_string(),
        amount: fee_amount,
        msg: to_binary(&Cw20MsgType::RedeemVoucher {}).unwrap(),
    });

    let res = execute(deps.as_mut(), env, mock_info(LOCAL_VOUCHER, &[]), msg).unwrap();

    match res.messages[0].clone().msg {
        CosmosMsg::Wasm(WasmMsg::Execute {
            contract_addr,
            msg,
            funds,
        }) => {
            assert_eq!(contract_addr, LOCAL_VOUCHER.to_string());
            assert_eq!(funds, vec![]);

            assert_eq!(
                from_binary::<Cw20ExecuteMsg>(&msg).unwrap(),
                Cw20ExecuteMsg::Burn { amount: fee_amount }
            )
        }
        _ => panic!(
            "Should be ComsosMsg::Wasm(WasmMsg::Execute), instead returned: {:?}",
            res.messages[0].clone().msg
        ),
    }

    match res.messages[1].clone().msg {
        CosmosMsg::Bank(BankMsg::Send { to_address, amount }) => {
            assert_eq!(to_address, LOCAL_RELAYER.to_string());
            assert_eq!(
                amount,
                vec![Coin {
                    denom: LOCAL_BASE_DENOM.to_string(),
                    amount: fee_amount
                }]
            )
        }
        _ => panic!(
            "Should be ComsosMsg::Wasm(WasmMsg::Execute), instead returned: {:?}",
            res.messages[0].clone().msg
        ),
    }
}

#[test]
fn collect_msgs() {
    let user_addr = "user000";

    let coin = Coin {
        denom: "btc".to_string(),
        amount: Uint128::from(123_u128),
    };

    let (mut deps, env) = initialize_gate().unwrap();

    // COLLECT

    let msg = ExecuteMsg::CollectRequests {
        to_contract: Addr::unchecked(LOCAL_CONTRACT),
        msg: Binary::default(),
    };

    let res = execute(
        deps.as_mut(),
        env.clone(),
        mock_info(user_addr, &[coin.clone()]),
        msg,
    )
    .unwrap();

    let msg_to_contract = &res.messages[0];
    let msg_send_packet = &res.messages[1];

    assert_eq!(
        msg_to_contract.msg,
        GateMsg::CollectRequests {
            sender: Addr::unchecked(user_addr),
            msg: Binary::default()
        }
        .into_cosmos_msg(LOCAL_CONTRACT.to_string(), vec![coin])
        .unwrap()
    );

    // RECEIVE DOUBLE REQUEST

    // 1

    let sender_1 = "sender_1".to_string();

    let receiver_1 = "receiver_1".to_string();

    let msg_1 = to_binary("msg_1").unwrap();

    let fee_1: Option<Coin> = None;

    let send_native_1 = Some(SendNativeInfo {
        coin: Coin {
            denom: "eth".to_string(),
            amount: Uint128::from(100_u128),
        },
        path_middle_forward: vec![PacketPath {
            channel_id: "middle-channel-transfer".to_string(),
            address: "middle-address".to_string(),
        }],
        dest_denom: "ibc/...".to_string(),
        channel_id: "dest-channel-transfer".to_string(),
        timeout: None,
    });

    let request_1 = GateRequest::SendMsg {
        msg: msg_1,
        to_contract: receiver_1,
        send_native: send_native_1.clone(),
    };

    let msg_1 = ExecuteMsg::SendRequests {
        requests: vec![request_1.clone()],
        chain: REMOTE_CHAIN.to_string(),
        timeout: None,
    };

    let funds_1 = merge_fee_with_send_native(&fee_1, &send_native_1);

    execute(
        deps.as_mut(),
        env.clone(),
        mock_info(&sender_1, &funds_1),
        msg_1,
    )
    .unwrap();

    // 2

    let msg_2 = to_binary("msg_2").unwrap();

    let fee_2: Option<Coin> = Some(Coin {
        denom: LOCAL_BASE_DENOM.to_string(),
        amount: Uint128::from(100_u128),
    });

    let send_native_2 = Some(SendNativeInfo {
        coin: Coin {
            denom: "eth".to_string(),
            amount: Uint128::from(150_u128),
        },
        path_middle_forward: vec![PacketPath {
            channel_id: "middle-channel-transfer".to_string(),
            address: "middle-address".to_string(),
        }],
        dest_denom: "ibc/...".to_string(),
        channel_id: "dest-channel-transfer".to_string(),
        timeout: None,
    });

    let sender_2 = "sender_2".to_string();
    let receiver_2 = "receiver_2".to_string();

    let request_2 = GateRequest::SendMsg {
        msg: msg_2,
        to_contract: receiver_2,
        send_native: send_native_2.clone(),
    };

    let msg_2 = ExecuteMsg::SendRequests {
        requests: vec![request_2.clone()],
        chain: REMOTE_CHAIN.to_string(),
        timeout: None,
    };

    let funds_2 = merge_fee_with_send_native(&fee_2, &send_native_2);

    execute(
        deps.as_mut(),
        env.clone(),
        mock_info(&sender_2, &funds_2),
        msg_2,
    )
    .unwrap();

    // PRIVATE_SEND_PACKET

    let msg: ExecuteMsg = if let CosmosMsg::Wasm(WasmMsg::Execute {
        contract_addr,
        msg,
        funds,
    }) = &msg_send_packet.msg
    {
        let msg: ExecuteMsg = from_binary(msg).unwrap();
        assert_eq!(contract_addr, &LOCAL_GATE.to_string());
        assert_eq!(funds, &vec![]);

        match msg {
            ExecuteMsg::PrivateSendCollectedMsgs => msg,
            _ => panic!(
                "Expected ExecuteMsg::PrivateSendCollectedMsgs, find {:?}",
                msg_send_packet
            ),
        }
    } else {
        panic!(
            "Wrong CosmosMsg, expected CosmosMsg::Wasm(WasmMsg::Execute), find {:?}",
            msg_send_packet
        )
    };

    let res_send_packet = execute(deps.as_mut(), env, mock_info(LOCAL_GATE, &[]), msg).unwrap();

    // ASSERT PACKET

    assert_eq!(&res_send_packet.messages.len(), &1);

    let packet = res_send_packet.messages.first().unwrap().clone().msg;

    if let CosmosMsg::Ibc(IbcMsg::SendPacket {
        channel_id, data, ..
    }) = packet
    {
        assert_eq!(channel_id, LOCAL_CHANNEL.to_string());

        let packet: GatePacket = from_binary(&data).unwrap();

        let total_fee: Option<Coin> = match merge_fee(&fee_1, &fee_2).unwrap() {
            Some(mut fee) => {
                fee.amount /= Uint128::from(2_u128);
                Some(fee)
            }
            None => None,
        };

        assert_eq!(
            packet,
            GatePacket::RequestPacket(Box::new(RequestsPacket {
                from_chain: None,
                to_chain: REMOTE_CHAIN.to_string(),
                fee: total_fee,
                requests_infos: vec![
                    GateRequestsInfo::new(
                        vec![request_1],
                        sender_1,
                        funds_1,
                        LOCAL_BASE_DENOM.to_string()
                    )
                    .unwrap(),
                    GateRequestsInfo::new(
                        vec![request_2],
                        sender_2,
                        funds_2,
                        LOCAL_BASE_DENOM.to_string()
                    )
                    .unwrap()
                ],
                send_native: merge_send_native(&send_native_1, &send_native_2).unwrap()
            }))
        )
    }
}

#[test]
fn timeout_no_native() {
    let (mut deps, env) = initialize_gate().unwrap();

    let packet = IbcPacket::new(
        to_binary(&GatePacket::RequestPacket(Box::new(RequestsPacket {
            requests_infos: vec![GateRequestsInfo::new(
                vec![GateRequest::SendMsg {
                    msg: Binary::default(),
                    to_contract: REMOTE_CONTRACT.to_string(),
                    send_native: None,
                }],
                LOCAL_CONTRACT.to_string(),
                vec![],
                LOCAL_BASE_DENOM.to_string(),
            )
            .unwrap()],
            fee: None,
            send_native: None,
            from_chain: None,
            to_chain: LOCAL_CHAIN.to_string(),
        })))
        .unwrap(),
        IbcEndpoint {
            port_id: get_wasm_port_id(REMOTE_CONTRACT),
            channel_id: REMOTE_CHANNEL.to_string(),
        },
        IbcEndpoint {
            port_id: get_wasm_port_id(LOCAL_CONTRACT),
            channel_id: LOCAL_CHANNEL.to_string(),
        },
        1_u64,
        IbcTimeout::with_block(IbcTimeoutBlock {
            revision: 1_u64,
            height: 1_u64,
        }),
    );

    let msg = IbcPacketTimeoutMsg::new(packet, Addr::unchecked(LOCAL_RELAYER));

    let res = ibc_packet_timeout(deps.as_mut(), env, msg).unwrap();

    assert_eq!(
        res.messages,
        vec![SubMsg {
            id: ReplyID::AckContract.repr(),
            gas_limit: Some(MAX_GAS_AMOUNT_PER_REVERT),
            reply_on: ReplyOn::Error,
            msg: CosmosMsg::Wasm(WasmMsg::Execute {
                contract_addr: LOCAL_CONTRACT.to_string(),
                funds: vec![],
                msg: to_binary(&ReceiverExecuteMsg::ReceiveGateMsg(
                    GateMsg::RequestFailed {
                        request: GateRequest::SendMsg {
                            msg: Binary::default(),
                            to_contract: REMOTE_CONTRACT.to_string(),
                            send_native: None,
                        }
                    }
                ))
                .unwrap()
            })
        }]
    )
}

#[test]
fn msg_transfer_fails_on_reply() {
    let (mut deps, mut env) = initialize_gate().unwrap();

    env.block.height = 200;

    // Trigger ibc_packet_ack

    let transfer_channel = "channel-123".to_string();
    let dest_denom = "ibc/uosmo".to_string();
    let transfer_denom = "uomso".to_string();
    let timeout_send_native = Some(123_123_123_u64);

    let dest_key = PacketSavedKey {
        channel: REMOTE_CHANNEL.to_string(),
        sequence: 1,
    };

    let send_native = Some(SendNativeInfo {
        coin: Coin {
            denom: transfer_denom,
            amount: Uint128::from(100_u128),
        },
        path_middle_forward: vec![],
        dest_denom,
        channel_id: transfer_channel,
        timeout: timeout_send_native,
    });

    let packet = RequestsPacket {
        from_chain: Some(LOCAL_CHAIN.to_string()),
        to_chain: REMOTE_CHAIN.to_string(),
        requests_infos: vec![],
        fee: None,
        send_native,
    };

    let ibc_packet = IbcPacket::new(
        to_binary(&GatePacket::RequestPacket(Box::new(packet.clone()))).unwrap(),
        IbcEndpoint {
            port_id: get_wasm_port_id(REMOTE_CONTRACT),
            channel_id: REMOTE_CHANNEL.to_string(),
        },
        IbcEndpoint {
            port_id: get_wasm_port_id(LOCAL_CONTRACT),
            channel_id: LOCAL_CHANNEL.to_string(),
        },
        1_u64,
        IbcTimeout::with_block(IbcTimeoutBlock {
            revision: 1_u64,
            height: 1_u64,
        }),
    );

    let msg = IbcPacketAckMsg::new(
        IbcAcknowledgement::new(
            to_binary(&GateAck {
                coin: None,
                ack: GateAckType::NativeSendRequest {
                    dest_key,
                    gate_packet: Box::new(packet),
                },
            })
            .unwrap(),
        ),
        ibc_packet,
        Addr::unchecked(LOCAL_RELAYER),
    );

    ibc_packet_ack(deps.as_mut(), env.clone(), msg.clone()).unwrap();

    // Trigger Reply

    let msg_reply = Reply {
        id: ReplyID::SendIbcHookPacket.repr(),
        result: SubMsgResult::Err("random_err".to_string()),
    };

    let res = reply(deps.as_mut(), env.clone(), msg_reply.clone()).unwrap();

    if let CosmosMsg::Ibc(IbcMsg::SendPacket { data, .. }) =
        res.messages.first().unwrap().clone().msg
    {
        let packet: GatePacket = from_binary(&data).unwrap();

        if let GatePacket::RemoveStoredPacket { src_key, .. } = packet {
            assert_eq!(
                src_key,
                PacketSavedKey {
                    channel: env.block.height.to_string(),
                    sequence: 0
                }
            )
        } else {
            panic!("wrong packet type")
        }
    } else {
        panic!("wrong msg type")
    }

    // Another fails on reply on the same block

    ibc_packet_ack(deps.as_mut(), env.clone(), msg.clone()).unwrap();

    let res = reply(deps.as_mut(), env.clone(), msg_reply.clone()).unwrap();

    if let CosmosMsg::Ibc(IbcMsg::SendPacket { data, .. }) =
        res.messages.first().unwrap().clone().msg
    {
        let packet: GatePacket = from_binary(&data).unwrap();

        if let GatePacket::RemoveStoredPacket { src_key, .. } = packet {
            assert_eq!(
                src_key,
                PacketSavedKey {
                    channel: env.block.height.to_string(),
                    sequence: 1
                }
            )
        } else {
            panic!("wrong packet type")
        }
    } else {
        panic!("wrong msg type")
    }

    // Another fails on reply on another block same block
    env.block.height = 201;

    ibc_packet_ack(deps.as_mut(), env.clone(), msg).unwrap();

    let res = reply(deps.as_mut(), env.clone(), msg_reply).unwrap();

    if let CosmosMsg::Ibc(IbcMsg::SendPacket { data, .. }) =
        res.messages.first().unwrap().clone().msg
    {
        let packet: GatePacket = from_binary(&data).unwrap();

        if let GatePacket::RemoveStoredPacket { src_key, .. } = packet {
            assert_eq!(
                src_key,
                PacketSavedKey {
                    channel: env.block.height.to_string(),
                    sequence: 0
                }
            )
        } else {
            panic!("wrong packet type")
        }
    } else {
        panic!("wrong msg type")
    }
}

// --- DEST CHAIN ---

#[test]
fn receive_single_msg_request_no_native_ok_with_fee() {
    let fee_amount = Uint128::from(50_u128);

    let fee = Coin {
        denom: REMOTE_BASE_DENOM.to_string(),
        amount: fee_amount,
    };

    let (mut deps, env) = initialize_gate().unwrap();

    let ibc_packet = IbcPacketReceiveMsg::new(
        IbcPacket::new(
            to_binary(&GatePacket::RequestPacket(Box::new(RequestsPacket {
                requests_infos: vec![GateRequestsInfo::new(
                    vec![GateRequest::SendMsg {
                        msg: Binary::default(),
                        to_contract: LOCAL_CONTRACT.to_string(),
                        send_native: None,
                    }],
                    REMOTE_CONTRACT.to_string(),
                    vec![fee.clone()],
                    REMOTE_BASE_DENOM.to_string(),
                )
                .unwrap()],
                fee: Some(fee.clone()),
                send_native: None,
                from_chain: None,
                to_chain: LOCAL_CHAIN.to_string(),
            })))
            .unwrap(),
            IbcEndpoint {
                port_id: get_wasm_port_id(REMOTE_CONTRACT),
                channel_id: REMOTE_CHANNEL.to_string(),
            },
            IbcEndpoint {
                port_id: get_wasm_port_id(LOCAL_CONTRACT),
                channel_id: LOCAL_CHANNEL.to_string(),
            },
            1_u64,
            IbcTimeout::with_block(IbcTimeoutBlock {
                revision: 1_u64,
                height: 1_u64,
            }),
        ),
        Addr::unchecked(LOCAL_RELAYER),
    );

    let res = ibc_packet_receive(deps.as_mut(), env.clone(), ibc_packet).unwrap();

    // MINT VOUCHER

    match res.messages[0].clone().msg {
        CosmosMsg::Wasm(WasmMsg::Execute {
            contract_addr,
            msg,
            funds,
        }) => {
            assert_eq!(contract_addr, LOCAL_VOUCHER_OF_REMOTE);
            assert_eq!(funds, vec![]);
            assert_eq!(
                from_binary::<Cw20ExecuteMsg>(&msg).unwrap(),
                Cw20ExecuteMsg::Mint {
                    recipient: LOCAL_RELAYER.to_string(),
                    amount: fee_amount
                }
            );
        }
        _ => panic!(
            "Should be ComsosMsg::Wasm(WasmMsg::Execute), instead returned: {:?}",
            res.messages.first().unwrap().clone().msg
        ),
    };

    // DELIVER REQUEST

    let next_msg = match res.messages[1].clone().msg {
        CosmosMsg::Wasm(WasmMsg::Execute {
            contract_addr,
            msg,
            funds,
        }) => {
            assert_eq!(contract_addr, env.contract.address);
            assert_eq!(funds, vec![]);

            let exe_msg = ExecuteMsg::PrivateRemoteExecuteRequests {
                requests_infos: vec![GateRequestsInfo::new(
                    vec![GateRequest::SendMsg {
                        msg: Binary::default(),
                        to_contract: LOCAL_CONTRACT.to_string(),
                        send_native: None,
                    }],
                    REMOTE_CONTRACT.to_string(),
                    vec![fee],
                    REMOTE_BASE_DENOM.to_string(),
                )
                .unwrap()],
                native_denom: None,
                from_chain: REMOTE_CHAIN.to_string(),
            };

            assert_eq!(from_binary::<ExecuteMsg>(&msg).unwrap(), exe_msg);

            exe_msg
        }
        _ => panic!(
            "Should be ComsosMsg::Wasm(WasmMsg::Execute), instead returned: {:?}",
            res.messages.first().unwrap().clone().msg
        ),
    };

    let res = execute(
        deps.as_mut(),
        env.clone(),
        mock_info(env.contract.address.as_str(), &[]),
        next_msg,
    )
    .unwrap();

    match res.messages.first().unwrap().clone().msg {
        CosmosMsg::Wasm(WasmMsg::Execute {
            contract_addr,
            msg,
            funds,
        }) => {
            assert_eq!(contract_addr, LOCAL_CONTRACT);
            assert_eq!(funds, vec![]);

            assert_eq!(
                from_binary::<ReceiverExecuteMsg>(&msg).unwrap(),
                ReceiverExecuteMsg::ReceiveGateMsg(GateMsg::ReceivedMsg {
                    sender: REMOTE_CONTRACT.to_string(),
                    msg: Binary::default()
                })
            );
        }
        _ => panic!(
            "Should be ComsosMsg::Wasm(WasmMsg::Execute), instead returned: {:?}",
            res.messages.first().unwrap().clone().msg
        ),
    }
}

#[test]
fn receive_single_msg_request_no_native_err() {
    let (mut deps, env) = initialize_gate().unwrap();

    // PACKET FROM NON GATE ADDRESS

    let ibc_packet = IbcPacketReceiveMsg::new(
        IbcPacket::new(
            to_binary(&GatePacket::RequestPacket(Box::new(RequestsPacket {
                requests_infos: vec![GateRequestsInfo::new(
                    vec![GateRequest::SendMsg {
                        msg: Binary::default(),
                        to_contract: LOCAL_CONTRACT.to_string(),
                        send_native: None,
                    }],
                    REMOTE_CONTRACT.to_string(),
                    vec![],
                    REMOTE_BASE_DENOM.to_string(),
                )
                .unwrap()],
                fee: None,
                send_native: None,
                from_chain: None,
                to_chain: LOCAL_CHAIN.to_string(),
            })))
            .unwrap(),
            IbcEndpoint {
                port_id: get_wasm_port_id("HACK_CONTRACT"),
                channel_id: "REMOTE_HACK_CHANNEL".to_string(),
            },
            IbcEndpoint {
                port_id: get_wasm_port_id(LOCAL_CONTRACT),
                channel_id: "LOCAL_HACK_CHANNEL".to_string(),
            },
            1_u64,
            IbcTimeout::with_block(IbcTimeoutBlock {
                revision: 1_u64,
                height: 1_u64,
            }),
        ),
        Addr::unchecked(LOCAL_RELAYER),
    );

    let res = ibc_packet_receive(deps.as_mut(), env.clone(), ibc_packet).unwrap();

    assert_eq!(res.messages.len(), 0);

    if let GateAckType::Error(err) = from_binary::<GateAck>(&res.acknowledgement).unwrap().ack {
        assert_eq!(
            err,
            ContractError::Std(StdError::generic_err(
                "Key not found \"LOCAL_HACK_CHANNEL\""
            ))
            .to_string()
        )
    }

    // REQUEST FROM NOT REGISTERED ADDRESS

    let ibc_packet = IbcPacketReceiveMsg::new(
        IbcPacket::new(
            to_binary(&GatePacket::RequestPacket(Box::new(RequestsPacket {
                requests_infos: vec![GateRequestsInfo::new(
                    vec![GateRequest::SendMsg {
                        msg: Binary::default(),
                        to_contract: LOCAL_CONTRACT.to_string(),
                        send_native: None,
                    }],
                    REMOTE_CONTRACT_HACK.to_string(),
                    vec![],
                    REMOTE_BASE_DENOM.to_string(),
                )
                .unwrap()],
                fee: None,
                send_native: None,
                from_chain: None,
                to_chain: LOCAL_CHAIN.to_string(),
            })))
            .unwrap(),
            IbcEndpoint {
                port_id: get_wasm_port_id(REMOTE_CONTRACT),
                channel_id: REMOTE_CHANNEL.to_string(),
            },
            IbcEndpoint {
                port_id: get_wasm_port_id(LOCAL_CONTRACT),
                channel_id: LOCAL_CHANNEL.to_string(),
            },
            1_u64,
            IbcTimeout::with_block(IbcTimeoutBlock {
                revision: 1_u64,
                height: 1_u64,
            }),
        ),
        Addr::unchecked(LOCAL_RELAYER),
    );

    let res = ibc_packet_receive(deps.as_mut(), env.clone(), ibc_packet).unwrap();

    let next_msg = match res.messages.first().unwrap().clone().msg {
        CosmosMsg::Wasm(WasmMsg::Execute { msg, .. }) => from_binary::<ExecuteMsg>(&msg).unwrap(),
        _ => panic!(
            "Should be ComsosMsg::Wasm(WasmMsg::Execute), instead returned: {:?}",
            res.messages.first().unwrap().clone().msg
        ),
    };

    let res = execute(
        deps.as_mut(),
        env.clone(),
        mock_info(env.contract.address.as_str(), &[]),
        next_msg,
    );

    if let ContractError::RemoteContractNotRegistered {
        local_contract,
        remote_contract,
    } = res.unwrap_err()
    {
        assert_eq!(local_contract, LOCAL_CONTRACT);
        assert_eq!(remote_contract, REMOTE_CONTRACT_HACK);
    } else {
        panic!("Should return error")
    }
}

#[test]
fn receive_single_query_request() {
    let (mut deps, env) = initialize_gate().unwrap();

    let local_oracle = "local_oracle".to_string();
    let remote_oracle = "remote_oracle".to_string();
    let remote_asset = "btc".to_string();

    let price = Decimal::from_str("3").unwrap();

    deps.querier.set_price(price);

    let msg = IbcPacketReceiveMsg::new(
        IbcPacket::new(
            to_binary(&GatePacket::RequestPacket(Box::new(RequestsPacket {
                requests_infos: vec![GateRequestsInfo::new(
                    vec![GateRequest::Query {
                        queries: vec![QueryRequest::Wasm(WasmQuery::Smart {
                            contract_addr: remote_oracle.clone(),
                            msg: to_binary(&QueryMsgOracle::Price {
                                asset: remote_asset.clone(),
                            })
                            .unwrap(),
                        })],
                        callback_msg: Some(Binary::default()),
                    }],
                    local_oracle.clone(),
                    vec![],
                    LOCAL_BASE_DENOM.to_string(),
                )
                .unwrap()],
                fee: None,
                send_native: None,
                from_chain: None,
                to_chain: LOCAL_CHAIN.to_string(),
            })))
            .unwrap(),
            IbcEndpoint {
                port_id: get_wasm_port_id(REMOTE_GATE),
                channel_id: REMOTE_CHANNEL.to_string(),
            },
            IbcEndpoint {
                port_id: get_wasm_port_id(LOCAL_GATE),
                channel_id: LOCAL_CHANNEL.to_string(),
            },
            1_u64,
            IbcTimeout::with_block(IbcTimeoutBlock {
                revision: 1_u64,
                height: 1_u64,
            }),
        ),
        Addr::unchecked(LOCAL_RELAYER),
    );

    // RECEIVE IBC PACKET
    let res = ibc_packet_receive(deps.as_mut(), env.clone(), msg).unwrap();

    assert_eq!(res.messages.len(), 1);

    let private_exe_requests = match res.messages.first().unwrap().msg.clone() {
        CosmosMsg::Wasm(WasmMsg::Execute {
            contract_addr,
            msg,
            funds,
        }) => {
            assert_eq!(contract_addr, env.contract.address);
            assert_eq!(funds, vec![]);
            from_binary::<ExecuteMsg>(&msg).unwrap()
        }
        _ => panic!(
            "Should be ComsosMsg::Wasm(WasmMsg::Execute), instead returned: {:?}",
            res.messages.first().unwrap().clone().msg
        ),
    };

    // PRIVATE_EXECUTE

    let res = execute(
        deps.as_mut(),
        env.clone(),
        mock_info(env.contract.address.as_str(), &[]),
        private_exe_requests,
    )
    .unwrap();

    let private_perform_query = match res.messages.first().unwrap().msg.clone() {
        CosmosMsg::Wasm(WasmMsg::Execute {
            contract_addr,
            msg,
            funds,
        }) => {
            assert_eq!(contract_addr, env.contract.address);
            assert_eq!(funds, vec![]);
            from_binary::<ExecuteMsg>(&msg).unwrap()
        }
        _ => panic!(
            "Should be ComsosMsg::Wasm(WasmMsg::Execute), instead returned: {:?}",
            res.messages.first().unwrap().clone().msg
        ),
    };

    // PRIVATE_EXECUTE_QUERY

    let _res = execute(
        deps.as_mut(),
        env.clone(),
        mock_info(env.contract.address.as_str(), &[]),
        private_perform_query,
    )
    .unwrap();

    // REPLY FROM ExecuteMsg::PrivateRemoteExecuteRequests

    let res = reply(
        deps.as_mut(),
        env,
        Reply {
            id: ReplyID::ExecuteRequest.repr(),
            result: SubMsgResult::Ok(SubMsgResponse {
                events: vec![],
                data: None,
            }),
        },
    )
    .unwrap();

    if let Some(data) = res.data {
        assert_eq!(
            from_binary::<GateAck>(&data).unwrap().ack,
            GateAckType::QueryResult(vec![QueryRequestInfoResponse {
                queries: vec![GateQueryResponse {
                    request: QueryRequest::Wasm(WasmQuery::Smart {
                        contract_addr: remote_oracle,
                        msg: to_binary(&QueryMsgOracle::Price {
                            asset: remote_asset,
                        })
                        .unwrap(),
                    }),
                    response: to_binary(&price).unwrap()
                }],
                from_contract: local_oracle,
                callback_msg: Some(Binary::default())
            }])
        )
    } else {
        panic!("Data is None but is should be something")
    }
}

// --- INTERCHAIN ---

#[test]
fn interchain() {
    let mut manager = GatesManager::new();
    let msg_to_send = to_binary("ok").unwrap();

    let send_native = None;
    let fee = None;

    let msg = ExecuteMsg::SendRequests {
        requests: vec![GateRequest::SendMsg {
            msg: msg_to_send.clone(),
            to_contract: REMOTE_CONTRACT.to_string(),
            send_native: send_native.clone(),
        }],
        chain: REMOTE_CHAIN.to_string(),
        timeout: None,
    };

    let rm = manager.execute_all(
        true,
        msg,
        Addr::unchecked(LOCAL_CONTRACT),
        merge_fee_with_send_native(&fee, &send_native),
    );

    let msg_response = rm.ordered_msg_response();

    // ASSERT EVERY MSG

    // 0 -> MSG SEND REQUEST, NO ASSERT NEED.

    // 1 -> SEND PACKET

    assert_eq!(
        msg_response[1].0,
        SubMsgType::SubMsg(SubMsg {
            id: 0,
            gas_limit: None,
            reply_on: ReplyOn::Never,
            msg: CosmosMsg::Ibc(IbcMsg::SendPacket {
                channel_id: LOCAL_CHANNEL.to_string(),
                timeout: gate_timeout(None),
                data: to_binary(&GatePacket::RequestPacket(Box::new(RequestsPacket {
                    from_chain: None,
                    to_chain: REMOTE_CHAIN.to_string(),
                    requests_infos: vec![GateRequestsInfo::new(
                        vec![GateRequest::SendMsg {
                            msg: msg_to_send.clone(),
                            to_contract: REMOTE_CONTRACT.to_string(),
                            send_native: send_native.clone(),
                        }],
                        LOCAL_CONTRACT.to_string(),
                        merge_fee_with_send_native(&fee, &send_native),
                        LOCAL_BASE_DENOM.to_string()
                    )
                    .unwrap()],
                    fee: halving_fee(&fee),
                    send_native: send_native.clone()
                })))
                .unwrap()
            })
        })
    );

    // 2 -> PACKET_RECEIVE

    assert_eq!(
        msg_response[2].0,
        SubMsgType::PacketReceive(IbcPacketReceiveMsg::new(
            IbcPacket::new(
                to_binary(&GatePacket::RequestPacket(Box::new(RequestsPacket {
                    requests_infos: vec![GateRequestsInfo::new(
                        vec![GateRequest::SendMsg {
                            msg: msg_to_send.clone(),
                            to_contract: REMOTE_CONTRACT.to_string(),
                            send_native: send_native.clone(),
                        }],
                        LOCAL_CONTRACT.to_string(),
                        merge_fee_with_send_native(&fee, &send_native),
                        LOCAL_BASE_DENOM.to_string()
                    )
                    .unwrap()],
                    fee: halving_fee(&fee),
                    send_native: send_native.clone(),
                    from_chain: None,
                    to_chain: REMOTE_CHAIN.to_string(),
                })))
                .unwrap(),
                IbcEndpoint {
                    port_id: get_wasm_port_id(LOCAL_GATE),
                    channel_id: LOCAL_CHANNEL.to_string(),
                },
                IbcEndpoint {
                    port_id: get_wasm_port_id(REMOTE_GATE),
                    channel_id: REMOTE_CHANNEL.to_string(),
                },
                0_u64,
                gate_timeout(None),
            ),
            Addr::unchecked(REMOTE_RELAYER),
        ))
    );

    // 3 -> PRIVATE EXECUTE

    assert_eq!(
        msg_response[3].0,
        SubMsgType::SubMsg(SubMsg {
            id: ReplyID::ExecuteRequest.repr(),
            gas_limit: None,
            reply_on: ReplyOn::Always,
            msg: CosmosMsg::Wasm(WasmMsg::Execute {
                contract_addr: REMOTE_GATE.to_string(),
                funds: vec![],
                msg: to_binary(&ExecuteMsg::PrivateRemoteExecuteRequests {
                    requests_infos: vec![GateRequestsInfo::new(
                        vec![GateRequest::SendMsg {
                            msg: msg_to_send.clone(),
                            to_contract: REMOTE_CONTRACT.to_string(),
                            send_native: send_native.clone(),
                        }],
                        LOCAL_CONTRACT.to_string(),
                        merge_fee_with_send_native(&fee, &send_native),
                        LOCAL_BASE_DENOM.to_string()
                    )
                    .unwrap()],
                    native_denom: None,
                    from_chain: LOCAL_CHAIN.to_string()
                })
                .unwrap(),
            })
        })
    );

    // 4 -> SEND MSG TO REMOTE CONTRACT WITH NATIVE

    assert_eq!(
        msg_response[4].0,
        SubMsgType::SubMsg(SubMsg {
            id: 0,
            gas_limit: None,
            reply_on: ReplyOn::Never,
            msg: CosmosMsg::Wasm(WasmMsg::Execute {
                contract_addr: REMOTE_CONTRACT.to_string(),
                msg: to_binary(&ReceiverExecuteMsg::ReceiveGateMsg(GateMsg::ReceivedMsg {
                    sender: LOCAL_CONTRACT.to_string(),
                    msg: msg_to_send
                }))
                .unwrap(),
                funds: vec![]
            })
        })
    );

    // 5 -> REPLY PRIVATE EXECUTE, EMPTY RESULT

    assert_eq!(
        msg_response[5].0,
        SubMsgType::Reply(Reply {
            id: ReplyID::ExecuteRequest.repr(),
            result: SubMsgResult::Ok(SubMsgResponse {
                events: vec![],
                data: None
            })
        })
    );

    // 6 -> ACK FIRED

    assert_eq!(
        msg_response[6].0,
        SubMsgType::GateAck(GateAck {
            coin: None,
            ack: GateAckType::EmptyResult
        })
    );

    if msg_response.len() != 7 {
        panic!("Some msgs unexpected, {:?}", msg_response)
    }
}

#[test]
fn interchain_query() {
    let mut manager = GatesManager::new();

    let remote_oracle = "remote_oracle".to_string();
    let remote_asset = "btc".to_string();

    let price = Decimal::from_str("3").unwrap();

    manager.set_price(false, price);

    let send_native = None;
    let fee = None;
    let callback_msg = Some(Binary::default());

    let msg = ExecuteMsg::SendRequests {
        requests: vec![GateRequest::Query {
            queries: vec![QueryRequest::Wasm(WasmQuery::Smart {
                contract_addr: remote_oracle.clone(),
                msg: to_binary(&QueryMsgOracle::Price {
                    asset: remote_asset.clone(),
                })
                .unwrap(),
            })],
            callback_msg: callback_msg.clone(),
        }],
        chain: REMOTE_CHAIN.to_string(),
        timeout: None,
    };

    let rm = manager.execute_all(
        true,
        msg,
        Addr::unchecked(LOCAL_CONTRACT),
        merge_fee_with_send_native(&fee, &send_native),
    );

    // ASSERT LAST MESSAGE IS THE CALLBACK WITH THE RESULT OF THE QUERIES

    assert_eq!(
        rm.ordered_msg_response().last().unwrap().0,
        SubMsgType::SubMsg(SubMsg {
            id: ReplyID::AckContract.repr(),
            gas_limit: None,
            reply_on: ReplyOn::Error,
            msg: CosmosMsg::Wasm(WasmMsg::Execute {
                contract_addr: LOCAL_CONTRACT.to_string(),
                funds: vec![],
                msg: to_binary(&ReceiverExecuteMsg::ReceiveGateMsg(
                    GateMsg::QueryResponse {
                        queries: vec![GateQueryResponse {
                            request: QueryRequest::Wasm(WasmQuery::Smart {
                                contract_addr: remote_oracle,
                                msg: to_binary(&QueryMsgOracle::Price {
                                    asset: remote_asset,
                                })
                                .unwrap(),
                            }),
                            response: to_binary(&price).unwrap()
                        }],
                        callback_msg
                    }
                ))
                .unwrap()
            })
        })
    )
}

#[test]
fn interchain_with_native() {
    let mut manager = GatesManager::new();

    let msg_to_send = to_binary("ok").unwrap();

    let transfer_channel = "channel-123".to_string();
    let dest_denom = "ibc/uosmo".to_string();
    let transfer_denom = "uomso".to_string();

    let middle_channel_1 = "channel-middle_1".to_string();
    let middle_channel_2 = "channel-middle_2".to_string();

    let middle_addr_1 = "addr_middle_1".to_string();
    let middle_addr_2 = "addr_middle_2".to_string();

    let timeout_send_native = Some(123_123_123_u64);

    let send_native = Some(SendNativeInfo {
        coin: Coin {
            denom: transfer_denom,
            amount: Uint128::from(100_u128),
        },
        path_middle_forward: vec![
            PacketPath {
                channel_id: middle_channel_1.clone(),
                address: middle_addr_1,
            },
            PacketPath {
                channel_id: middle_channel_2.clone(),
                address: middle_addr_2.clone(),
            },
        ],
        dest_denom: dest_denom.clone(),
        channel_id: transfer_channel.clone(),
        timeout: timeout_send_native,
    });

    let fee = Some(Coin {
        denom: LOCAL_BASE_DENOM.to_string(),
        amount: Uint128::from(100_u128),
    });

    let msg = ExecuteMsg::SendRequests {
        requests: vec![GateRequest::SendMsg {
            msg: msg_to_send.clone(),
            to_contract: REMOTE_CONTRACT.to_string(),
            send_native: send_native.clone(),
        }],
        chain: REMOTE_CHAIN.to_string(),
        timeout: None,
    };

    let rm = manager.execute_all(
        true,
        msg,
        Addr::unchecked(LOCAL_CONTRACT),
        merge_fee_with_send_native(&fee, &send_native),
    );

    // ASSERT NO ERROR RECEIVED

    assert_eq!(rm.unhandled_errors_as_vec(), vec![]);

    let msg_response = rm.ordered_msg_response();

    // ASSERT EVERY MSG

    // 0 -> MSG SEND REQUEST, NO ASSERT NEED.

    // 1 -> SEND PACKET

    assert_eq!(
        msg_response[1].0,
        SubMsgType::SubMsg(SubMsg {
            id: 0,
            gas_limit: None,
            reply_on: ReplyOn::Never,
            msg: CosmosMsg::Ibc(IbcMsg::SendPacket {
                channel_id: LOCAL_CHANNEL.to_string(),
                timeout: gate_timeout(None),
                data: to_binary(&GatePacket::RequestPacket(Box::new(RequestsPacket {
                    from_chain: None,
                    to_chain: REMOTE_CHAIN.to_string(),
                    requests_infos: vec![GateRequestsInfo::new(
                        vec![GateRequest::SendMsg {
                            msg: msg_to_send.clone(),
                            to_contract: REMOTE_CONTRACT.to_string(),
                            send_native: send_native.clone(),
                        }],
                        LOCAL_CONTRACT.to_string(),
                        merge_fee_with_send_native(&fee, &send_native),
                        LOCAL_BASE_DENOM.to_string()
                    )
                    .unwrap()],
                    fee: halving_fee(&fee),
                    send_native: send_native.clone()
                })))
                .unwrap()
            })
        })
    );

    // 2 -> PACKET_RECEIVE

    assert_eq!(
        msg_response[2].0,
        SubMsgType::PacketReceive(IbcPacketReceiveMsg::new(
            IbcPacket::new(
                to_binary(&GatePacket::RequestPacket(Box::new(RequestsPacket {
                    requests_infos: vec![GateRequestsInfo::new(
                        vec![GateRequest::SendMsg {
                            msg: msg_to_send.clone(),
                            to_contract: REMOTE_CONTRACT.to_string(),
                            send_native: send_native.clone(),
                        }],
                        LOCAL_CONTRACT.to_string(),
                        merge_fee_with_send_native(&fee, &send_native),
                        LOCAL_BASE_DENOM.to_string()
                    )
                    .unwrap()],
                    fee: halving_fee(&fee),
                    send_native: send_native.clone(),
                    from_chain: None,
                    to_chain: REMOTE_CHAIN.to_string(),
                })))
                .unwrap(),
                IbcEndpoint {
                    port_id: get_wasm_port_id(LOCAL_GATE),
                    channel_id: LOCAL_CHANNEL.to_string(),
                },
                IbcEndpoint {
                    port_id: get_wasm_port_id(REMOTE_GATE),
                    channel_id: REMOTE_CHANNEL.to_string(),
                },
                0_u64,
                gate_timeout(None),
            ),
            Addr::unchecked(REMOTE_RELAYER),
        ))
    );

    // 3 -> MINT VOUCHER

    assert_eq!(
        msg_response[3].0,
        SubMsgType::SubMsg(SubMsg {
            id: ReplyID::MintVoucher.repr(),
            gas_limit: None,
            reply_on: ReplyOn::Error,
            msg: CosmosMsg::Wasm(WasmMsg::Execute {
                contract_addr: REMOTE_VOUCHER_OF_LOCAL.to_string(),
                msg: to_binary(&Cw20ExecuteMsg::Mint {
                    recipient: REMOTE_RELAYER.to_string(),
                    amount: halving_fee(&fee).unwrap().amount
                })
                .unwrap(),
                funds: vec![]
            })
        })
    );

    // 4 -> ACK FIRED

    assert_eq!(
        msg_response[4].0,
        SubMsgType::GateAck(GateAck {
            coin: halving_fee(&fee),
            ack: GateAckType::NativeSendRequest {
                dest_key: PacketSavedKey {
                    sequence: 0,
                    channel: REMOTE_CHANNEL.to_string()
                },
                gate_packet: Box::new(RequestsPacket {
                    requests_infos: vec![GateRequestsInfo::new(
                        vec![GateRequest::SendMsg {
                            msg: msg_to_send.clone(),
                            to_contract: REMOTE_CONTRACT.to_string(),
                            send_native: send_native.clone(),
                        }],
                        LOCAL_CONTRACT.to_string(),
                        merge_fee_with_send_native(&fee, &send_native),
                        LOCAL_BASE_DENOM.to_string()
                    )
                    .unwrap()],
                    fee: halving_fee(&fee),
                    send_native: send_native.clone(),
                    from_chain: Some(LOCAL_CHAIN.to_string()),
                    to_chain: REMOTE_CHAIN.to_string(),
                })
            }
        })
    );

    // 5 -> MINT VOUCHER

    assert_eq!(
        msg_response[5].0,
        SubMsgType::SubMsg(SubMsg {
            id: ReplyID::MintVoucher.repr(),
            gas_limit: None,
            reply_on: ReplyOn::Error,
            msg: CosmosMsg::Wasm(WasmMsg::Execute {
                contract_addr: LOCAL_VOUCHER.to_string(),
                msg: to_binary(&Cw20ExecuteMsg::Mint {
                    recipient: LOCAL_RELAYER.to_string(),
                    amount: halving_fee(&fee).unwrap().amount
                })
                .unwrap(),
                funds: vec![]
            })
        })
    );

    // 6 -> REPLY OF MSG_TRANSFER (7) (IN REALITY WE FIRED THE PACKET BEFORE THE REPLY
    //      BUT SINCE THE EXECUTION ON REMOTE CHAIN HAPPENS ASYNC, WE HANLDE THE REPLY IN THE LOCAL CHAIN BEFORE)

    assert_eq!(
        msg_response[6].0,
        SubMsgType::Reply(Reply {
            id: ReplyID::SendIbcHookPacket.repr(),
            result: SubMsgResult::Ok(SubMsgResponse {
                events: vec![],
                data: Some(create_msg_transfer_reponse_encoded(0))
            })
        })
    );

    // 7 -> MSG TRANSFER

    let memo_field = if send_native.clone().unwrap().path_middle_forward.is_empty() {
        MemoField {
            forward: None,
            ibc_callback: Some(LOCAL_GATE.to_string()),
            wasm: Some(WasmField {
                contract: REMOTE_GATE.to_string(),
                msg: ExecuteMsg::IbcHook(IbcHookMsg::ExecutePendingRequest {
                    channel: REMOTE_CHANNEL.to_string(),
                    sequence: 0,
                }),
            }),
        }
    } else {
        MemoField {
            ibc_callback: Some(LOCAL_GATE.to_string()),
            wasm: None,
            forward: Some(ForwardField {
                receiver: middle_addr_2,
                port: "transfer".to_string(),
                channel: middle_channel_2,
                next: Some(Box::new(MemoField {
                    wasm: None,
                    ibc_callback: None,
                    forward: Some(ForwardField {
                        receiver: REMOTE_GATE.to_string(),
                        port: "transfer".to_string(),
                        channel: transfer_channel.clone(),
                        next: Some(Box::new(MemoField {
                            forward: None,
                            ibc_callback: None,
                            wasm: Some(WasmField {
                                contract: REMOTE_GATE.to_string(),
                                msg: ExecuteMsg::IbcHook(IbcHookMsg::ExecutePendingRequest {
                                    channel: REMOTE_CHANNEL.to_string(),
                                    sequence: 0,
                                }),
                            }),
                        })),
                    }),
                })),
            }),
        }
    };

    let msg_transfer = if send_native.clone().unwrap().path_middle_forward.is_empty() {
        MsgTransfer {
            source_port: "transfer".to_string(),
            source_channel: transfer_channel,
            token: Some(send_native.clone().unwrap().coin.into()),
            sender: LOCAL_GATE.to_string(),
            receiver: REMOTE_GATE.to_string(),
            timeout_height: None,
            timeout_timestamp: Some(
                gate_timeout(Some(timeout_send_native.unwrap_or(DEFAULT_TIMEOUT)))
                    .timestamp()
                    .unwrap()
                    .nanos(),
            ),
            memo: to_string_pretty(&memo_field).unwrap(),
        }
    } else {
        let first_path = send_native.clone().unwrap().path_middle_forward[0].clone();

        MsgTransfer {
            source_port: "transfer".to_string(),
            source_channel: first_path.channel_id.to_owned(),
            token: Some(send_native.clone().unwrap().coin.into()),
            sender: LOCAL_GATE.to_string(),
            receiver: first_path.address,
            timeout_height: None,
            timeout_timestamp: Some(
                gate_timeout(Some(timeout_send_native.unwrap_or(DEFAULT_TIMEOUT)))
                    .timestamp()
                    .unwrap()
                    .nanos(),
            ),
            memo: to_string_pretty(&memo_field).unwrap(),
        }
    };

    assert_eq!(
        msg_response[7].0,
        SubMsgType::SubMsg(SubMsg {
            id: ReplyID::SendIbcHookPacket.repr(),
            gas_limit: None,
            reply_on: ReplyOn::Always,
            msg: CosmosMsg::Stargate {
                type_url: "/ibc.applications.transfer.v1.MsgTransfer".to_string(),
                value: msg_transfer.to_binary()
            }
        })
    );

    // 8 -> IBC_HOOK

    assert_eq!(
        msg_response[8].0,
        SubMsgType::SubMsg(SubMsg {
            id: 0,
            gas_limit: None,
            reply_on: ReplyOn::Never,
            msg: CosmosMsg::Wasm(WasmMsg::Execute {
                contract_addr: REMOTE_GATE.to_string(),
                funds: vec![Coin {
                    denom: send_native.clone().unwrap().dest_denom,
                    amount: send_native.clone().unwrap().coin.amount
                }],
                msg: to_binary(&ExecuteMsg::IbcHook(IbcHookMsg::ExecutePendingRequest {
                    channel: REMOTE_CHANNEL.to_string(),
                    sequence: 0
                }))
                .unwrap()
            })
        })
    );

    // 9 -> PRIVATE EXECUTE

    assert_eq!(
        msg_response[9].0,
        SubMsgType::SubMsg(SubMsg {
            id: 0,
            gas_limit: None,
            reply_on: ReplyOn::Never,
            msg: CosmosMsg::Wasm(WasmMsg::Execute {
                contract_addr: REMOTE_GATE.to_string(),
                funds: vec![],
                msg: to_binary(&ExecuteMsg::PrivateRemoteExecuteRequests {
                    requests_infos: vec![GateRequestsInfo::new(
                        vec![GateRequest::SendMsg {
                            msg: msg_to_send,
                            to_contract: REMOTE_CONTRACT.to_string(),
                            send_native: send_native.clone(),
                        }],
                        LOCAL_CONTRACT.to_string(),
                        merge_fee_with_send_native(&fee, &send_native),
                        LOCAL_BASE_DENOM.to_string()
                    )
                    .unwrap()],
                    native_denom: Some(dest_denom),
                    from_chain: LOCAL_CHAIN.to_string()
                })
                .unwrap(),
            })
        })
    );

    // 10 -> SEND MSG TO REMOTE CONTRACT WITH NATIVE

    assert_eq!(
        msg_response[10].0,
        SubMsgType::SubMsg(SubMsg {
            id: 0,
            gas_limit: None,
            reply_on: ReplyOn::Never,
            msg: CosmosMsg::Wasm(WasmMsg::Execute {
                contract_addr: REMOTE_CONTRACT.to_string(),
                msg: to_binary(&ReceiverExecuteMsg::ReceiveGateMsg(GateMsg::ReceivedMsg {
                    sender: LOCAL_CONTRACT.to_string(),
                    msg: to_binary("ok").unwrap()
                }))
                .unwrap(),
                funds: vec![Coin {
                    denom: send_native.clone().unwrap().dest_denom,
                    amount: send_native.unwrap().coin.amount
                }]
            })
        })
    );

    // 11 -> IBC_CALLBACK: SUDO ON LOCAL CHAIN

    assert_eq!(
        msg_response[11].0,
        SubMsgType::Sudo(SudoMsg::IBCLifecycleComplete(
            IBCLifecycleComplete::IBCAck {
                channel: middle_channel_1,
                sequence: 0,
                ack: "".to_string(),
                success: true
            }
        ))
    );

    // At this point the process should be finished.
    // Assert unexpected msg

    if msg_response.len() != 12 {
        panic!("Some msgs unexpected, {:?}", msg_response)
    }
}

#[test]
fn interchain_collect_msgs() {
    let mut manager = GatesManager::new();

    // MOCK CUSTOM RESPONSE
    // The flow is:
    // - A collect msg is send to the gate;
    // - The gate forward the collect to the specified contract and a msg to itself that will be executed after.
    // - The mock contract that receive the collect trigger here two msgs from LOCAL CONTRACT (like a cw20-icg bridge request)
    // - The LOCAL CONTRACT send the request to the gate (2 times, one per msg)
    // - When the two msgs are arrived, the collect msgs is finished (no new msgs) so the private_send_collected_msgs is then fired

    let send_msg_trigger_100: Binary = to_binary(&"send_msg_100").unwrap();
    let send_msg_trigger_200: Binary = to_binary(&"send_msg_200").unwrap();

    let user = "user";

    let receiver_collect_contract = "receiver_collect_contract";

    let msg_forwarded = to_binary(&"msg_forwarded").unwrap();

    let msg_collect = to_binary(&ReceiverExecuteMsg::ReceiveGateMsg(
        GateMsg::CollectRequests {
            sender: Addr::unchecked(user),
            msg: msg_forwarded.clone(),
        },
    ))
    .unwrap();

    let response = ResponseType::Response(Response::new().add_messages(vec![
        CosmosMsg::Wasm(WasmMsg::Execute {
            contract_addr: LOCAL_CONTRACT.to_string(),
            msg: send_msg_trigger_100.clone(),
            funds: vec![],
        }),
        CosmosMsg::Wasm(WasmMsg::Execute {
            contract_addr: LOCAL_CONTRACT.to_string(),
            msg: send_msg_trigger_200.clone(),
            funds: vec![],
        }),
    ]));

    manager.set_non_gate_response(receiver_collect_contract.to_string(), msg_collect, response);

    // HANDLE THE send_msg_trigger_100 / send_msg_trigger_200 for the LOCAL CONTRACT

    let msg_ok = to_binary("ok").unwrap();

    let response = ResponseType::Response(
        Response::new().add_message(CosmosMsg::Wasm(WasmMsg::Execute {
            contract_addr: LOCAL_GATE.to_string(),
            msg: to_binary(&ExecuteMsg::SendRequests {
                requests: vec![GateRequest::SendMsg {
                    msg: msg_ok.clone(),
                    to_contract: REMOTE_CONTRACT.to_string(),
                    send_native: None,
                }],
                chain: REMOTE_CHAIN.to_string(),
                timeout: None,
            })
            .unwrap(),
            funds: vec![Coin {
                denom: LOCAL_BASE_DENOM.to_string(),
                amount: Uint128::from(100_u128),
            }],
        })),
    );

    manager.set_non_gate_response(LOCAL_CONTRACT.to_string(), send_msg_trigger_100, response);

    let response = ResponseType::Response(
        Response::new().add_message(CosmosMsg::Wasm(WasmMsg::Execute {
            contract_addr: LOCAL_GATE.to_string(),
            msg: to_binary(&ExecuteMsg::SendRequests {
                requests: vec![GateRequest::SendMsg {
                    msg: msg_ok.clone(),
                    to_contract: REMOTE_CONTRACT.to_string(),
                    send_native: None,
                }],
                chain: REMOTE_CHAIN.to_string(),
                timeout: None,
            })
            .unwrap(),
            funds: vec![Coin {
                denom: LOCAL_BASE_DENOM.to_string(),
                amount: Uint128::from(200_u128),
            }],
        })),
    );

    manager.set_non_gate_response(LOCAL_CONTRACT.to_string(), send_msg_trigger_200, response);

    let rm = manager.execute_all(
        true,
        ExecuteMsg::CollectRequests {
            to_contract: Addr::unchecked(receiver_collect_contract),
            msg: msg_forwarded,
        },
        Addr::unchecked(user),
        vec![],
    );

    // PARTIAL ASSERT

    // 9 -> MINT VOUCHER

    let msgs = rm.ordered_msg_response();

    assert_eq!(
        msgs[9].0,
        SubMsgType::SubMsg(SubMsg {
            id: ReplyID::MintVoucher.repr(),
            gas_limit: None,
            reply_on: ReplyOn::Error,
            msg: CosmosMsg::Wasm(WasmMsg::Execute {
                contract_addr: REMOTE_VOUCHER_OF_LOCAL.to_string(),
                msg: to_binary(&Cw20ExecuteMsg::Mint {
                    recipient: REMOTE_RELAYER.to_string(),
                    amount: Uint128::from(150_u128)
                })
                .unwrap(),
                funds: vec![]
            })
        })
    );

    // 11 -> first_msg_delivered

    assert_eq!(
        msgs[11].0,
        SubMsgType::SubMsg(SubMsg {
            id: 0,
            gas_limit: None,
            reply_on: ReplyOn::Never,
            msg: CosmosMsg::Wasm(WasmMsg::Execute {
                contract_addr: REMOTE_CONTRACT.to_string(),
                msg: to_binary(&ReceiverExecuteMsg::ReceiveGateMsg(GateMsg::ReceivedMsg {
                    sender: LOCAL_CONTRACT.to_string(),
                    msg: msg_ok.clone()
                }))
                .unwrap(),
                funds: vec![]
            })
        })
    );

    assert_eq!(
        msgs[12].0,
        SubMsgType::SubMsg(SubMsg {
            id: 0,
            gas_limit: None,
            reply_on: ReplyOn::Never,
            msg: CosmosMsg::Wasm(WasmMsg::Execute {
                contract_addr: REMOTE_CONTRACT.to_string(),
                msg: to_binary(&ReceiverExecuteMsg::ReceiveGateMsg(GateMsg::ReceivedMsg {
                    sender: LOCAL_CONTRACT.to_string(),
                    msg: msg_ok
                }))
                .unwrap(),
                funds: vec![]
            })
        })
    );
}

#[test]
fn interchain_errors() {
    // Double native different dest denom

    let mut manager = GatesManager::new();

    let send_native_1 = Some(SendNativeInfo {
        coin: Coin {
            denom: "uosmo".to_string(),
            amount: Uint128::from(100_u128),
        },
        path_middle_forward: vec![],
        dest_denom: "ibc/uosmo".to_string(),
        channel_id: "channel-123".to_string(),
        timeout: None,
    });

    let send_native_2 = Some(SendNativeInfo {
        coin: Coin {
            denom: "uosmo".to_string(),
            amount: Uint128::from(100_u128),
        },
        path_middle_forward: vec![],
        dest_denom: "ibc/uosmo_wrong".to_string(),
        channel_id: "channel-123".to_string(),
        timeout: None,
    });

    let msg = ExecuteMsg::SendRequests {
        requests: vec![
            GateRequest::SendMsg {
                msg: Binary::default(),
                to_contract: REMOTE_CONTRACT.to_string(),
                send_native: send_native_1,
            },
            GateRequest::SendMsg {
                msg: Binary::default(),
                to_contract: REMOTE_CONTRACT.to_string(),
                send_native: send_native_2,
            },
        ],
        chain: REMOTE_CHAIN.to_string(),
        timeout: None,
    };

    let rm = manager.execute_all(
        true,
        msg,
        Addr::unchecked(LOCAL_CONTRACT),
        vec![Coin {
            denom: "uosmo".to_string(),
            amount: Uint128::from(200_u128),
        }],
    );

    assert_eq!(
        rm.unhandled_errors_as_vec(),
        vec![ResponseType::Err(
            "Generic error: Multiple dest_denom detected".to_string()
        )]
    );

    // Permission fails

    let mut manager = GatesManager::new();

    let msg = ExecuteMsg::SendRequests {
        requests: vec![GateRequest::SendMsg {
            msg: Binary::default(),
            to_contract: REMOTE_CONTRACT_HACK.to_string(),
            send_native: None,
        }],
        chain: REMOTE_CHAIN.to_string(),
        timeout: None,
    };

    let rm = manager.execute_all(true, msg, Addr::unchecked(LOCAL_CONTRACT), vec![]);

    // Assert the permission. This is a handled error since is handled on reply

    assert_eq!(
        rm.handled_errors,
        vec![ResponseType::Err(
            "Permissions for remote_contract_hack has never been set".to_string()
        )]
    )
}

#[test]
fn interchain_fails() {
    // DOUBLE MSG NO NATIVE FIRST PASS SECOND FAILS, ALL NEED TO BE REVERT

    let mut manager = GatesManager::new();

    let msg_to_send_ok = to_binary("ok").unwrap();

    let msg_to_send_fail = to_binary("fail").unwrap();

    let msg = ExecuteMsg::SendRequests {
        requests: vec![
            GateRequest::SendMsg {
                msg: msg_to_send_ok.clone(),
                to_contract: REMOTE_CONTRACT.to_string(),
                send_native: None,
            },
            GateRequest::SendMsg {
                msg: msg_to_send_fail.clone(),
                to_contract: REMOTE_CONTRACT.to_string(),
                send_native: None,
            },
        ],
        chain: REMOTE_CHAIN.to_string(),
        timeout: None,
    };

    let rm = manager.execute_all(true, msg, Addr::unchecked(LOCAL_CONTRACT), vec![]);

    // PARTIAL ASSERT

    // CHECK EXECUTION HAS BEEN SENT AS SUB MSG WITH REPLY

    let msgs = rm.ordered_msg_response();

    if let SubMsgType::SubMsg(SubMsg { id, reply_on, .. }) = &msgs[3].0 {
        assert_eq!(id.to_owned(), ReplyID::ExecuteRequest.repr());
        assert_eq!(reply_on.to_owned(), ReplyOn::Always);
    } else {
        panic!("Should be SubMsgType::SubMsg(SubMsg...")
    }

    // CHECK IF REVERT MSG HASS BEEN SENT

    assert_eq!(
        msgs[msgs.len() - 3].0,
        SubMsgType::SubMsg(SubMsg {
            id: ReplyID::AckContract.repr(),
            gas_limit: Some(MAX_GAS_AMOUNT_PER_REVERT),
            reply_on: ReplyOn::Error,
            msg: CosmosMsg::Wasm(WasmMsg::Execute {
                contract_addr: LOCAL_CONTRACT.to_string(),
                funds: vec![],
                msg: to_binary(&ReceiverExecuteMsg::ReceiveGateMsg(
                    GateMsg::RequestFailed {
                        request: GateRequest::SendMsg {
                            msg: msg_to_send_ok,
                            to_contract: REMOTE_CONTRACT.to_string(),
                            send_native: None,
                        }
                    }
                ))
                .unwrap()
            })
        })
    );

    assert_eq!(
        msgs[msgs.len() - 2].0,
        SubMsgType::SubMsg(SubMsg {
            id: ReplyID::AckContract.repr(),
            gas_limit: Some(MAX_GAS_AMOUNT_PER_REVERT),
            reply_on: ReplyOn::Error,
            msg: CosmosMsg::Wasm(WasmMsg::Execute {
                contract_addr: LOCAL_CONTRACT.to_string(),
                funds: vec![],
                msg: to_binary(&ReceiverExecuteMsg::ReceiveGateMsg(
                    GateMsg::RequestFailed {
                        request: GateRequest::SendMsg {
                            msg: msg_to_send_fail,
                            to_contract: REMOTE_CONTRACT.to_string(),
                            send_native: None,
                        }
                    }
                ))
                .unwrap()
            })
        })
    );
}

#[test]
fn interchain_fails_with_native() {
    let transfer_channel = "channel-123".to_string();
    let dest_denom = "ibc/uosmo".to_string();
    let transfer_denom = "uomso".to_string();

    let msg_to_send_ok = to_binary("ok").unwrap();

    let msg_to_send_fail = to_binary("fail").unwrap();

    let send_native = Some(SendNativeInfo {
        coin: Coin {
            denom: transfer_denom,
            amount: Uint128::from(100_u128),
        },
        path_middle_forward: vec![],
        dest_denom,
        channel_id: transfer_channel.clone(),
        timeout: None,
    });

    let msg = ExecuteMsg::SendRequests {
        requests: vec![
            GateRequest::SendMsg {
                msg: msg_to_send_ok.clone(),
                to_contract: REMOTE_CONTRACT.to_string(),
                send_native: send_native.clone(),
            },
            GateRequest::SendMsg {
                msg: msg_to_send_fail.clone(),
                to_contract: REMOTE_CONTRACT.to_string(),
                send_native: None,
            },
        ],
        chain: REMOTE_CHAIN.to_string(),
        timeout: None,
    };

    let mut manager = GatesManager::new();

    let rm = manager.execute_all(true, msg, Addr::unchecked(LOCAL_CONTRACT), vec![]);

    // PARTIAL ASSERT

    // CHECK EXECUTION HAS BEEN SENT AS SUB MSG WITHOUT REPLY (IBC HOOK ITSELF HANLDE THE REPLY WITH THE CALLBACK, IT'S RIGHT TO FAILS THE EXECUTION)

    let msgs: Vec<(SubMsgType, ResponseType)> = rm.ordered_msg_response();

    if let SubMsgType::SubMsg(SubMsg { id, reply_on, .. }) = &msgs[7].0 {
        assert_eq!(id.to_owned(), 0);
        assert_eq!(reply_on.to_owned(), ReplyOn::Never);
    } else {
        panic!("Should be SubMsgType::SubMsg(SubMsg...")
    }

    // CHECK IF A PACKET HAS BEEN SENT TO THE DEST CHAIN TO REMOVE THE STORED PACKET

    assert_eq!(
        msgs[msgs.len() - 6].0,
        SubMsgType::SubMsg(SubMsg {
            id: 0,
            gas_limit: None,
            reply_on: ReplyOn::Never,
            msg: CosmosMsg::Ibc(IbcMsg::SendPacket {
                channel_id: LOCAL_CHANNEL.to_string(),
                timeout: gate_timeout(None),
                data: to_binary(&GatePacket::RemoveStoredPacket {
                    dest_key: PacketSavedKey {
                        channel: REMOTE_CHANNEL.to_string(),
                        sequence: 0
                    },
                    src_key: PacketSavedKey {
                        channel: transfer_channel.to_string(),
                        sequence: 0
                    }
                })
                .unwrap()
            })
        })
    );

    // CHECK IF IN THE ACK IS SETTED THAT THE PACKET HAS BEEN REMOVED FROM THE STATE

    assert_eq!(
        msgs[msgs.len() - 4].0,
        SubMsgType::GateAck(GateAck {
            coin: None,
            ack: GateAckType::RemoveStoredPacket {
                src_key: PacketSavedKey {
                    channel: transfer_channel,
                    sequence: 0
                },
                removed: true
            }
        })
    );

    // CHECK IF REVERT MSG HAS BEEN SENT WITH NATIVE TOKEN ON FIRST REQUEST

    assert_eq!(
        msgs[msgs.len() - 3].0,
        SubMsgType::SubMsg(SubMsg {
            id: ReplyID::AckContract.repr(),
            gas_limit: Some(MAX_GAS_AMOUNT_PER_REVERT),
            reply_on: ReplyOn::Error,
            msg: CosmosMsg::Wasm(WasmMsg::Execute {
                contract_addr: LOCAL_CONTRACT.to_string(),
                funds: vec![send_native.clone().unwrap().coin],
                msg: to_binary(&ReceiverExecuteMsg::ReceiveGateMsg(
                    GateMsg::RequestFailed {
                        request: GateRequest::SendMsg {
                            msg: msg_to_send_ok,
                            to_contract: REMOTE_CONTRACT.to_string(),
                            send_native,
                        }
                    }
                ))
                .unwrap()
            })
        })
    );

    assert_eq!(
        msgs[msgs.len() - 2].0,
        SubMsgType::SubMsg(SubMsg {
            id: ReplyID::AckContract.repr(),
            gas_limit: Some(MAX_GAS_AMOUNT_PER_REVERT),
            reply_on: ReplyOn::Error,
            msg: CosmosMsg::Wasm(WasmMsg::Execute {
                contract_addr: LOCAL_CONTRACT.to_string(),
                funds: vec![],
                msg: to_binary(&ReceiverExecuteMsg::ReceiveGateMsg(
                    GateMsg::RequestFailed {
                        request: GateRequest::SendMsg {
                            msg: msg_to_send_fail,
                            to_contract: REMOTE_CONTRACT.to_string(),
                            send_native: None,
                        }
                    }
                ))
                .unwrap()
            })
        })
    );
}
