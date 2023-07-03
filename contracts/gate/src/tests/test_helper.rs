use std::{
    collections::{HashMap, VecDeque},
    fmt::Display,
    str::FromStr,
};

use cosmwasm_schema::cw_serde;
use cosmwasm_std::{
    from_binary,
    testing::{mock_env, mock_info, MockApi},
    to_binary, Addr, Attribute, Binary, BlockInfo, Coin, CosmosMsg, Decimal, DepsMut, Empty, Env,
    Event, IbcAcknowledgement, IbcBasicResponse, IbcChannel, IbcChannelConnectMsg, IbcEndpoint,
    IbcMsg, IbcOrder, IbcPacket, IbcPacketAckMsg, IbcPacketReceiveMsg, IbcReceiveResponse,
    IbcTimeout, MemoryStorage, MessageInfo, Never, OwnedDeps, Reply, ReplyOn, Response, StdResult,
    Storage, SubMsg, SubMsgResponse, SubMsgResult, Timestamp, Uint128, WasmMsg,
};
use gate_pkg::{
    ExecuteMsg, GateMsg, GateRequest, IbcHookMsg, Permission, ReceiverExecuteMsg, SendNativeInfo,
};
use prost::{encoding::bool, Message};
use protobuf::Message as ProtoMsg;
use schemars::_serde_json::{from_str, to_string_pretty};

use crate::{
    contract::{execute, instantiate, reply, sudo},
    error::ContractError,
    extra::{
        msg_transfer::{MsgTransfer, MsgTransferResponse},
        response::MsgInstantiateContractResponse,
    },
    ibc::{ibc_channel_connect, ibc_packet_ack, ibc_packet_receive},
    state::{
        GateAck, IBCLifecycleComplete, InstantiateMsg, MemoField, ReplyID, SudoMsg, WasmField,
        ICG_VERSION, PENDING_PACKETS,
    },
};

use super::mock_querier::{custom_mock_dependencies, WasmMockQuerier};

pub const CONTROLLER: &str = "controller0000";
pub const OWNER: &str = "owner0000";

pub const LOCAL_GATE: &str = "local_gate";
pub const REMOTE_GATE: &str = "remote_gate";
pub const _REMOTE_GATE_HACK: &str = "remote_gate_hack";

pub const LOCAL_CONTRACT: &str = "local_contract_1";
pub const REMOTE_CONTRACT: &str = "remote_contract_1";
pub const REMOTE_CONTRACT_HACK: &str = "remote_contract_hack";

pub const LOCAL_CHAIN: &str = "terra";
pub const REMOTE_CHAIN: &str = "injective";

pub const LOCAL_CHANNEL: &str = "local_channel_1";
pub const REMOTE_CHANNEL: &str = "remote_channel_1";
pub const CONNECTION: &str = "connection";

pub const LOCAL_RELAYER: &str = "local_relayer";
pub const REMOTE_RELAYER: &str = "remote_relayer";

pub const LOCAL_VOUCHER: &str = "uluna_voucher";
pub const LOCAL_VOUCHER_OF_REMOTE: &str = "inj_voucher";

pub const REMOTE_VOUCHER: &str = "inj_voucher";
pub const REMOTE_VOUCHER_OF_LOCAL: &str = "uluna_voucher";

pub const LOCAL_BASE_DENOM: &str = "uluna";
pub const REMOTE_BASE_DENOM: &str = "inj";

pub const MAX_GAS_AMOUNT_PER_REVERT: u64 = 1_000_000;

pub const DEFAULT_TIMEOUT: u64 = 100;

pub const DEFAULT_HEIGHT: u64 = 100;

pub const DEFAULT_TIMESTAMP: u64 = 1_000_000_000;

pub fn initialize_gate() -> StdResult<(OwnedDeps<MemoryStorage, MockApi, WasmMockQuerier>, Env)> {
    let mut deps = custom_mock_dependencies();
    let mut env = mock_env();
    env.block = BlockInfo {
        height: DEFAULT_HEIGHT,
        time: Timestamp::from_seconds(DEFAULT_TIMESTAMP),
        chain_id: LOCAL_CHAIN.to_string(),
    };
    env.contract.address = Addr::unchecked(LOCAL_GATE);

    let local_port_id = get_wasm_port_id(LOCAL_GATE);

    let remote_port_id = get_wasm_port_id(REMOTE_GATE);

    env.contract.address = Addr::unchecked("local_gate");

    // Initialize
    let msg = InstantiateMsg {
        controller: Addr::unchecked(CONTROLLER),
        default_timeout: DEFAULT_TIMEOUT,
        default_gas_limit: None,
        cw20_icg_code_id: 1,
        base_denom: LOCAL_BASE_DENOM.to_string(),
        max_gas_amount_per_revert: MAX_GAS_AMOUNT_PER_REVERT,
    };

    let info: MessageInfo = mock_info(OWNER, &[]);

    let res = instantiate(deps.as_mut(), env.clone(), info, msg);

    if res.is_err() {
        panic!("Should return Ok, instead returned: {}", res.unwrap_err())
    }

    // Store voucher contract
    store_voucher_contract(deps.as_mut(), LOCAL_VOUCHER.to_string());

    // Open channel
    let msg = IbcChannelConnectMsg::OpenAck {
        channel: IbcChannel::new(
            IbcEndpoint {
                port_id: local_port_id,
                channel_id: LOCAL_CHANNEL.to_string(),
            },
            IbcEndpoint {
                port_id: remote_port_id,
                channel_id: REMOTE_CHANNEL.to_string(),
            },
            IbcOrder::Unordered,
            ICG_VERSION,
            CONNECTION.to_string(),
        ),

        counterparty_version: "icg-1".to_string(),
    };

    let res = ibc_channel_connect(deps.as_mut(), env.clone(), msg);

    if res.is_err() {
        panic!("Should return Ok, instead returned: {}", res.unwrap_err())
    }

    // Register channel
    let msg = ExecuteMsg::RegisterChainAndChannel {
        chain: REMOTE_CHAIN.to_string(),
        src_channel: LOCAL_CHANNEL.to_string(),
        base_denom: REMOTE_BASE_DENOM.to_string(),
    };

    let res = execute(deps.as_mut(), env.clone(), mock_info(CONTROLLER, &[]), msg);

    if res.is_err() {
        panic!("Should return Ok, instead returned: {}", res.unwrap_err())
    }

    // Store voucher contract
    store_voucher_contract(deps.as_mut(), LOCAL_VOUCHER_OF_REMOTE.to_string());

    // Set permission
    let msg = ExecuteMsg::SetPermission {
        permission: Permission::Permissioned {
            addresses: vec![REMOTE_CONTRACT.to_string()],
        },
        chain: REMOTE_CHAIN.to_string(),
    };

    let res = execute(
        deps.as_mut(),
        env.clone(),
        mock_info(LOCAL_CONTRACT, &[]),
        msg,
    );

    if res.is_err() {
        panic!("Should return Ok, instead returned: {}", res.unwrap_err())
    }

    Ok((deps, env))
}

pub fn store_voucher_contract(deps: DepsMut, contract_addr: String) {
    let data = MsgInstantiateContractResponse {
        contract_address: contract_addr,
        data: vec![],
        unknown_fields: Default::default(),
        cached_size: Default::default(),
    }
    .write_to_bytes()
    .unwrap();

    let reply_msg = Reply {
        id: ReplyID::InitToken.repr(),
        result: SubMsgResult::Ok(SubMsgResponse {
            events: vec![],
            data: Some(data.into()),
        }),
    };

    let _res = reply(deps, mock_env(), reply_msg).unwrap();
}

pub fn get_wasm_port_id(contract: &str) -> String {
    let mut port_id = "wasm.".to_string();
    port_id.push_str(contract);
    port_id
}

pub fn gate_timeout(with_override: Option<u64>) -> IbcTimeout {
    IbcTimeout::with_timestamp(Timestamp::from_seconds(
        with_override.unwrap_or(DEFAULT_TIMEOUT) + DEFAULT_TIMESTAMP,
    ))
}

pub fn halving_fee(fee: &Option<Coin>) -> Option<Coin> {
    fee.as_ref().map(|val| Coin {
        denom: val.denom.clone(),
        amount: val.amount / Uint128::from(2_u128),
    })
}

pub fn create_msg_transfer_reponse_encoded(sequence: u64) -> Binary {
    let mut buffer: Vec<u8> = vec![];
    MsgTransferResponse { sequence }
        .encode(&mut buffer)
        .unwrap();
    Binary::from(buffer)
}

// --- MANAGER ---

fn clone_storage(memory_storage: &MemoryStorage) -> MemoryStorage {
    let mut res = MemoryStorage::new();

    for (k, v) in memory_storage.range(None, None, cosmwasm_std::Order::Descending) {
        res.set(&k, &v)
    }
    res
}

pub struct GatesManager {
    local_deps: OwnedDeps<MemoryStorage, MockApi, WasmMockQuerier>,
    local_env: Env,
    remote_deps: OwnedDeps<MemoryStorage, MockApi, WasmMockQuerier>,
    remote_env: Env,
    sequences: HashMap<bool, HashMap<String, u64>>,
    ibc_packet: Option<IbcPacket>,
    non_gate_response: HashMap<(String, Binary), ResponseType>,
}

impl GatesManager {
    pub fn new() -> GatesManager {
        let (local_deps, local_env) = GatesManager::initialize_gate(true).unwrap();
        let (remote_deps, remote_env) = GatesManager::initialize_gate(false).unwrap();

        let mut map: HashMap<bool, HashMap<String, u64>> = HashMap::new();

        map.insert(true, HashMap::new());
        map.insert(false, HashMap::new());

        let mut manager = GatesManager {
            local_deps,
            local_env,
            remote_deps,
            remote_env,
            sequences: map,
            ibc_packet: None,
            non_gate_response: HashMap::new(),
        };

        // Set some default response for fake contracts

        manager.set_non_gate_response(
            REMOTE_CONTRACT.to_string(),
            to_binary(&ReceiverExecuteMsg::ReceiveGateMsg(GateMsg::ReceivedMsg {
                sender: LOCAL_CONTRACT.to_string(),
                msg: to_binary(&"ok").unwrap(),
            }))
            .unwrap(),
            ResponseType::Response(
                Response::new().add_attribute("action_mock_contract", "msg_received"),
            ),
        );

        manager.set_non_gate_response(
            REMOTE_CONTRACT.to_string(),
            to_binary(&ReceiverExecuteMsg::ReceiveGateMsg(GateMsg::ReceivedMsg {
                sender: LOCAL_CONTRACT.to_string(),
                msg: to_binary(&"fail").unwrap(),
            }))
            .unwrap(),
            ResponseType::Err("Execution on remote contract fails".to_string()),
        );

        // Set also some default response in case execution fails to test also reply on revert

        manager.set_non_gate_response(
            LOCAL_CONTRACT.to_string(),
            to_binary(&ReceiverExecuteMsg::ReceiveGateMsg(
                GateMsg::RequestFailed {
                    request: GateRequest::SendMsg {
                        msg: to_binary(&"ok").unwrap(),
                        to_contract: REMOTE_CONTRACT.to_string(),
                        send_native: None,
                    },
                },
            ))
            .unwrap(),
            ResponseType::Response(
                Response::new().add_attribute("action_mock_contract", "corrected_revert"),
            ),
        );

        manager.set_non_gate_response(
            LOCAL_CONTRACT.to_string(),
            to_binary(&ReceiverExecuteMsg::ReceiveGateMsg(
                GateMsg::RequestFailed {
                    request: GateRequest::SendMsg {
                        msg: to_binary(&"fail").unwrap(),
                        to_contract: REMOTE_CONTRACT.to_string(),
                        send_native: None,
                    },
                },
            ))
            .unwrap(),
            ResponseType::Err("Revert on local contract fails".to_string()),
        );

        manager
    }

    pub fn set_non_gate_response(
        &mut self,
        contract_addr: String,
        msg: Binary,
        response: ResponseType,
    ) {
        self.non_gate_response
            .insert((contract_addr, msg), response);
    }

    pub fn execute_all(
        &mut self,
        local: bool,
        msg: ExecuteMsg,
        sender: Addr,
        funds: Vec<Coin>,
    ) -> ResponseManager {
        let sub_msg = SubMsg::new(CosmosMsg::Wasm(WasmMsg::Execute {
            contract_addr: get_gate_address(local).to_string(),
            msg: to_binary(&msg).unwrap(),
            funds,
        }));

        self.handle_msg(sender.to_string(), SubMsgType::SubMsg(sub_msg), local)
    }

    fn handle_msg(
        &mut self,
        sender: String,
        sub_msg_type: SubMsgType,
        local: bool,
    ) -> ResponseManager {
        let mut next_local = local;

        let next_sender: String;

        match sub_msg_type.clone() {
            SubMsgType::SubMsg(sub_msg) => {
                match sub_msg.clone().msg {
                    // Ibc packet, change chain
                    CosmosMsg::Ibc(msg) => {
                        next_local = !local;
                        let response = self.handle_ibc_sub_msg(msg, next_local);
                        next_sender = "chain_output_packet".to_string();

                        let msg_response = MsgResponse::new(sender, sub_msg_type, response, local);

                        self.handle_response(msg_response, next_sender, next_local)
                    }
                    CosmosMsg::Wasm(msg) => {
                        let (response, next) = self.handle_wasm(sender.clone(), msg, local);
                        next_sender = next;

                        let msg_response =
                            MsgResponse::new(sender.clone(), sub_msg_type, response, local);

                        let mut manager =
                            self.handle_response(msg_response, next_sender, next_local);

                        let reply = match manager.next_unhandled_error() {
                            None => match sub_msg.reply_on {
                                ReplyOn::Always | ReplyOn::Success => Some(Reply {
                                    id: sub_msg.id,
                                    result: SubMsgResult::Ok(SubMsgResponse {
                                        events: manager.events(local),
                                        data: manager.data(local),
                                    }),
                                }),
                                _ => None,
                            },
                            Some(err) => match sub_msg.reply_on {
                                ReplyOn::Always | ReplyOn::Error => {
                                    manager.pop_next_unhandled_error();
                                    Some(Reply {
                                        id: sub_msg.id,
                                        result: SubMsgResult::Err(err.to_string()),
                                    })
                                }
                                _ => return manager,
                            },
                        };

                        // Execute reply
                        if let Some(reply) = reply {
                            let next_manager =
                                self.handle_msg(sender, SubMsgType::Reply(reply), local);
                            manager.merge_same_lvl(next_manager);
                        }

                        manager
                    }

                    // Ics20 packet, change chain
                    CosmosMsg::Stargate { type_url, value } => {
                        next_local = !local;
                        let (response, channel, sequence) =
                            self.handle_stargate(type_url, value, local);
                        next_sender = "chain_output_packet_transfer".to_string();

                        // Manual trigger reply here since this is not happend atomically

                        let reply = Reply {
                            id: sub_msg.id,
                            result: SubMsgResult::Ok(SubMsgResponse {
                                events: vec![],
                                data: Some(create_msg_transfer_reponse_encoded(sequence)),
                            }),
                        };

                        let mut reply_manager =
                            self.handle_msg(sender.clone(), SubMsgType::Reply(reply), local);

                        // Execute the ibc_hook

                        let msg_response = MsgResponse::new(sender, sub_msg_type, response, local);

                        let mut manager =
                            self.handle_response(msg_response, next_sender, next_local);

                        // Ibc ack

                        let sudo_msg = match manager.next_unhandled_error() {
                            Some(err) => {
                                SudoMsg::IBCLifecycleComplete(IBCLifecycleComplete::IBCAck {
                                    channel,
                                    sequence,
                                    ack: err.to_string(),
                                    success: false,
                                })
                            }
                            None => SudoMsg::IBCLifecycleComplete(IBCLifecycleComplete::IBCAck {
                                channel,
                                sequence,
                                ack: "".to_string(),
                                success: true,
                            }),
                        };

                        manager = reply_manager.merge_same_lvl(manager);

                        // Exeucte sudo
                        let sudo_manager = self.handle_msg(
                            "chain_sudo_ack".to_string(),
                            SubMsgType::Sudo(sudo_msg),
                            local,
                        );
                        manager.merge_same_lvl(sudo_manager);

                        manager
                    }
                    _ => panic!("CosmosMsg type not handled {:?}", sub_msg.msg),
                }
            }

            SubMsgType::Reply(reply) => {
                let next_response = self.handle_reply(reply, local);
                self.handle_response(
                    MsgResponse::new(sender.clone(), sub_msg_type, next_response, local),
                    sender,
                    local,
                )
            }

            SubMsgType::Sudo(sudo_msg) => {
                let next_response = self.handle_sudo(sudo_msg, local);
                self.handle_response(
                    MsgResponse::new(sender.clone(), sub_msg_type, next_response, local),
                    sender,
                    local,
                )
            }

            SubMsgType::GateAck(ack) => {
                let response = self.handle_ack(ack, local);

                let msg_response = MsgResponse::new(sender.clone(), sub_msg_type, response, local);

                self.handle_response(msg_response, sender, local)
            }

            SubMsgType::PacketReceive(packet) => {
                let (response, next_sender) = self.handle_packet_receive(packet, local);

                let msg_response = MsgResponse::new(sender, sub_msg_type, response, local);

                self.handle_response(msg_response, next_sender, local)
            }
        }
    }

    fn handle_response(
        &mut self,
        msg_response: MsgResponse,
        next_sender: String,
        next_local: bool,
    ) -> ResponseManager {
        let mut manager = ResponseManager::new(msg_response.clone());

        let c_local = clone_storage(&self.local_deps.storage);
        let c_remote = clone_storage(&self.remote_deps.storage);

        for sub_msg in msg_response.response.msgs() {
            let next_manager = self.handle_msg(next_sender.clone(), sub_msg, next_local);
            manager.merge_next_lvl(next_manager);
            if manager.next_unhandled_error().is_some() {
                self.local_deps.storage = c_local;
                self.remote_deps.storage = c_remote;

                return manager;
            }
        }

        // The response has some data. Check if this data is an ack
        if let Some(data) = manager.data(msg_response.local) {
            if let Ok(ack) = from_binary::<GateAck>(&data) {
                let mut next_manager = self.handle_msg(
                    "chain_moudle".to_string(),
                    SubMsgType::GateAck(ack),
                    !next_local,
                );

                manager
                    .msg_responses
                    .first_mut()
                    .unwrap()
                    .next
                    .append(&mut next_manager.msg_responses);

                manager
                    .unhandled_errors
                    .append(&mut next_manager.unhandled_errors);

                if manager.next_unhandled_error().is_some() {
                    return manager;
                }
            }
        }

        manager
    }

    // --- WASM ----

    fn handle_wasm(
        &mut self,
        sender: String,
        execute_msg: WasmMsg,
        local: bool,
    ) -> (ResponseType, String) {
        match execute_msg {
            WasmMsg::Execute {
                contract_addr,
                msg,
                funds,
            } => self.handle_wasm_execute(sender, contract_addr, msg, funds, local),
            _ => panic!("CosmosMsg type not handled {:?}", execute_msg),
        }
    }

    fn handle_wasm_execute(
        &mut self,
        sender: String,
        contract_addr: String,
        msg: Binary,
        funds: Vec<Coin>,
        local: bool,
    ) -> (ResponseType, String) {
        if is_gate_address(&contract_addr) {
            let res = self.execute(
                local,
                from_binary::<ExecuteMsg>(&msg).unwrap(),
                Addr::unchecked(sender),
                funds,
            );
            (ResponseType::from_response(res), contract_addr)
        } else {
            self.handle_non_gate_address(contract_addr, msg)
        }
    }

    fn handle_non_gate_address(
        &self,
        contract_addr: String,
        msg: Binary,
    ) -> (ResponseType, String) {
        match self.non_gate_response.get(&(contract_addr.clone(), msg)) {
            Some(response) => (response.to_owned(), contract_addr),
            None => (ResponseType::NotHandled(), contract_addr),
        }
    }

    fn execute(
        &mut self,
        local: bool,
        msg: ExecuteMsg,
        sender: Addr,
        funds: Vec<Coin>,
    ) -> Result<Response, ContractError> {
        let (deps, env) = self.get_data(local);
        execute(
            deps,
            env.to_owned(),
            mock_info(sender.as_str(), &funds),
            msg,
        )
    }

    // --- IBC ---

    fn handle_ibc_sub_msg(&mut self, msg: IbcMsg, local: bool) -> ResponseType {
        match msg {
            IbcMsg::SendPacket {
                channel_id,
                data,
                timeout,
            } => self.handle_ibc_sub_msg_send_packet(local, channel_id, data, timeout),
            _ => panic!("IbcMsg type not handled {:?}", msg),
        }
    }

    fn handle_ibc_sub_msg_send_packet(
        &mut self,
        local: bool,
        _channel_id: String,
        data: Binary,
        timeout: IbcTimeout,
    ) -> ResponseType {
        let sequence = self.update_sequence(!local, get_endpoint(!local).channel_id);

        let packet = IbcPacket::new(
            data,
            get_endpoint(!local),
            get_endpoint(local),
            sequence,
            timeout,
        );

        self.ibc_packet = Some(packet.clone());

        let ibc_receive_msg = IbcPacketReceiveMsg::new(packet, get_relayer(local));

        ResponseType::ResponseSendPacket {
            packet: ibc_receive_msg,
        }
    }

    fn handle_packet_receive(
        &mut self,
        packet: IbcPacketReceiveMsg,
        local: bool,
    ) -> (ResponseType, String) {
        let (deps, env) = if local {
            (self.local_deps.as_mut(), &self.local_env)
        } else {
            (self.remote_deps.as_mut(), &self.remote_env)
        };

        let res = ibc_packet_receive(deps, env.to_owned(), packet);

        (
            ResponseType::from_ibc_receive_response(res),
            get_gate_address(local).to_string(),
        )
    }

    // --- STARGATE ---

    fn handle_stargate(
        &mut self,
        type_url: String,
        value: Binary,
        local: bool,
    ) -> (ResponseType, String, u64) {
        match type_url.as_str() {
            "/ibc.applications.transfer.v1.MsgTransfer" => {
                self.handle_stargate_msg_transfer(value, local)
            }
            _ => panic!(),
        }
    }

    fn handle_stargate_msg_transfer(
        &mut self,
        value: Binary,
        local: bool,
    ) -> (ResponseType, String, u64) {
        let msg = MsgTransfer::decode(value.as_slice()).unwrap();

        let local_sequence = self.update_sequence(local, msg.source_channel.clone());

        let mut memo: MemoField<ExecuteMsg> = from_str(msg.memo.as_str()).unwrap();

        let mut wasm: Option<WasmField<ExecuteMsg>> = None;

        let mut n = 1;

        while n < 100 {
            if let Some(w) = &memo.wasm {
                wasm = Some(w.to_owned());
                break;
            } else {
                memo = *memo.forward.unwrap().next.unwrap();
                n += 1
            }
        }

        let wasm = wasm.unwrap();

        let (channel, sequence) =
            if let ExecuteMsg::IbcHook(IbcHookMsg::ExecutePendingRequest { channel, sequence }) =
                wasm.msg.clone()
            {
                (channel, sequence)
            } else {
                panic!("Wrong execute msg: {:?}", wasm.msg)
            };

        // Load the packet saved on the other chain to get the correct denom to be received
        let (deps, _) = if !local {
            (self.local_deps.as_mut(), &self.local_env)
        } else {
            (self.remote_deps.as_mut(), &self.remote_env)
        };

        let packet = PENDING_PACKETS
            .load(deps.storage, (channel, sequence))
            .unwrap();

        let remote_addr = get_gate_address(!local);

        (
            ResponseType::from_response(Ok(Response::new().add_message(CosmosMsg::Wasm(
                WasmMsg::Execute {
                    contract_addr: remote_addr.to_string(),
                    msg: to_binary(&wasm.msg).unwrap(),
                    funds: vec![Coin {
                        denom: packet.send_native.unwrap().dest_denom,
                        amount: Uint128::from_str(msg.token.unwrap().amount.as_str()).unwrap(),
                    }],
                },
            )))),
            msg.source_channel,
            local_sequence,
        )
    }

    // --- REPLY ---

    fn handle_reply(&mut self, reply_msg: Reply, local: bool) -> ResponseType {
        let (deps, env) = self.get_data(local);
        let res = reply(deps, env.to_owned(), reply_msg);
        ResponseType::from_response(res)
    }

    // --- ACK ----

    fn handle_ack(&mut self, ack: GateAck, local: bool) -> ResponseType {
        let msg = IbcPacketAckMsg::new(
            IbcAcknowledgement::new(to_binary(&ack).unwrap()),
            self.ibc_packet.clone().unwrap(),
            get_relayer(local),
        );

        let (deps, env) = self.get_data(local);

        let res = ibc_packet_ack(deps, env.to_owned(), msg);

        ResponseType::from_ibc_basic_response(res)
    }

    // --- SUDO ---

    fn handle_sudo(&mut self, sudo_msg: SudoMsg, local: bool) -> ResponseType {
        let (deps, env) = self.get_data(local);

        let res = sudo(deps, env.to_owned(), sudo_msg);

        ResponseType::from_response(res)
    }

    // ---

    fn update_sequence(&mut self, local: bool, channel_id: String) -> u64 {
        match self
            .sequences
            .get_mut(&!local)
            .unwrap()
            .get_mut(&channel_id)
        {
            Some(val) => {
                *val += 1_u64;
                val.to_owned()
            }
            None => {
                self.sequences
                    .get_mut(&!local)
                    .unwrap()
                    .insert(channel_id, 0);
                0_u64
            }
        }
    }

    fn initialize_gate(
        local: bool,
    ) -> StdResult<(OwnedDeps<MemoryStorage, MockApi, WasmMockQuerier>, Env)> {
        let (
            local_chain,
            local_gate,
            remote_gate,
            local_contract,
            remote_contract,
            base_denom,
            voucher,
            local_channel,
            remote_channel,
            remote_chain,
            remote_base_denom,
            local_voucher_of_remote,
        ) = if local {
            (
                LOCAL_CHAIN,
                LOCAL_GATE,
                REMOTE_GATE,
                LOCAL_CONTRACT,
                REMOTE_CONTRACT,
                LOCAL_BASE_DENOM,
                LOCAL_VOUCHER,
                LOCAL_CHANNEL,
                REMOTE_CHANNEL,
                REMOTE_CHAIN,
                REMOTE_BASE_DENOM,
                LOCAL_VOUCHER_OF_REMOTE,
            )
        } else {
            (
                LOCAL_CHAIN,
                REMOTE_GATE,
                LOCAL_GATE,
                REMOTE_CONTRACT,
                LOCAL_CONTRACT,
                REMOTE_BASE_DENOM,
                REMOTE_VOUCHER,
                REMOTE_CHANNEL,
                LOCAL_CHANNEL,
                LOCAL_CHAIN,
                LOCAL_BASE_DENOM,
                REMOTE_VOUCHER_OF_LOCAL,
            )
        };

        let mut deps = custom_mock_dependencies();
        let mut env = mock_env();
        env.block = BlockInfo {
            height: DEFAULT_HEIGHT,
            time: Timestamp::from_seconds(DEFAULT_TIMESTAMP),
            chain_id: local_chain.to_string(),
        };

        env.contract.address = Addr::unchecked(local_gate);

        let local_port_id = get_wasm_port_id(local_gate);

        let remote_port_id = get_wasm_port_id(remote_gate);

        env.contract.address = Addr::unchecked(local_gate);

        // Initialize
        let msg = InstantiateMsg {
            controller: Addr::unchecked(CONTROLLER),
            default_timeout: 100_u64,
            default_gas_limit: None,
            cw20_icg_code_id: 1,
            base_denom: base_denom.to_string(),
            max_gas_amount_per_revert: MAX_GAS_AMOUNT_PER_REVERT,
        };

        let info: MessageInfo = mock_info(OWNER, &[]);

        let res = instantiate(deps.as_mut(), env.clone(), info, msg);

        if res.is_err() {
            panic!("Should return Ok, instead returned: {}", res.unwrap_err())
        }

        // Store voucher contract
        store_voucher_contract(deps.as_mut(), voucher.to_string());

        // Open channel
        let msg = IbcChannelConnectMsg::OpenAck {
            channel: IbcChannel::new(
                IbcEndpoint {
                    port_id: local_port_id,
                    channel_id: local_channel.to_string(),
                },
                IbcEndpoint {
                    port_id: remote_port_id,
                    channel_id: remote_channel.to_string(),
                },
                IbcOrder::Unordered,
                ICG_VERSION,
                CONNECTION.to_string(),
            ),

            counterparty_version: "icg-1".to_string(),
        };

        let res = ibc_channel_connect(deps.as_mut(), env.clone(), msg);

        if res.is_err() {
            panic!("Should return Ok, instead returned: {}", res.unwrap_err())
        }

        // Register channel
        let msg = ExecuteMsg::RegisterChainAndChannel {
            chain: remote_chain.to_string(),
            src_channel: local_channel.to_string(),
            base_denom: remote_base_denom.to_string(),
        };

        let res = execute(deps.as_mut(), env.clone(), mock_info(CONTROLLER, &[]), msg);

        if res.is_err() {
            panic!("Should return Ok, instead returned: {}", res.unwrap_err())
        }

        // Store voucher contract
        store_voucher_contract(deps.as_mut(), local_voucher_of_remote.to_string());

        // Set permission
        let msg = ExecuteMsg::SetPermission {
            permission: Permission::Permissioned {
                addresses: vec![remote_contract.to_string()],
            },
            chain: remote_chain.to_string(),
        };

        let res = execute(
            deps.as_mut(),
            env.clone(),
            mock_info(local_contract, &[]),
            msg,
        );

        if res.is_err() {
            panic!("Should return Ok, instead returned: {}", res.unwrap_err())
        }

        Ok((deps, env))
    }

    pub fn get_data(&mut self, local: bool) -> (DepsMut<Empty>, &Env) {
        if local {
            (self.local_deps.as_mut(), &self.local_env)
        } else {
            (self.remote_deps.as_mut(), &self.remote_env)
        }
    }

    pub fn set_price(&mut self, local: bool, price: Decimal) {
        if local {
            self.local_deps.querier.set_price(price)
        } else {
            self.remote_deps.querier.set_price(price)
        };
    }
}

impl Default for GatesManager {
    fn default() -> Self {
        Self::new()
    }
}

fn get_endpoint(local: bool) -> IbcEndpoint {
    let (port_id, channel_id) = if local {
        (get_wasm_port_id(LOCAL_GATE), LOCAL_CHANNEL)
    } else {
        (get_wasm_port_id(REMOTE_GATE), REMOTE_CHANNEL)
    };

    IbcEndpoint {
        port_id,
        channel_id: channel_id.to_string(),
    }
}

fn get_relayer(local: bool) -> Addr {
    if local {
        Addr::unchecked(LOCAL_RELAYER)
    } else {
        Addr::unchecked(REMOTE_RELAYER)
    }
}

fn is_gate_address(addr: &String) -> bool {
    *addr == LOCAL_GATE || *addr == REMOTE_GATE
}

fn get_gate_address(local: bool) -> Addr {
    if local {
        Addr::unchecked(LOCAL_GATE)
    } else {
        Addr::unchecked(REMOTE_GATE)
    }
}

pub fn merge_fee_with_send_native(
    fee: &Option<Coin>,
    send_native: &Option<SendNativeInfo>,
) -> Vec<Coin> {
    let mut funds: Vec<Coin> = vec![];

    if let Some(fee) = fee {
        funds.push(fee.to_owned())
    };

    if let Some(send_native_info) = send_native {
        if let Some(inserted) = funds.first_mut() {
            if inserted.denom == send_native_info.coin.denom {
                inserted.amount += send_native_info.coin.amount
            } else {
                funds.push(send_native_info.coin.clone())
            }
        } else {
            funds.push(send_native_info.coin.clone())
        };
    }

    funds
}

#[cw_serde]
pub enum ResponseType {
    Response(Response),
    IbcReceiveResponse(IbcReceiveResponse),
    IbcBasicResponse(IbcBasicResponse),
    NotHandled(),
    Err(String),
    ResponseSendPacket { packet: IbcPacketReceiveMsg },
}

impl ResponseType {
    pub fn msgs(&self) -> Vec<SubMsgType> {
        match self {
            ResponseType::Response(val) => val
                .messages
                .clone()
                .into_iter()
                .map(|sub_msg| -> SubMsgType { SubMsgType::SubMsg(sub_msg) })
                .collect(),
            ResponseType::IbcReceiveResponse(val) => val
                .messages
                .clone()
                .into_iter()
                .map(|sub_msg| -> SubMsgType { SubMsgType::SubMsg(sub_msg) })
                .collect(),
            ResponseType::IbcBasicResponse(val) => val
                .messages
                .clone()
                .into_iter()
                .map(|sub_msg| -> SubMsgType { SubMsgType::SubMsg(sub_msg) })
                .collect(),
            ResponseType::NotHandled() => vec![],
            ResponseType::Err(_) => vec![],
            ResponseType::ResponseSendPacket { packet } => {
                vec![SubMsgType::PacketReceive(packet.to_owned())]
            }
        }
    }

    pub fn from_response(res: Result<Response, ContractError>) -> ResponseType {
        match res {
            Ok(val) => ResponseType::Response(val),
            Err(err) => ResponseType::Err(err.to_string()),
        }
    }

    pub fn from_ibc_receive_response(res: Result<IbcReceiveResponse, Never>) -> ResponseType {
        match res {
            Ok(val) => ResponseType::IbcReceiveResponse(val),
            Err(err) => ResponseType::Err(err.to_string()),
        }
    }

    pub fn from_ibc_basic_response(res: Result<IbcBasicResponse, ContractError>) -> ResponseType {
        match res {
            Ok(val) => ResponseType::IbcBasicResponse(val),
            Err(err) => ResponseType::Err(err.to_string()),
        }
    }

    pub fn events(self) -> Vec<Event> {
        match self {
            ResponseType::Response(val) => val.events,
            ResponseType::IbcReceiveResponse(val) => val.events,
            ResponseType::IbcBasicResponse(val) => val.events,
            _ => vec![],
        }
    }

    pub fn data(self) -> Option<Binary> {
        match self {
            ResponseType::Response(val) => val.data,
            ResponseType::IbcReceiveResponse(val) => Some(val.acknowledgement),
            _ => None,
        }
    }

    pub fn attributes(self) -> Vec<Attribute> {
        match self {
            ResponseType::Response(val) => val.attributes,
            ResponseType::IbcReceiveResponse(val) => val.attributes,
            ResponseType::IbcBasicResponse(val) => val.attributes,
            _ => vec![],
        }
    }
}

impl Display for ResponseType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self {
            ResponseType::Err(err) => {
                write!(f, "Error: {}", err)?;
            }
            ResponseType::NotHandled() => {
                write!(f, "NotHandled")?;
            }
            _ => {}
        }
        for msg in self.msgs() {
            let a = to_string_pretty(&msg).unwrap();
            writeln!(f, "{}", a)?
        }

        writeln!(f, "{:?}", self)
    }
}

#[cw_serde]
pub enum SubMsgType {
    SubMsg(SubMsg),
    Reply(Reply),
    GateAck(GateAck),
    PacketReceive(IbcPacketReceiveMsg),
    Sudo(SudoMsg),
}

#[derive(Debug, Clone)]
pub struct ResponseManager {
    pub msg_responses: Vec<MsgResponse>,
    pub unhandled_errors: VecDeque<ResponseType>,
    pub handled_errors: Vec<ResponseType>,
}

impl ResponseManager {
    pub fn new(msg_response: MsgResponse) -> ResponseManager {
        let unhandled_errors = match msg_response.response {
            ResponseType::Err(_) => VecDeque::from(vec![msg_response.response.clone()]),
            _ => VecDeque::from(vec![]),
        };

        ResponseManager {
            msg_responses: vec![msg_response],
            unhandled_errors,
            handled_errors: vec![],
        }
    }

    pub fn events(&self, local: bool) -> Vec<Event> {
        self.next_event_deep(local, self.msg_responses.clone())
    }

    #[allow(clippy::only_used_in_recursion)]
    fn next_event_deep(&self, local: bool, msg_responses: Vec<MsgResponse>) -> Vec<Event> {
        let mut events: Vec<Event> = vec![];
        for v in msg_responses {
            if v.local == local {
                events.append(&mut v.response.clone().events());
            }
            events.append(&mut self.next_event_deep(local, v.next));
        }
        events
    }

    pub fn data(&self, local: bool) -> Option<Binary> {
        self.next_data_deep(local, self.msg_responses.clone())
    }

    #[allow(clippy::only_used_in_recursion)]
    fn next_data_deep(&self, local: bool, msg_responses: Vec<MsgResponse>) -> Option<Binary> {
        let mut data: Option<Binary> = None;
        for msg_response in msg_responses {
            if msg_response.response.clone().data().is_some() && msg_response.local == local {
                return msg_response.response.data();
            }
            data = self.next_data_deep(local, msg_response.next)
        }
        data
    }

    pub fn merge_same_lvl(&mut self, mut with: ResponseManager) -> ResponseManager {
        self.msg_responses.append(&mut with.msg_responses);
        self.unhandled_errors.append(&mut with.unhandled_errors);
        self.handled_errors.append(&mut with.handled_errors);
        self.clone()
    }

    pub fn merge_next_lvl(&mut self, mut with: ResponseManager) -> ResponseManager {
        self.msg_responses
            .first_mut()
            .unwrap()
            .next
            .append(&mut with.msg_responses);

        self.unhandled_errors.append(&mut with.unhandled_errors);
        self.handled_errors.append(&mut with.handled_errors);
        self.clone()
    }

    pub fn ordered_msg_response(&self) -> Vec<(SubMsgType, ResponseType)> {
        let mut ret = vec![];
        for msg_response in self.msg_responses.clone() {
            ret.append(&mut self.next_msg_response_deep(msg_response))
        }
        ret
    }

    #[allow(clippy::only_used_in_recursion)]
    fn next_msg_response_deep(&self, msg_response: MsgResponse) -> Vec<(SubMsgType, ResponseType)> {
        let mut ret = vec![(msg_response.sub_msg, msg_response.response)];
        for a in msg_response.next {
            ret.append(&mut self.next_msg_response_deep(a))
        }
        ret
    }

    pub fn unhandled_errors_as_vec(&self) -> Vec<ResponseType> {
        self.unhandled_errors.clone().into()
    }

    pub fn next_unhandled_error(&self) -> Option<ResponseType> {
        self.unhandled_errors.get(0).map(|v| v.to_owned())
    }

    pub fn pop_next_unhandled_error(&mut self) {
        if let Some(popped) = self.unhandled_errors.pop_front() {
            self.handled_errors.push(popped)
        }
    }
}

impl Display for ResponseManager {
    fn fmt(&self, _: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for val in self.msg_responses.clone() {
            val.repr(0);
        }
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct MsgResponse {
    pub sender: String,
    pub sub_msg: SubMsgType,
    pub response: ResponseType,
    pub local: bool,
    pub next: Vec<MsgResponse>,
}

impl MsgResponse {
    pub fn new(
        sender: String,
        sub_msg: SubMsgType,
        response: ResponseType,
        local: bool,
    ) -> MsgResponse {
        MsgResponse {
            sender,
            sub_msg,
            response,
            local,
            next: vec![],
        }
    }

    pub fn repr(self, deep: usize) {
        let local = if self.local { "local" } else { "remote" };
        print!("\n{}{:->width$}", deep, "", width = deep);
        println!(" {} | sender: {}", local, self.sender);

        print!(" {:->width$}", "", width = deep);
        println!(" Msg: {:?}", self.sub_msg);

        print!(" {:-<width$}", "", width = deep);
        println!(" Response: {:?}", self.response);

        for i in self.next {
            i.repr(deep + 1)
        }
    }
}

#[cw_serde]
pub struct Log {
    pub local: Vec<Vec<Attribute>>,
    pub remote: Vec<Vec<Attribute>>,
    pub ibc_packet: Option<IbcPacket>,
}

impl Log {
    pub fn new() -> Log {
        Log {
            local: vec![],
            remote: vec![],
            ibc_packet: None,
        }
    }

    pub fn update(&mut self, response: ResponseType, local: bool) {
        if local {
            self.local.push(response.attributes())
        } else {
            self.remote.push(response.attributes())
        }
    }
}

impl Default for Log {
    fn default() -> Self {
        Self::new()
    }
}
