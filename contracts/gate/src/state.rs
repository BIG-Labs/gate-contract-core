use cosmwasm_schema::cw_serde;
use cosmwasm_std::{Addr, Coin, IbcOrder, StdError, StdResult};
use cw_storage_macro::index_list;
use cw_storage_plus::{IndexedMap, Item, Map, MultiIndex};
use enum_repr::EnumRepr;
use gate_pkg::{
    ChannelInfo, Config, GateRequestsInfo, Permission, QueryRequestInfoResponse, SendNativeInfo,
};
use serde::Serialize;

// --- CONSTANTS ---

pub const CONIFG: Item<Config> = Item::new("config");

pub const REGISTERED_CONTRACTS: Map<(String, String), Permission> =
    Map::new("registered_contracts");

pub const CHANNEL_INFO: Map<String, ChannelInfo> = Map::new("registered_ports");

pub const IS_REGISTERING: Item<bool> = Item::new("is_registering");

pub const BUFFER_PACKETS: Item<Option<GatePacketInfo>> = Item::new("buffer_packets");

pub const PENDING_PACKETS: Map<(String, u64), RequestsPacket> = Map::new("pending_packets");

pub const PACKET_IBC_HOOK_AWAITING_REPLY: Item<(RequestsPacket, PacketSavedKey)> =
    Item::new("awaiting_packet_reply");

pub const PACKET_IBC_HOOK_AWAITING_ACK: Map<(String, u64), (RequestsPacket, PacketSavedKey)> =
    Map::new("on_ack_await");

pub const RECEIVED_FEE: Item<Option<Coin>> = Item::new("received_fee");

pub const BUFFER_QUERIES_RESPONSE: Item<Vec<QueryRequestInfoResponse>> =
    Item::new("buffer_queries_response");

pub const VOUCHER_REGISTERING_CHAIN: Item<Option<RegisteringVoucherChain>> =
    Item::new("voucher_registering_chain");

pub const ICG_VERSION: &str = "icg-1";

pub const ICG_ORDERING: IbcOrder = IbcOrder::Unordered;

pub const LAST_FAILED_KEY_GENERATED: Item<(u64, u64)> = Item::new("last_failed_key_generated");

#[index_list(ChannelInfo)]
pub struct ChannelInfoChannelIndexes<'a> {
    pub src_channel_dest_channel: MultiIndex<'a, String, ChannelInfo, String>,
}

#[cw_serde]
pub struct PacketSavedKey {
    pub channel: String,
    pub sequence: u64,
}

#[allow(non_snake_case)]
pub fn CHAIN_REGISTERED_CHANNELS<'a>(
) -> IndexedMap<'a, String, ChannelInfo, ChannelInfoChannelIndexes<'a>> {
    let indexes = ChannelInfoChannelIndexes {
        src_channel_dest_channel: MultiIndex::new(
            |_pk, channel_info| channel_info.src_channel_id.clone(),
            "ns",
            "ns_src_channel_dest_channel",
        ),
    };
    IndexedMap::new("ns", indexes)
}

// --- MSGS ---

/// Message type for `sudo` entry_point
#[cw_serde]
pub enum SudoMsg {
    #[serde(rename = "ibc_lifecycle_complete")]
    IBCLifecycleComplete(IBCLifecycleComplete),
}

#[cw_serde]
pub struct InstantiateMsg {
    pub controller: Addr,
    pub default_timeout: u64,
    pub default_gas_limit: Option<u64>,
    pub cw20_icg_code_id: u64,
    pub base_denom: String,
    pub max_gas_amount_per_revert: u64,
}

#[cw_serde]
pub struct MigrateMsg {}

#[cw_serde]
pub enum Cw20MsgType {
    RedeemVoucher {},
}

#[cw_serde]
pub enum RegisteringVoucherChain {
    Local,
    Chain { name: String },
}

// --- REPLY/ACK ---

#[EnumRepr(type = "u64")]
pub enum ReplyID {
    /// Reply received when execute msg in remote chain
    ExecuteRequest = 1,
    AckContract = 2,
    InitToken = 3,
    MintVoucher = 4,
    SendIbcHookPacket = 5,
}

/// Base Ack structure
#[cw_serde]
pub struct GateAck {
    pub coin: Option<Coin>,
    pub ack: GateAckType,
}

/// Ack type handled by gate contract
#[cw_serde]
pub enum GateAckType {
    EmptyResult,
    QueryResult(Vec<QueryRequestInfoResponse>),
    Error(String),
    NativeSendRequest {
        dest_key: PacketSavedKey,
        gate_packet: Box<RequestsPacket>,
    },
    RemoveStoredPacket {
        src_key: PacketSavedKey,
        removed: bool,
    },
}

// --- STRUCTURES ---

#[cw_serde]
pub enum GatePacket {
    RequestPacket(Box<RequestsPacket>),
    RemoveStoredPacket {
        dest_key: PacketSavedKey,
        src_key: PacketSavedKey,
    },
}

impl GatePacket {
    pub fn as_request_packet(&self) -> StdResult<RequestsPacket> {
        match self {
            GatePacket::RequestPacket(packet) => Ok(*packet.to_owned()),
            _ => Err(StdError::generic_err(
                "GatePacket is not RequestPacket type",
            )),
        }
    }
}

#[cw_serde]
pub struct RequestsPacket {
    pub from_chain: Option<String>,
    pub to_chain: String,
    pub requests_infos: Vec<GateRequestsInfo>,
    pub fee: Option<Coin>,
    pub send_native: Option<SendNativeInfo>,
}

#[cw_serde]
pub struct GatePacketInfo {
    pub packet: RequestsPacket,
    pub timeout: Option<u64>,
}

// --- IBC PACKET MEMO ---

#[cw_serde]
pub enum IBCLifecycleComplete {
    #[serde(rename = "ibc_ack")]
    IBCAck {
        /// The source channel (osmosis side) of the IBC packet
        channel: String,
        /// The sequence number that the packet was sent with
        sequence: u64,
        /// String encoded version of the ack as seen by OnAcknowledgementPacket(..)
        ack: String,
        /// Weather an ack is a success of failure according to the transfer spec
        success: bool,
    },
    #[serde(rename = "ibc_timeout")]
    IBCTimeout {
        /// The source channel (osmosis side) of the IBC packet
        channel: String,
        /// The sequence number that the packet was sent with
        sequence: u64,
    },
}

#[cw_serde]
pub struct MemoField<T: Serialize> {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub forward: Option<ForwardField<T>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wasm: Option<WasmField<T>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ibc_callback: Option<String>,
}

#[cw_serde]
pub struct ForwardField<T: Serialize> {
    pub receiver: String,
    pub port: String,
    pub channel: String,
    // pub timeout: String,
    // pub retries: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next: Option<Box<MemoField<T>>>,
}

#[cw_serde]
pub struct WasmField<T: Serialize> {
    pub contract: String,
    pub msg: T,
}

#[cw_serde]
pub struct Forward {
    pub receiver: String,
    pub channel: String,
}
