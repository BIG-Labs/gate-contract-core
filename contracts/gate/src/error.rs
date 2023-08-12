use cosmwasm_std::{Addr, Coin, StdError};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ContractError {
    #[error("{0}")]
    Std(#[from] StdError),

    #[error("Unauthorized")]
    Unauthorized {},

    #[error("Only supports channel with ibc version icg-1, got {version}")]
    InvalidIbcVersion { version: String },

    #[error("Only supports unordered channel")]
    OnlyUnorderedChannel {},

    #[error("Channel {channel} not registered")]
    ChannelNotRegistered { channel: String },

    #[error("Chain not found: {chain}")]
    ChainNotFound { chain: String },

    #[error("Permissions for {contract} has never been set")]
    PermissionNeverSetted { contract: String, chain: String },

    #[error(
        "Remote contract {remote_contract} not registered for local contract {local_contract}"
    )]
    RemoteContractNotRegistered {
        local_contract: String,
        remote_contract: String,
    },

    #[error("Packet with sequence: {sequence} | channel: {channel} alredy in pending")]
    PacketAlredyInPending { sequence: u64, channel: String },

    #[error("Invalid id Reply: {id}")]
    InvalidIdReply { id: u64 },

    #[error("No coin has been sent with the packet, expected {expected}")]
    NoCoinWithPacket { expected: Coin },

    #[error("No request received on collected msgs")]
    NoRequestReceivedOnCollectedMsgs {},

    #[error("Contract without admin: {contract}")]
    ContractWithoutAdmin { contract: String },

    #[error("Initalize token fails: {err}")]
    InitializeCw20Fails { err: String },

    #[error("Wrong voucher address - expected: {expected}, received: {received}")]
    WrongVoucherAddres { expected: String, received: String },

    #[error("Query failed")]
    QueryFailed {},

    #[error("Address with another gate account: address: {address}, chain: {chain}, gate_account{gate_account}")]
    AddressWithAccount {
        address: String,
        chain: String,
        gate_account: Addr,
    },

    #[error("Pending address not match: pending: {pending}, registering: {registering}")]
    PendingWrongAddress { pending: Addr, registering: Addr },

    #[error("Account in pending: account: {account_addr}, user: {user_addr}, chain: {chain}")]
    AccountInPending {
        account_addr: Addr,
        user_addr: String,
        chain: String,
    },
}
