use cosmwasm_std::Binary;
use osmosis_std_derive::CosmwasmExt;
use prost::Message;

#[derive(
    Clone,
    PartialEq,
    Eq,
    ::prost::Message,
    serde::Serialize,
    serde::Deserialize,
    schemars::JsonSchema,
)]
pub struct IbcCounterpartyHeight {
    #[prost(uint64, optional, tag = "1")]
    revision_number: Option<u64>,
    #[prost(uint64, optional, tag = "2")]
    revision_height: Option<u64>,
}

#[derive(
    Clone,
    PartialEq,
    Eq,
    ::prost::Message,
    serde::Serialize,
    serde::Deserialize,
    schemars::JsonSchema,
    CosmwasmExt,
)]
#[proto_message(type_url = "/ibc.applications.transfer.v1.MsgTransfer")]

pub struct MsgTransfer {
    #[prost(string, tag = "1")]
    pub source_port: String,
    #[prost(string, tag = "2")]
    pub source_channel: String,
    #[prost(message, optional, tag = "3")]
    pub token: ::core::option::Option<osmosis_std::types::cosmos::base::v1beta1::Coin>,
    #[prost(string, tag = "4")]
    pub sender: String,
    #[prost(string, tag = "5")]
    pub receiver: String,
    #[prost(message, optional, tag = "6")]
    pub timeout_height: Option<IbcCounterpartyHeight>,
    #[prost(uint64, optional, tag = "7")]
    pub timeout_timestamp: ::core::option::Option<u64>,
    #[prost(string, tag = "8")]
    pub memo: String,
}

// We define the response as a prost message to be able to decode the protobuf data.
#[derive(Clone, PartialEq, Eq, ::prost::Message)]
pub struct MsgTransferResponse {
    #[prost(uint64, tag = "1")]
    pub sequence: u64,
}

impl MsgTransfer {
    pub fn to_binary(&self) -> Binary {
        let mut msg_transfer_binary: Vec<u8> = vec![];
        self.encode(&mut msg_transfer_binary).unwrap();
        Binary::from(msg_transfer_binary)
    }
}
