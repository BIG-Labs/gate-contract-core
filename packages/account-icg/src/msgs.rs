use cosmwasm_schema::cw_serde;
use cosmwasm_std::Addr;

use serde::{Deserialize, Serialize};

use crate::definitions::MsgToExecuteInfo;

#[cw_serde]
pub struct InstantiateMsg {}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum ExecuteMsg {
    ExecuteMsgs { msgs: Vec<MsgToExecuteInfo> },

    PrivateExecuteMsg(MsgToExecuteInfo),
}

#[cw_serde]
pub struct InstantiateDataResponse {
    pub remote_owners: Vec<(String, String)>,
    pub local_owners: Option<Vec<String>>,
}

#[cw_serde]
pub enum QueryMsg {
    Config {},
}

#[cw_serde]
pub struct ConfigResponse {
    pub gate_address: Addr,
}
