use cosmwasm_schema::cw_serde;
use cosmwasm_std::{Addr, CosmosMsg, Uint128, WasmMsg, to_binary, BankMsg, StdResult, Coin};
use cw20::Cw20ExecuteMsg;
use schemars::_serde_json::value::Index;

#[cw_serde]
pub struct InstantiateMsg {
    pub external_owners: Vec<(String, String)>,
    pub local_owners: Vec<Addr>,
}

#[cw_serde]
pub enum ExecuteMsg {
    ExecuteMsgs {
        msgs: Vec<MsgToExecuteInfo>,
    },
    GateExecuteMsgs {
        sender: (String, String),
        msgs: Vec<MsgToExecuteInfo>,
    },
    PrivateExecuteMsg(MsgToExecuteInfo),
}

#[cw_serde]
pub struct QueryMsg {}

#[cw_serde]
pub struct MsgToExecuteInfo {
    pub msg: CosmosMsg,
    pub replaces_infos: Vec<ReplaceInfo>,
}

#[cw_serde]
pub struct ReplaceInfo {
    pub token_info: TokenInfo,
    pub path: Vec<ReplacePath>,
}

#[cw_serde]
pub struct ReplacePath {
    pub value: String,
    pub key_type: ReplaceKeyType,
    pub is_next_in_binary: bool,
}

#[cw_serde]
pub enum ReplaceKeyType {
    String,
    IndexArray,
}

#[cw_serde]
pub enum IndexType {
    String(String),
    Index(usize),
}
impl IndexType {
    pub fn as_index(&self) -> Box<dyn Index> {
        match self {
            IndexType::String(v) => Box::new(v.to_owned()),
            IndexType::Index(v) => Box::new(v.to_owned()),
        }
    }
}

#[cw_serde]
#[derive(Eq, Hash)]
pub enum TokenInfo {
    Cw20(Addr),
    Native(String),
}

impl TokenInfo {
    pub fn as_string(&self) -> String {
        match self {
            TokenInfo::Cw20(v) => v.to_string(),
            TokenInfo::Native(v) => v.to_owned(),
        }
    }

    pub fn as_send_msg(&self, amount:Uint128, receiver:Addr) -> StdResult<CosmosMsg> {

        match self {
            TokenInfo::Cw20(contract) => {
                Ok(CosmosMsg::Wasm(WasmMsg::Execute
                    {
                        contract_addr: contract.to_string(),
                        msg: to_binary(&Cw20ExecuteMsg::Transfer { recipient: receiver.to_string(), amount })?,
                        funds: vec![] }))
            },
            TokenInfo::Native(denom) => {
                Ok(
                CosmosMsg::Bank(BankMsg::Send { to_address: receiver.to_string(), amount: vec![Coin{denom: denom.to_owned(), amount}] }))
            },
        }

    }
}
