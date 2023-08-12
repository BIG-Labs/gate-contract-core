use cosmwasm_schema::cw_serde;
use cosmwasm_std::{to_binary, Addr, BankMsg, Coin, CosmosMsg, StdResult, Uint128, WasmMsg};
use cw20::Cw20ExecuteMsg;
use rhaki_cw_plus::serde::Value;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct MsgToExecuteInfo {
    pub msg: Value,
    pub replaces_infos: Vec<ReplaceInfo>,
}

#[cw_serde]
pub struct ReplaceInfo {
    pub key: String,
    pub value: ReplaceValueType,
}

#[cw_serde]
pub enum ReplaceValueType {
    TokenAmount(TokenInfo),
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
            TokenInfo::Cw20(address) => address.to_string(),
            TokenInfo::Native(denom) => denom.to_owned(),
        }
    }

    pub fn as_send_msg(&self, amount: Uint128, receiver: Addr) -> StdResult<CosmosMsg> {
        match self {
            TokenInfo::Cw20(address) => Ok(CosmosMsg::Wasm(WasmMsg::Execute {
                contract_addr: address.to_string(),
                msg: to_binary(&Cw20ExecuteMsg::Transfer {
                    recipient: receiver.to_string(),
                    amount,
                })?,
                funds: vec![],
            })),
            TokenInfo::Native(denom) => Ok(CosmosMsg::Bank(BankMsg::Send {
                to_address: receiver.to_string(),
                amount: vec![Coin {
                    denom: denom.to_owned(),
                    amount,
                }],
            })),
        }
    }
}
