use cosmwasm_std::{
    from_binary, to_binary, Addr, Binary, Coin, CosmosMsg, Env, QuerierWrapper, StdError,
    StdResult, Storage, Uint128,
};
use schemars::_serde_json::Value;
use std::{
    collections::{HashMap, VecDeque},
    str::FromStr,
};

use cw20::{BalanceResponse as Cw20BalanceResponse, Cw20QueryMsg};

use base64::{engine::general_purpose, Engine as _};

use crate::{
    msgs::{IndexType, ReplaceInfo, ReplaceKeyType, ReplacePath, TokenInfo},
    state::BALANCES,
};

pub fn replace_amount(
    msg: CosmosMsg,
    replace_info: &ReplaceInfo,
    amount: Uint128,
) -> StdResult<CosmosMsg> {
    let msg: Value = from_binary(&to_binary(&msg)?)?;

    let msg_mod = replace_amount_rec(msg, amount, VecDeque::from(replace_info.path.to_owned()));

    from_binary(&to_binary(&msg_mod)?)
}

fn replace_amount_rec(mut json: Value, amount: Uint128, mut paths: VecDeque<ReplacePath>) -> Value {
    let path = paths.pop_front();

    if let Some(cur) = path {
        let i = match cur.key_type {
            ReplaceKeyType::String => IndexType::String(cur.value.clone()),
            ReplaceKeyType::IndexArray => {
                IndexType::Index(u32::from_str(cur.value.as_str()).unwrap() as usize)
            }
        };

        let mut next = json[i.as_index().as_ref()].to_owned();

        if cur.is_next_in_binary {
            next = value_from_b64(&next);
        }

        next = replace_amount_rec(next.clone(), amount, paths);

        if cur.is_next_in_binary {
            next = value_to_b64(&next);
        }

        json[i.as_index().as_ref()] = next;

        json
    } else {
        Value::from(amount.to_string())
    }
}

fn value_from_b64(value: &Value) -> Value {
    from_binary(&Binary::from_base64(value.as_str().unwrap()).unwrap()).unwrap()
}

fn value_to_b64(value: &Value) -> Value {
    Value::from(general_purpose::STANDARD.encode(value.to_string()))
}

pub fn vec_coins_to_hashmap(coins: Vec<Coin>) -> StdResult<HashMap<String, Uint128>> {
    let mut m: HashMap<String, Uint128> = HashMap::new();

    for coin in coins {
        if m.contains_key(&coin.denom) {
            return Err(StdError::generic_err(format!(
                "multiple denom detected, {}",
                &coin.denom
            )));
        }
        m.insert(coin.denom, coin.amount);
    }

    Ok(m)
}

pub fn query_token_balance(querier: &QuerierWrapper, token: &TokenInfo, address: &Addr) -> Uint128 {
    match token {
        TokenInfo::Cw20(contract) => {
            querier
                .query_wasm_smart::<Cw20BalanceResponse>(
                    contract,
                    &Cw20QueryMsg::Balance {
                        address: address.to_string(),
                    },
                )
                .unwrap()
                .balance
        }
        TokenInfo::Native(denom) => {
            querier
                .query_balance(address.to_string(), denom)
                .unwrap()
                .amount
        }
    }
}

pub fn avaiable_amount(
    env: &Env,
    storage: &mut dyn Storage,
    querier: &QuerierWrapper,
    info: &TokenInfo,
) -> StdResult<Uint128> {
    match BALANCES.load(storage)?.get(&info.as_string()) {
        Some(amount) => Ok(query_token_balance(querier, info, &env.contract.address) - amount),
        None => Err(StdError::generic_err(format!(
            "balance not found, {}",
            info.as_string()
        ))),
    }
}
