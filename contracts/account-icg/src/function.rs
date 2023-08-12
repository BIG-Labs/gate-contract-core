use std::collections::BTreeMap;

use cosmwasm_std::{Addr, CosmosMsg, Env, QuerierWrapper, StdError, StdResult, Storage, Uint128};
use rhaki_cw_plus::{
    encdec::{base64_decode_as_string, base64_encode},
    serde::{value_from_string, value_to_comsos_msg, value_to_string, Value},
};

use cw20::{BalanceResponse as Cw20BalanceResponse, Cw20QueryMsg};

use crate::state::BALANCES;

use account_icg_pkg::definitions::{ReplaceInfo, ReplaceValueType, TokenInfo};

pub fn vec_replace_info_into_result(
    storage: &mut dyn Storage,
    querier: &QuerierWrapper,
    env: &Env,
    replace_infos: Vec<ReplaceInfo>,
) -> Vec<(String, String)> {
    replace_infos
        .into_iter()
        .map(|info| match info.value {
            ReplaceValueType::TokenAmount(token) => {
                let res = avaiable_amount(storage, querier, env, &token).unwrap();
                (info.key, res.to_string())
            }
        })
        .collect()
}

pub fn substitute_key_in_value_into_comsos_msg(
    storage: &mut dyn Storage,
    querier: &QuerierWrapper,
    env: &Env,
    input: &Value,
    replace_info: Vec<ReplaceInfo>,
) -> StdResult<CosmosMsg> {
    let res = if !replace_info.is_empty() {
        let substitutes = vec_replace_info_into_result(storage, querier, env, replace_info);
        recursive_decode(input.clone(), substitutes)?
    } else {
        input.clone()
    };

    value_to_comsos_msg(&res)
}

pub fn recursive_decode(value: Value, variables: Vec<(String, String)>) -> StdResult<Value> {
    // match the type of the Value
    match value.clone() {
        // if it's a string
        Value::String(string_value) => {
            // for each variable in variables
            for (k, v) in variables.clone() {
                // check if we can replace it
                if k == string_value {
                    // serialize into Value
                    return Ok(Value::String(v.clone()));
                }
            }
            // if we didn't find the variables, try to decode
            match base64_decode_as_string(&string_value) {
                // if we can decode call recursive decode again to serialize the new substring into a Value
                Ok(v) => {
                    let decoded: Value = recursive_decode(value_from_string(&v)?, variables)?;
                    // Encode again the substring
                    let decoded_str: String = value_to_string(&decoded)?;
                    Ok(Value::String(base64_encode(&decoded_str)))
                }
                // else return the value (not decoded)
                Err(_) => Ok(value),
            }
        }
        // if it's a struct map it
        Value::Map(map) => {
            let mut new_map: BTreeMap<Value, Value> = BTreeMap::new();
            // iter each key
            for (k, v) in map.iter() {
                // for each key call recursive_decode and decode again
                let result = recursive_decode(v.clone(), variables.clone())?;
                // create a Map assiging the key with the object the Map will be in alphabetical order
                new_map.insert(k.clone(), result);
            }
            // return the msg once done
            Ok(Value::Map(new_map))
        }
        // if it's an array
        Value::Seq(arr) => {
            // iter into it and recursive decode fields
            let iter_arr: Vec<Value> = arr
                .into_iter()
                .map(|i| recursive_decode(i, variables.clone()).unwrap())
                .collect();

            Ok(Value::Seq(iter_arr))
        }
        // we could add more type of data there
        _ => Ok(value),
    }
}

pub fn query_token_balance(querier: &QuerierWrapper, token: &TokenInfo, address: &Addr) -> Uint128 {
    match token {
        TokenInfo::Cw20(address) => {
            querier
                .query_wasm_smart::<Cw20BalanceResponse>(
                    address,
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
    storage: &mut dyn Storage,
    querier: &QuerierWrapper,
    env: &Env,
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
