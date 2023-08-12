use std::str::FromStr;

use cosmwasm_std::{attr, Addr, BankMsg, Coin, CosmosMsg, Uint128};
use cw_multi_test::Executor;
use rhaki_cw_plus::serde::{json, std_to_sjw_value, value_to_b64_string, value_to_comsos_msg};

use account_icg_pkg::{
    definitions::{MsgToExecuteInfo, ReplaceInfo, ReplaceValueType, TokenInfo},
    msgs::ExecuteMsg,
};

use crate::{function::recursive_decode, tests::mocks::MOCK_ADDR};

use super::mocks::{startup_app, ACCOUNT_ADDR, GATE_ADDR};

#[test]
fn test_parse_bank_send_msg() {
    let value = json!({"bank":{"send":{
        "to_address": "addr_1",
        "amount": [
            {
                "denom": "ustake",
                "amount": "key_1"
            }
        ]
    }}});

    let value = std_to_sjw_value(value);

    let value_new =
        recursive_decode(value, vec![("key_1".to_string(), "100".to_string())]).unwrap();

    let msg = value_to_comsos_msg(&value_new).unwrap();

    println!("{value_new:#?}");

    assert_eq!(
        msg,
        CosmosMsg::Bank(BankMsg::Send {
            to_address: "addr_1".to_string(),
            amount: vec![Coin {
                denom: "ustake".to_string(),
                amount: Uint128::from(100_u128)
            }]
        })
    )
}

#[test]
fn multi_test() {
    let mut app = startup_app();

    let send_amount = "500";

    let amount_ask = "250";

    let msg = ExecuteMsg::ExecuteMsgs {
        msgs: vec![
            MsgToExecuteInfo {
                msg: std_to_sjw_value(json!(
                    {
                        "wasm":{
                            "execute":{
                                "contract_addr": MOCK_ADDR,
                                "funds":[
                                    {
                                        "denom": "uluna",
                                        "amount": send_amount
                                    }
                                ],
                                "msg": value_to_b64_string(
                                    &std_to_sjw_value(
                                        json!({"swap":{
                                            "amount_swap": send_amount,
                                            "request": {
                                                "native": "uatom"
                                            },
                                            "amount_ask": amount_ask
                                        }}))
                                ).unwrap()
                            }
                        }
                    }
                )),
                replaces_infos: vec![],
            },
            MsgToExecuteInfo {
                msg: std_to_sjw_value(json!(
                    {
                        "wasm":{
                            "execute":{
                                "contract_addr": MOCK_ADDR,
                                "funds":[
                                    {
                                        "denom": "uatom",
                                        "amount": "key_1"
                                    }
                                ],
                                "msg": value_to_b64_string(
                                    &std_to_sjw_value(
                                        json!({"deposit":{
                                            "amount_deposit": "key_1",
                                        }}))
                                ).unwrap()
                            }
                        }
                    }
                )),
                replaces_infos: vec![ReplaceInfo {
                    key: "key_1".to_string(),
                    value: ReplaceValueType::TokenAmount(TokenInfo::Native("uatom".to_string())),
                }],
            },
        ],
    };

    let res = app
        .execute_contract(
            Addr::unchecked(GATE_ADDR),
            Addr::unchecked(ACCOUNT_ADDR),
            &msg,
            &[Coin {
                denom: "uluna".to_string(),
                amount: Uint128::from_str(send_amount).unwrap(),
            }],
        )
        .unwrap();

    // Since 100 uatom has been sent within the startup, only 250 should be deposit and not 350

    assert_eq!(
        res.events.last().unwrap().attributes.last().unwrap(),
        attr("uatom", "250")
    )
}
