use cosmwasm_std::{to_binary, BankMsg, Coin, CosmosMsg, Uint128, WasmMsg, Addr};
use cw_multi_test::Executor;

use crate::{
    function::replace_amount,
    msgs::{ReplaceInfo, ReplaceKeyType, ReplacePath, TokenInfo, ExecuteMsg, MsgToExecuteInfo}, tests::mocks::MockExecuteMsg,
};

use super::mocks::{GATE_ADDR, external_owners, start_balance, startup_app};

#[test]
fn test_parse_bank_send_msg() {
    let r_amount = Uint128::from(100_u128);

    let replace_info = ReplaceInfo {
        token_info: TokenInfo::Native("ustake".to_string()),
        path: vec![
            ReplacePath {
                value: "bank".to_string(),
                key_type: ReplaceKeyType::String,
                is_next_in_binary: false,
            },
            ReplacePath {
                value: "send".to_string(),
                key_type: ReplaceKeyType::String,
                is_next_in_binary: false,
            },
            ReplacePath {
                value: "amount".to_string(),
                key_type: ReplaceKeyType::String,
                is_next_in_binary: false,
            },
            ReplacePath {
                value: "1".to_string(),
                key_type: ReplaceKeyType::IndexArray,
                is_next_in_binary: false,
            },
            ReplacePath {
                value: "amount".to_string(),
                key_type: ReplaceKeyType::String,
                is_next_in_binary: false,
            },
        ],
    };

    let msg: CosmosMsg = CosmosMsg::Bank(BankMsg::Send {
        to_address: "receiver".to_string(),
        amount: vec![
            Coin {
                denom: "ustake".to_string(),
                amount: Uint128::zero(),
            },
            Coin {
                denom: "pippo".to_string(),
                amount: Uint128::zero(),
            },
        ],
    });

    println!("{:?}", msg);

    let b = replace_amount(msg, &replace_info, r_amount).unwrap();

    println!("{:?}", b)
}

#[test]
fn test_parse_wasm_execute_msg() {


    let r_amount = Uint128::from(100_u128);

    let msg: CosmosMsg = CosmosMsg::Wasm(WasmMsg::Execute {
        contract_addr: "random_address".to_string(),
        msg: to_binary(&MockExecuteMsg::Deposit {
            amount: Uint128::zero(),
        })
        .unwrap(),
        funds: vec![],
    });

    let replace_info = ReplaceInfo {
        token_info: TokenInfo::Native("ustake".to_string()),
        path: vec![
            ReplacePath {
                value: "wasm".to_string(),
                key_type: ReplaceKeyType::String,
                is_next_in_binary: false,
            },
            ReplacePath {
                value: "execute".to_string(),
                key_type: ReplaceKeyType::String,
                is_next_in_binary: false,
            },
            ReplacePath {
                value: "msg".to_string(),
                key_type: ReplaceKeyType::String,
                is_next_in_binary: true,
            },
            ReplacePath {
                value: "deposit".to_string(),
                key_type: ReplaceKeyType::String,
                is_next_in_binary: false,
            },
            ReplacePath {
                value: "amount".to_string(),
                key_type: ReplaceKeyType::String,
                is_next_in_binary: false,
            },
        ],
    };

    println!("{:?}", msg);

    let b = replace_amount(msg, &replace_info, r_amount).unwrap();

    println!("{:?}", b);
}

#[test]
fn double_msg() {

    let (mut app, contract_account, contract_mock) = startup_app();

    // EXECUTE FROM GATE

    let mut first_coin = start_balance()[0].clone();

    first_coin.amount -= Uint128::from(30_u128);

    let msg = ExecuteMsg::GateExecuteMsgs { sender: external_owners()[0].clone(), msgs: vec![
        MsgToExecuteInfo{ msg: CosmosMsg::Wasm(WasmMsg::Execute { contract_addr: contract_mock.to_string(), msg: to_binary(&MockExecuteMsg::Swap { amount: first_coin.amount}).unwrap(), funds: vec![first_coin.clone()] }), replaces_infos: vec![] },
        MsgToExecuteInfo{ msg: CosmosMsg::Wasm(WasmMsg::Execute { contract_addr: contract_mock.to_string(), msg: to_binary(&MockExecuteMsg::Deposit { amount: Uint128::zero()}).unwrap(), funds: vec![first_coin.clone()] }), replaces_infos: vec![
            ReplaceInfo{
                token_info: TokenInfo::Native(first_coin.denom.clone()),
                path: vec![
                    ReplacePath {
                        value: "wasm".to_string(),
                        key_type: ReplaceKeyType::String,
                        is_next_in_binary: false,
                    },
                    ReplacePath {
                        value: "execute".to_string(),
                        key_type: ReplaceKeyType::String,
                        is_next_in_binary: false,
                    },
                    ReplacePath {
                        value: "msg".to_string(),
                        key_type: ReplaceKeyType::String,
                        is_next_in_binary: true,
                    },
                    ReplacePath {
                        value: "deposit".to_string(),
                        key_type: ReplaceKeyType::String,
                        is_next_in_binary: false,
                    },
                    ReplacePath {
                        value: "amount".to_string(),
                        key_type: ReplaceKeyType::String,
                        is_next_in_binary: false,
                    }
                ]
            },
            ReplaceInfo{
                token_info: TokenInfo::Native(first_coin.denom),
                path: vec![
                    ReplacePath {
                        value: "wasm".to_string(),
                        key_type: ReplaceKeyType::String,
                        is_next_in_binary: false,
                    },
                    ReplacePath {
                        value: "execute".to_string(),
                        key_type: ReplaceKeyType::String,
                        is_next_in_binary: false,
                    },
                    ReplacePath {
                        value: "funds".to_string(),
                        key_type: ReplaceKeyType::String,
                        is_next_in_binary: false,
                    },
                    ReplacePath {
                        value: "0".to_string(),
                        key_type: ReplaceKeyType::IndexArray,
                        is_next_in_binary: false,
                    },
                    ReplacePath {
                        value: "amount".to_string(),
                        key_type: ReplaceKeyType::String,
                        is_next_in_binary: false,
                    }
                ]
            }
        ] }

    ]
     };

    let res = app.execute_contract(Addr::unchecked(GATE_ADDR), contract_account, &msg, &start_balance()).unwrap();

    for i in res.events {
        println!("{i:?}")
    }



}