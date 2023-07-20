use cosmwasm_std::{
    from_binary,
    testing::{mock_dependencies, mock_env, mock_info},
    to_binary, Addr, Coin, CosmosMsg, ReplyOn, SubMsg, Uint128, WasmMsg,
};
use cw20::{BalanceResponse, Cw20Coin, Cw20ReceiveMsg, MinterResponse};
use cw20_base::ContractError;
use cw20_icg_pkg::{Cw20GateMsgType, ExecuteMsg, InstantiateMsg, QueryMsg};

use gate_pkg::{ExecuteMsg as GateExecuteMsg, GateMsg, GateRequest, Permission};

use crate::contract::{execute, instantiate, query};

#[test]
fn test() {
    let mut deps = mock_dependencies();
    let env = mock_env();

    let mint_amount = Uint128::from(200_u128);

    let local_user = "user_1";

    let init_minter_user = "user_0";

    let info = mock_info("owner", &[]);

    let minter = "minter";

    let msg = InstantiateMsg {
        name: "token".to_string(),
        symbol: "TOKEN".to_string(),
        decimals: 6,
        initial_balances: vec![Cw20Coin {
            address: init_minter_user.to_string(),
            amount: mint_amount,
        }],
        mint: Some(MinterResponse {
            minter: minter.to_string(),
            cap: None,
        }),
    };

    instantiate(deps.as_mut(), env.clone(), info, msg).unwrap();

    // Standard Transfer

    let info = mock_info(init_minter_user, &[]);

    let msg = ExecuteMsg::Transfer {
        recipient: local_user.to_string(),
        amount: Uint128::from(200_u128),
    };

    execute(deps.as_mut(), env.clone(), info, msg).unwrap();

    // Query balance

    let msg = QueryMsg::Balance {
        address: local_user.to_string(),
    };

    let res = query(deps.as_ref(), env.clone(), msg).unwrap();

    assert_eq!(
        BalanceResponse {
            balance: Uint128::from(200_u128)
        },
        from_binary(&res).unwrap()
    );

    // GATE

    let gate_contract = "gate";

    // Register gate from non minter

    let msg = ExecuteMsg::RegisterGate {
        contract: Addr::unchecked(gate_contract),
    };

    let res = execute(
        deps.as_mut(),
        env.clone(),
        mock_info("random_addr", &[]),
        msg.clone(),
    );

    assert_eq!(
        res.unwrap_err().to_string(),
        ContractError::Unauthorized {}.to_string()
    );

    // Register gate

    execute(deps.as_mut(), env.clone(), mock_info(minter, &[]), msg).unwrap();

    // Query gate

    let res = query(deps.as_ref(), env.clone(), QueryMsg::Gate {}).unwrap();

    assert_eq!(
        gate_contract.to_string(),
        from_binary::<String>(&res).unwrap()
    );

    // Set permission from non minter

    let remote_contract = "remote_contract";
    let chain = "remote_chain";

    let msg = ExecuteMsg::GateSetPermission {
        contract: remote_contract.to_string(),
        chain: chain.to_string(),
    };

    let res = execute(
        deps.as_mut(),
        env.clone(),
        mock_info("random_addr", &[]),
        msg.clone(),
    );

    assert_eq!(
        res.unwrap_err().to_string(),
        ContractError::Unauthorized {}.to_string()
    );

    // Set permission

    let res = execute(deps.as_mut(), env.clone(), mock_info(minter, &[]), msg).unwrap();

    assert_eq!(
        res.messages,
        vec![SubMsg {
            id: 0,
            gas_limit: None,
            reply_on: ReplyOn::Never,
            msg: CosmosMsg::Wasm(WasmMsg::Execute {
                contract_addr: gate_contract.to_string(),
                funds: vec![],
                msg: to_binary(&GateExecuteMsg::SetPermission {
                    permission: Permission::Permissioned {
                        addresses: vec![remote_contract.to_string()]
                    },
                    chain: chain.to_string()
                })
                .unwrap()
            })
        }]
    );

    // Gate bridge

    let bridge_amount = Uint128::from(100_u128);

    let remote_user = "user2_remote";

    let fee = Coin {
        denom: "uluna".to_string(),
        amount: Uint128::from(50_u128),
    };

    let msg = ExecuteMsg::GateBridge {
        chain: chain.to_string(),
        remote_receiver: remote_user.to_string(),
        amount: bridge_amount,
    };

    let res = execute(
        deps.as_mut(),
        env.clone(),
        mock_info(local_user, &[fee.clone()]),
        msg,
    )
    .unwrap();

    assert_eq!(
        res.messages,
        vec![SubMsg {
            id: 0,
            gas_limit: None,
            reply_on: ReplyOn::Never,
            msg: CosmosMsg::Wasm(WasmMsg::Execute {
                contract_addr: gate_contract.to_string(),
                msg: to_binary(&GateExecuteMsg::SendRequests {
                    requests: vec![GateRequest::SendMsg {
                        msg: to_binary(&Cw20GateMsgType::Bridge {
                            sender: local_user.to_string(),
                            receiver: remote_user.to_string(),
                            amount: bridge_amount
                        })
                        .unwrap(),
                        to_contract: remote_contract.to_string(),
                        send_native: None
                    }],
                    chain: chain.to_string(),
                    timeout: None
                })
                .unwrap(),
                funds: vec![fee]
            })
        }]
    );

    // Check remaining amount

    let msg = QueryMsg::Balance {
        address: local_user.to_string(),
    };

    let res = query(deps.as_ref(), env.clone(), msg).unwrap();

    assert_eq!(
        BalanceResponse {
            balance: mint_amount - bridge_amount
        },
        from_binary(&res).unwrap()
    );

    // GateBridgeAndExecute

    let remote_mock = "remote_mock";

    let b_msg = to_binary("123").unwrap();

    let msg = ExecuteMsg::GateBridgeAndExecute {
        chain: chain.to_string(),
        remote_receiver: remote_user.to_string(),
        amount: bridge_amount,
        remote_contract: remote_mock.to_string(),
        msg: b_msg.clone(),
    };

    let res = execute(deps.as_mut(), env.clone(), mock_info(local_user, &[]), msg).unwrap();

    assert_eq!(
        res.messages,
        vec![SubMsg {
            id: 0,
            gas_limit: None,
            reply_on: ReplyOn::Never,
            msg: CosmosMsg::Wasm(WasmMsg::Execute {
                contract_addr: gate_contract.to_string(),
                msg: to_binary(&GateExecuteMsg::SendRequests {
                    requests: vec![GateRequest::SendMsg {
                        msg: to_binary(&Cw20GateMsgType::BridgeAndExecute {
                            sender: local_user.to_string(),
                            receiver: remote_user.to_string(),
                            amount: bridge_amount,
                            to_contract: remote_mock.to_string(),
                            msg: b_msg.clone()
                        })
                        .unwrap(),
                        to_contract: remote_contract.to_string(),
                        send_native: None
                    }],
                    chain: chain.to_string(),
                    timeout: None
                })
                .unwrap(),
                funds: vec![]
            })
        }]
    );

    // Check remaining amount

    let msg = QueryMsg::Balance {
        address: local_user.to_string(),
    };

    let res = query(deps.as_ref(), env.clone(), msg).unwrap();

    assert_eq!(
        BalanceResponse {
            balance: mint_amount - bridge_amount - bridge_amount
        },
        from_binary(&res).unwrap()
    );

    // Receive from gate

    // Non gate contract

    let bridge_request_msg = Cw20GateMsgType::Bridge {
        sender: remote_user.to_string(),
        receiver: local_user.to_string(),
        amount: bridge_amount,
    };

    let msg = ExecuteMsg::ReceiveGateMsg(GateMsg::ReceivedMsg {
        sender: remote_contract.to_string(),
        msg: to_binary(&bridge_request_msg).unwrap(),
    });

    execute(
        deps.as_mut(),
        env.clone(),
        mock_info("fake_gate", &[]),
        msg.clone(),
    )
    .unwrap_err();

    // From gate

    execute(
        deps.as_mut(),
        env.clone(),
        mock_info(gate_contract, &[]),
        msg,
    )
    .unwrap();

    // Check new amount

    let msg = QueryMsg::Balance {
        address: local_user.to_string(),
    };

    let res = query(deps.as_ref(), env.clone(), msg).unwrap();

    assert_eq!(
        BalanceResponse {
            balance: mint_amount - bridge_amount - bridge_amount + bridge_amount
        },
        from_binary(&res).unwrap()
    );

    // Receive check and execute

    let local_mock = "local_mock";

    let bridge_request_msg = Cw20GateMsgType::BridgeAndExecute {
        sender: remote_user.to_string(),
        receiver: local_user.to_string(),
        amount: bridge_amount,
        to_contract: local_mock.to_string(),
        msg: b_msg.clone(),
    };

    let msg = ExecuteMsg::ReceiveGateMsg(GateMsg::ReceivedMsg {
        sender: remote_contract.to_string(),
        msg: to_binary(&bridge_request_msg).unwrap(),
    });

    let res = execute(
        deps.as_mut(),
        env.clone(),
        mock_info(gate_contract, &[]),
        msg,
    )
    .unwrap();

    assert_eq!(
        res.messages,
        vec![SubMsg {
            id: 0,
            gas_limit: None,
            reply_on: ReplyOn::Never,
            msg: CosmosMsg::Wasm(WasmMsg::Execute {
                contract_addr: local_mock.to_string(),
                funds: vec![],
                msg: Cw20ReceiveMsg {
                    sender: local_user.to_string(),
                    amount: bridge_amount,
                    msg: b_msg
                }
                .into_binary()
                .unwrap()
            })
        }]
    );

    // Check amount for local_mock

    let msg = QueryMsg::Balance {
        address: local_mock.to_string(),
    };

    let res = query(deps.as_ref(), env.clone(), msg).unwrap();

    assert_eq!(
        BalanceResponse {
            balance: bridge_amount
        },
        from_binary(&res).unwrap()
    );

    // Request Failed

    let msg = ExecuteMsg::ReceiveGateMsg(GateMsg::RequestFailed {
        request: GateRequest::SendMsg {
            msg: to_binary(&Cw20GateMsgType::Bridge {
                sender: local_user.to_string(),
                receiver: remote_user.to_string(),
                amount: bridge_amount,
            })
            .unwrap(),
            to_contract: remote_contract.to_string(),
            send_native: None,
        },
    });

    execute(
        deps.as_mut(),
        env.clone(),
        mock_info("fake_gate", &[]),
        msg.clone(),
    )
    .unwrap_err();

    execute(
        deps.as_mut(),
        env.clone(),
        mock_info(gate_contract, &[]),
        msg,
    )
    .unwrap();

    // Check amount for local_user

    let msg = QueryMsg::Balance {
        address: local_user.to_string(),
    };

    let res = query(deps.as_ref(), env, msg).unwrap();

    assert_eq!(
        BalanceResponse {
            balance: bridge_amount + bridge_amount
        },
        from_binary(&res).unwrap()
    );
}
