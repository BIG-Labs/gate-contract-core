use cosmwasm_std::{Addr, Coin, Uint128};
use cw_multi_test::{App, AppBuilder, ContractWrapper, Executor};

use account_icg_pkg::msgs::InstantiateMsg;

use crate::contract::{execute, instantiate, query};

pub const GATE_ADDR: &str = "gate_addr";

pub const ACCOUNT_ADDR: &str = "contract0";
pub const MOCK_ADDR: &str = "contract1";

fn mock_app(init_funds: &[Coin]) -> App {
    AppBuilder::new().build(|router, _, storage| {
        router
            .bank
            .init_balance(storage, &Addr::unchecked(GATE_ADDR), init_funds.to_vec())
            .unwrap();
    })
}

/// Startup App and contracts
/// - `50_000` `uatom` are sent to `MOCK_CONTRACT`
/// - `100` `uatom` are sent to `ACCOUNT_CONTRACT`
pub fn startup_app() -> App {
    let mut app = mock_app(&start_balance());

    let code_account = app.store_code(Box::new(ContractWrapper::new(execute, instantiate, query)));

    let code_mock = app.store_code(Box::new(ContractWrapper::new(
        mock_contract::execute,
        mock_contract::instantiate,
        mock_contract::query,
    )));

    let init_msg = InstantiateMsg {};

    let contract_account = app
        .instantiate_contract(
            code_account,
            Addr::unchecked(GATE_ADDR),
            &init_msg,
            &[],
            "account",
            None,
        )
        .unwrap();

    assert_eq!(contract_account, ACCOUNT_ADDR);

    let contract_mock = app
        .instantiate_contract(
            code_mock,
            Addr::unchecked("random_addr"),
            &mock_contract::InstantiateMsg {},
            &[],
            "mock_contract",
            None,
        )
        .unwrap();

    assert_eq!(contract_mock, MOCK_ADDR);

    app.send_tokens(
        Addr::unchecked(GATE_ADDR),
        Addr::unchecked(MOCK_ADDR),
        &[Coin {
            denom: "uatom".to_string(),
            amount: Uint128::from(50_000_u128),
        }],
    )
    .unwrap();

    app.send_tokens(
        Addr::unchecked(GATE_ADDR),
        Addr::unchecked(ACCOUNT_ADDR),
        &[Coin {
            denom: "uatom".to_string(),
            amount: Uint128::from(100_u128),
        }],
    )
    .unwrap();

    app
}

pub fn start_balance() -> Vec<Coin> {
    vec![
        Coin {
            denom: "uluna".to_string(),
            amount: Uint128::from(100_000_u128),
        },
        Coin {
            denom: "uatom".to_string(),
            amount: Uint128::from(100_000_u128),
        },
    ]
}

mod mock_contract {
    use account_icg_pkg::definitions::TokenInfo;
    use cosmwasm_schema::cw_serde;
    use cosmwasm_std::{
        entry_point, BankMsg, Binary, Coin, CosmosMsg, Deps, DepsMut, Env, MessageInfo, Response,
        StdError, StdResult, Uint128,
    };

    use crate::function::query_token_balance;

    #[cw_serde]
    pub struct InstantiateMsg {}

    #[cw_serde]
    pub enum ExecuteMsg {
        Deposit {
            amount_deposit: Uint128,
        },
        Swap {
            amount_swap: Uint128,
            request: TokenInfo,
            amount_ask: Uint128,
        },
    }

    #[cw_serde]
    pub enum QueryMsg {}

    #[entry_point]
    pub fn instantiate(
        _deps: DepsMut,
        _env: Env,
        _info: MessageInfo,
        _msg: InstantiateMsg,
    ) -> StdResult<Response> {
        Ok(Response::new())
    }

    #[entry_point]
    pub fn execute(
        deps: DepsMut,
        env: Env,
        info: MessageInfo,
        msg: ExecuteMsg,
    ) -> Result<Response, StdError> {
        let mut res = Response::new();

        for i in &info.funds {
            res = res.add_attribute(i.denom.clone(), i.amount);
        }

        match msg {
            ExecuteMsg::Deposit { amount_deposit } => {
                let coin = info.funds.first().unwrap();

                if coin.amount != amount_deposit {
                    return Err(StdError::generic_err("Amount sent not match"));
                };
            }
            ExecuteMsg::Swap {
                amount_swap,
                request,
                amount_ask,
            } => {
                let coin = info.funds.first().unwrap();

                if coin.amount != amount_swap {
                    return Err(StdError::generic_err("Amount sent not match"));
                }

                let current_amount_ask =
                    query_token_balance(&deps.querier, &request, &env.contract.address);

                if current_amount_ask < amount_ask {
                    return Err(StdError::generic_err("Asket amount to low"));
                }

                res = res.add_message(CosmosMsg::Bank(BankMsg::Send {
                    to_address: info.sender.to_string(),
                    amount: vec![Coin {
                        denom: request.as_string(),
                        amount: amount_ask,
                    }],
                }));
            }
        }

        Ok(res)
    }

    #[entry_point]
    pub fn query(_deps: Deps, _env: Env, _msg: QueryMsg) -> StdResult<Binary> {
        Ok(Binary::default())
    }
}
