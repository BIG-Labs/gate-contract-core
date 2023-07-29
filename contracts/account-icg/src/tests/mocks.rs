
use cosmwasm_schema::cw_serde;
use cosmwasm_std::{Uint128, Addr, Coin, testing::{mock_dependencies_with_balances, mock_env, mock_info, MockStorage, MockApi, MockQuerier}, OwnedDeps, Env, entry_point, DepsMut, MessageInfo, Response, StdError, Deps, StdResult, Binary};
use cw_multi_test::{App, ContractWrapper, Executor, AppBuilder};

use crate::{msgs::{InstantiateMsg, TokenInfo}, contract::{instantiate, execute, query}, function::query_token_balance};

pub const GATE_ADDR: &str = "gate_addr";

pub fn _startup() -> (OwnedDeps<MockStorage, MockApi, MockQuerier>, Env) {

    let contract_addr = "icg-account_addr";

    let balances: &[(&str, &[Coin])]= &[
        (contract_addr, &start_balance())
    ];

    let mut deps = mock_dependencies_with_balances(balances);
    let mut env = mock_env();
    env.contract.address = Addr::unchecked(contract_addr);

    let msg = InstantiateMsg{
        external_owners: external_owners(),
        local_owners: local_owners(),
    };

    instantiate(deps.as_mut(), env.clone(), mock_info(GATE_ADDR, &[]), msg).unwrap();

    (deps, env)

}


fn mock_app(init_funds: &[Coin]) -> App {
    AppBuilder::new().build(|router, _, storage| {
        router
            .bank
            .init_balance(storage, &Addr::unchecked(GATE_ADDR), init_funds.to_vec())
            .unwrap();
    })
}
pub fn startup_app() -> (App, Addr, Addr) {

    let mut app = mock_app(&start_balance());
    
    let code_account = app.store_code(Box::new(ContractWrapper::new(execute, instantiate, query)));

    let code_mock = app.store_code(Box::new(ContractWrapper::new(mock_execute, mock_instantiate, mock_query)));

    let init_msg = InstantiateMsg{
        external_owners: external_owners(),
        local_owners: local_owners(),
    };

    let contract_account = app.instantiate_contract(code_account, Addr::unchecked(GATE_ADDR), &init_msg, &[], "account", None).unwrap();

    let contract_mock = app.instantiate_contract(code_mock, Addr::unchecked("random_addr"), &MockInstantiate{}, &[], "mock_contract", None).unwrap();

    // app.send_tokens(Addr::unchecked(GATE_ADDR), contract_account.clone(), &start_balance()).unwrap();

    (app, contract_account, contract_mock)

}

pub fn external_owners() -> Vec<(String, String)>{
    vec![
        ("osmo123".to_string(), "osmosis".to_string()),
        ("inj123".to_string(), "injective".to_string())
    ]
}

pub fn local_owners() -> Vec<Addr> {
    vec![
        Addr::unchecked("terra123")
    ]
}

pub fn start_balance() -> Vec<Coin> {
    return vec![
        Coin{denom: "ustake".to_string(), amount:Uint128::from(100_u128)}
    ];
}

// --- MOCK CONTRACT ---

#[cw_serde]
pub struct MockInstantiate {
}

#[cw_serde]
pub enum MockExecuteMsg {
    Deposit { amount: Uint128 },
    Swap { amount:Uint128, request:TokenInfo }
}

#[cw_serde]
pub enum MockQueryMsg {
}

#[entry_point]
pub fn mock_instantiate(
    _deps: DepsMut,
    _env: Env,
    _info: MessageInfo,
    _msg: MockInstantiate) -> Result<Response, StdError> {

    Ok(Response::new())
}


#[entry_point]
pub fn mock_execute(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    msg: MockExecuteMsg,
) -> Result<Response, StdError> {

    let mut res = Response::new();

    for i in &info.funds {
        res = res.add_attribute(i.denom.clone(), i.amount);
    }

    if let MockExecuteMsg::Swap { amount, request } = msg {

        let coin = info.funds.first().unwrap();

        if coin.amount != amount {
            return  Err(StdError::generic_err("amount not match"));
        }

        let amount = query_token_balance(&deps.querier, &request, &env.contract.address);


        
    }



    Ok(res)

}

#[entry_point]
pub fn mock_query(_deps: Deps, _env: Env, _msg: MockQueryMsg) -> StdResult<Binary> {
    Ok(Binary::default())
}

