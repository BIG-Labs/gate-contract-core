use std::{collections::HashMap, marker::PhantomData};

use cosmwasm_schema::{cw_serde, QueryResponses};
use cosmwasm_std::{
    from_binary, from_slice,
    testing::{MockApi, MockQuerier, MockStorage},
    to_binary, ContractInfoResponse, ContractResult, CustomQuery, Decimal, OwnedDeps, Querier,
    QuerierResult, QueryRequest, SystemError, SystemResult, WasmQuery,
};

#[cw_serde]
#[derive(QueryResponses)]
pub enum QueryMsgOracle {
    #[returns(Decimal)]
    Price { asset: String },
}

pub fn custom_mock_dependencies() -> OwnedDeps<MockStorage, MockApi, WasmMockQuerier> {
    OwnedDeps {
        storage: MockStorage::default(),
        api: MockApi::default(),
        querier: WasmMockQuerier::new(),
        custom_query_type: PhantomData,
    }
}

pub struct WasmMockQuerier {
    base: MockQuerier<DefaultWasmMockQuerier>,
    price: Option<Decimal>,
    contract_info: HashMap<String, ContractInfoResponse>,
}

#[cw_serde]
pub struct DefaultWasmMockQuerier {}

impl CustomQuery for DefaultWasmMockQuerier {}

impl Querier for WasmMockQuerier {
    fn raw_query(&self, bin_request: &[u8]) -> QuerierResult {
        // MockQuerier doesn't support Custom, so we ignore it completely here
        let request: QueryRequest<DefaultWasmMockQuerier> = match from_slice(bin_request) {
            Ok(v) => v,
            Err(e) => {
                return SystemResult::Err(SystemError::InvalidRequest {
                    error: format!("Parsing query request: {}", e),
                    request: bin_request.into(),
                })
            }
        };
        self.handle_query(&request)
    }
}

impl WasmMockQuerier {
    pub fn new() -> WasmMockQuerier {
        WasmMockQuerier {
            base: MockQuerier::new(&[]),
            price: None,
            contract_info: HashMap::new(),
        }
    }

    pub fn handle_query(&self, request: &QueryRequest<DefaultWasmMockQuerier>) -> QuerierResult {
        match &request {
            QueryRequest::Wasm(WasmQuery::Smart { msg, .. }) => match from_binary(msg) {
                Ok(v) => match v {
                    QueryMsgOracle::Price { .. } => match self.price {
                        Some(v) => SystemResult::Ok(ContractResult::from(to_binary(&v))),
                        None => SystemResult::Err(SystemError::InvalidRequest {
                            error: "No borrow rate exists".to_string(),
                            request: msg.to_owned(),
                        }),
                    },
                },
                Err(_) => SystemResult::Err(SystemError::InvalidRequest {
                    error: "No borrow rate exists".to_string(),
                    request: msg.to_owned(),
                }),
            },

            QueryRequest::Wasm(WasmQuery::Raw { key, .. }) => match from_binary(key).unwrap() {
                QueryMsgOracle::Price { .. } => match self.price {
                    Some(v) => SystemResult::Ok(ContractResult::from(to_binary(&v))),
                    None => SystemResult::Err(SystemError::InvalidRequest {
                        error: "No borrow rate exists".to_string(),
                        request: key.as_slice().into(),
                    }),
                },
            },

            QueryRequest::Wasm(WasmQuery::ContractInfo { contract_addr }) => {
                match self.contract_info.get(contract_addr) {
                    Some(contract_info) => {
                        SystemResult::Ok(ContractResult::from(to_binary(&contract_info)))
                    }
                    None => SystemResult::Err(SystemError::NoSuchContract {
                        addr: contract_addr.to_owned(),
                    }),
                }
            }

            _ => self.base.handle_query(request),
        }
    }

    pub fn set_price(&mut self, price: Decimal) {
        self.price = Some(price)
    }

    pub fn set_contract_info(&mut self, contract: String, contract_info: ContractInfoResponse) {
        self.contract_info.insert(contract, contract_info);
    }
}

impl Default for WasmMockQuerier {
    fn default() -> Self {
        Self::new()
    }
}
