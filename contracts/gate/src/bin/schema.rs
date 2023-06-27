use cosmwasm_schema::write_api;

use cw20_icg_pkg::InstantiateMsg;
use gate_pkg::{ExecuteMsg, QueryMsg};

fn main() {
    write_api! {
        instantiate: InstantiateMsg,
        execute: ExecuteMsg,
        query: QueryMsg,
    }
}
