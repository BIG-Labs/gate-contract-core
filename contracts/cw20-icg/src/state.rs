use cosmwasm_std::Addr;
use cw_storage_plus::{Item, Map};

pub const GATE: Item<Addr> = Item::new("gate");

pub const CHAINS_CONTRACT: Map<String, String> = Map::new("chains_contracts");
