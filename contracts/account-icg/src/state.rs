use std::collections::HashMap;

use cosmwasm_std::{Addr, Uint128};
use cw_storage_plus::Item;

/// `Vec<Address, Chain>`
pub const EXTERNAL_OWNERS: Item<Vec<(String, String)>> = Item::new("external_owners");
pub const LOCAL_OWNERS: Item<Vec<Addr>> = Item::new("local_owners");
pub const BALANCES: Item<HashMap<String, Uint128>> = Item::new("balances_key");
