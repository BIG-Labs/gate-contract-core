use cosmwasm_std::{Addr, Deps};
use gate_pkg::{ChannelInfo, Config, Permission};

use crate::{
    error::ContractError,
    state::{CHAINS, CONIFG, REGISTERED_CONTRACTS},
};

/// Get saved `Config`
pub fn qy_config(deps: Deps) -> Result<Config, ContractError> {
    Ok(CONIFG.load(deps.storage)?)
}

/// Get `Permission` for a specific contract and chain
pub fn qy_permission(
    deps: Deps,
    contract: Addr,
    chain: String,
) -> Result<Permission, ContractError> {
    match REGISTERED_CONTRACTS.load(deps.storage, (contract.to_string(), chain.clone())) {
        Ok(value) => Ok(value),
        Err(_) => Err(ContractError::PermissionNeverSetted {
            contract: contract.to_string(),
            chain,
        }),
    }
}

/// Get channel info
pub fn qy_channel_info(deps: Deps, chain: String) -> Result<ChannelInfo, ContractError> {
    let channel = CHAINS().load(deps.storage, chain)?;

    Ok(channel)
}
