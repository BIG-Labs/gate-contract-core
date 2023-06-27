use cosmwasm_std::{Addr, Coin, Deps, Order, StdError, StdResult, Storage};
use gate_pkg::{ChannelInfo, Config, Permission};

use crate::{
    error::ContractError,
    state::{CHAIN_REGISTERED_CHANNELS, CONIFG, REGISTERED_CONTRACTS},
};

/// Return stored `base_denom`.
pub fn get_base_denom(storage: &dyn Storage) -> StdResult<String> {
    let denom = CONIFG.load(storage)?.base_denom;
    Ok(denom)
}

/// Assert the controller and return Config
pub fn is_controller(deps: Deps, address: Addr) -> Result<Config, ContractError> {
    let config = CONIFG.load(deps.storage)?;

    if config.controller != address {
        return Err(ContractError::Unauthorized {});
    }

    Ok(config)
}

/// Return the `(chain, channel_info)` from a registered channel.
pub fn get_chain_and_channel_info_from_registered_channel(
    storage: &dyn Storage,
    src_channel: String,
) -> Result<(String, ChannelInfo), ContractError> {
    let channels_info: Vec<(String, ChannelInfo)> = CHAIN_REGISTERED_CHANNELS()
        .idx
        .src_channel_dest_channel
        .prefix(src_channel.clone())
        .range(storage, None, None, Order::Ascending)
        .take(usize::from(1_u8))
        .map(|tuple| tuple.unwrap())
        .collect();

    if channels_info.is_empty() {
        return Err(ContractError::ChannelNotRegistered {
            channel: src_channel,
        });
    }

    let channel_info = channels_info.first().unwrap();

    Ok(channel_info.to_owned())
}

/// Return a `channl-id` from a `chain`.
pub fn get_channel_from_chain(
    storage: &dyn Storage,
    chain: &String,
) -> Result<String, ContractError> {
    match CHAIN_REGISTERED_CHANNELS().load(storage, chain.to_owned()) {
        Ok(channel_info) => Ok(channel_info.src_channel_id),
        Err(_) => Err(ContractError::ChainNotFound {
            chain: chain.to_owned(),
        }),
    }
}

/// Return the address of a `gate` from a `chain`.
pub fn get_remote_gate_addr_from_chain(
    storage: &dyn Storage,
    chain: &String,
) -> Result<String, ContractError> {
    match CHAIN_REGISTERED_CHANNELS().load(storage, chain.to_owned()) {
        Ok(channel_info) => Ok(channel_info.get_remote_gate()?),
        Err(_) => Err(ContractError::ChainNotFound {
            chain: chain.to_owned(),
        }),
    }
}

/// Check if the `local_addr` (the address in the current chain) allow msgs from the `remote_addr` is a specific `chain`
/// In case of `Permission::Permissionless` return `Ok()`
pub fn remote_contract_is_registered(
    deps: Deps,
    local_contract: String,
    remote_contract: String,
    chain: String,
) -> Result<(), ContractError> {
    match REGISTERED_CONTRACTS.load(deps.storage, (local_contract.clone(), chain.clone())) {
        Ok(permission) => match permission {
            Permission::Permissioned { addresses } => {
                if addresses.contains(&remote_contract) {
                    Ok(())
                } else {
                    Err(ContractError::RemoteContractNotRegistered {
                        local_contract,
                        remote_contract,
                    })
                }
            }
            Permission::Permissionless {} => Ok(()),
        },
        Err(_) => Err(ContractError::PermissionNeverSetted {
            contract: local_contract,
            chain,
        }),
    }
}

pub fn merge_fee(from: &Option<Coin>, with: &Option<Coin>) -> StdResult<Option<Coin>> {
    match from {
        Some(from) => match with {
            Some(with) => {
                if from.denom != with.denom {
                    return Err(StdError::generic_err("Fee should must have same denom"));
                }
                Ok(Some(Coin {
                    denom: from.denom.clone(),
                    amount: from.amount + with.amount,
                }))
            }
            None => Ok(Some(from.to_owned())),
        },
        None => Ok(with.to_owned()),
    }
}
