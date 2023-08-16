use account_icg_pkg::definitions::MsgToExecuteInfo;
use cosmwasm_std::{
    to_binary, Addr, Binary, Coin, CosmosMsg, Deps, DepsMut, Env, StdError, StdResult, Storage,
    WasmMsg,
};
use gate_pkg::{ChannelInfo, Config, Permission};
use rhaki_cw_plus::wasm::generate_instantiate_2_addr;
use sha2::{Digest, Sha256};

use crate::{
    error::ContractError,
    state::{
        GateAccountState, CHAINS, CONIFG, GATE_ACCOUNT, LOCAL_CHAIN_NAME, REGISTERED_CONTRACTS,
    },
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
    rhaki_cw_plus::storage::multi_index::get_unique_value(
        storage,
        src_channel,
        CHAINS().idx.src_channel,
    )
    .map_err(|err| err.into())
}

/// Return a `channl-id` from a `chain`.
pub fn get_channel_from_chain(
    storage: &dyn Storage,
    chain: &String,
) -> Result<String, ContractError> {
    match CHAINS().load(storage, chain.to_owned()) {
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
    match CHAINS().load(storage, chain.to_owned()) {
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

pub fn get_gate_account_registered(
    storage: &dyn Storage,
    address: String,
    chain: String,
) -> Result<Addr, ContractError> {
    match GATE_ACCOUNT().load(storage, (address.clone(), chain.clone()))? {
        GateAccountState::Pending(account_addr) => Err(ContractError::AccountInPending {
            account_addr,
            user_addr: address,
            chain,
        }),
        GateAccountState::Registered(account_addr) => Ok(account_addr),
    }
}

pub fn get_gate_account_in_pending(
    storage: &dyn Storage,
    address: String,
    chain: String,
) -> StdResult<Addr> {
    match GATE_ACCOUNT().load(storage, (address.clone(), chain.clone()))? {
        GateAccountState::Pending(account_addr) => Ok(account_addr),
        GateAccountState::Registered(account_addr) => Err(StdError::generic_err(format!(
            "Address {address} for chain {chain} is alredy registered for account {account_addr}"
        ))),
    }
}

// --- GATE ACCOUNT ---

pub fn gate_account_create_account(
    deps: &mut DepsMut,
    env: Env,
    sender: String,
    from_chain: String,
    remote_owners: Option<Vec<(String, String)>>,
    local_owners: Option<Vec<String>>,
) -> Result<Option<CosmosMsg>, ContractError> {
    let code_id = CONIFG.load(deps.storage)?.account_icg_code_id;

    let salt = create_salt(deps.storage, &sender, &from_chain)?;

    let account_addr = generate_instantiate_2_addr(
        &deps.querier,
        deps.api,
        code_id,
        &env.contract.address,
        &salt,
    )?;

    if let Some(GateAccountState::Registered(saved_addr)) =
        GATE_ACCOUNT().may_load(deps.storage, (sender.clone(), from_chain.clone()))?
    {
        return Err(ContractError::AddressWithAccount {
            address: sender,
            chain: from_chain,
            gate_account: saved_addr,
        });
    }

    GATE_ACCOUNT().save(
        deps.storage,
        (sender.clone(), from_chain.clone()),
        &GateAccountState::Registered(account_addr.clone()),
    )?;

    ga_store_pending(deps.storage, account_addr, remote_owners, local_owners)?;

    Ok(Some(CosmosMsg::Wasm(WasmMsg::Instantiate2 {
        admin: Some(env.contract.address.to_string()),
        code_id: CONIFG.load(deps.storage)?.account_icg_code_id,
        label: "account-icg".to_string(),
        funds: vec![],
        salt,
        msg: to_binary(&account_icg_pkg::msgs::InstantiateMsg {})?,
    })))
}

pub fn gate_account_validate_registration(
    deps: &mut DepsMut,
    account_addr: String,
    sender: String,
    from_chain: String,
) -> Result<Option<CosmosMsg>, ContractError> {
    let account_addr = deps.api.addr_validate(&account_addr)?;

    let pending_account =
        get_gate_account_in_pending(deps.storage, sender.clone(), from_chain.clone())?;

    if pending_account != account_addr {
        return Err(ContractError::PendingWrongAddress {
            pending: pending_account,
            registering: account_addr,
        });
    };

    GATE_ACCOUNT().save(
        deps.storage,
        (sender, from_chain),
        &GateAccountState::Registered(account_addr),
    )?;

    Ok(None)
}

pub fn gate_account_add_owners(
    storage: &mut dyn Storage,
    sender: String,
    from_chain: String,
    remote_owners: Option<Vec<(String, String)>>,
    local_owners: Option<Vec<String>>,
) -> Result<Option<CosmosMsg>, ContractError> {
    let account_addr = get_gate_account_registered(storage, sender, from_chain)?;

    ga_store_pending(storage, account_addr, remote_owners, local_owners)?;

    Ok(None)
}

pub fn gate_account_remove_owners(
    storage: &mut dyn Storage,
    sender: String,
    from_chain: String,
    remote_owners: Option<Vec<(String, String)>>,
    local_owners: Option<Vec<String>>,
) -> Result<Option<CosmosMsg>, ContractError> {
    let account_addr = get_gate_account_registered(storage, sender, from_chain)?;

    ga_remove_owners(storage, account_addr, remote_owners, local_owners)?;

    Ok(None)
}

pub fn gate_account_execute_requests(
    storage: &mut dyn Storage,
    sender: String,
    from_chain: String,
    msgs: Vec<MsgToExecuteInfo>,
    funds: Vec<Coin>,
) -> Result<Option<CosmosMsg>, ContractError> {
    let account_addr = get_gate_account_registered(storage, sender, from_chain)?;

    Ok(Some(CosmosMsg::Wasm(WasmMsg::Execute {
        contract_addr: account_addr.to_string(),
        msg: to_binary(&account_icg_pkg::msgs::ExecuteMsg::ExecuteMsgs { msgs })?,
        funds,
    })))
}

fn create_salt(storage: &mut dyn Storage, sender: &str, chain: &str) -> StdResult<Binary> {
    let mut hasher = Sha256::new();
    hasher.update(sender.as_bytes());
    hasher.update(chain.as_bytes());

    let config: Config = CONIFG
        .update(storage, |mut config| -> StdResult<Config> {
            config.index_account += 1;
            Ok(config)
        })
        .unwrap();

    hasher.update(config.index_account.to_be_bytes());

    Ok(hasher.finalize().to_vec().into())
}

fn ga_store_pending(
    storage: &mut dyn Storage,
    account_addr: Addr,
    remote_owners: Option<Vec<(String, String)>>,
    local_owners: Option<Vec<String>>,
) -> Result<(), ContractError> {
    if let Some(remote_owners) = remote_owners {
        for (remote_address, remote_chain) in remote_owners.clone() {
            if let Some(GateAccountState::Registered(saved_addr)) =
                GATE_ACCOUNT().may_load(storage, (remote_address.clone(), remote_chain.clone()))?
            {
                return Err(ContractError::AddressWithAccount {
                    address: remote_address,
                    chain: remote_chain,
                    gate_account: saved_addr,
                });
            } else {
                GATE_ACCOUNT().save(
                    storage,
                    (remote_address, remote_chain),
                    &GateAccountState::Pending(account_addr.clone()),
                )?
            };
        }
    }

    if let Some(local_owners) = local_owners {
        for local_owner in local_owners {
            if let Some(GateAccountState::Registered(saved_addr)) = GATE_ACCOUNT()
                .may_load(storage, (local_owner.clone(), LOCAL_CHAIN_NAME.to_string()))?
            {
                return Err(ContractError::AddressWithAccount {
                    address: local_owner,
                    chain: LOCAL_CHAIN_NAME.to_string(),
                    gate_account: saved_addr,
                });
            } else {
                GATE_ACCOUNT().save(
                    storage,
                    (local_owner, LOCAL_CHAIN_NAME.to_string()),
                    &GateAccountState::Pending(account_addr.clone()),
                )?
            };
        }
    }

    Ok(())
}

fn ga_remove_owners(
    storage: &mut dyn Storage,
    account_addr: Addr,
    remote_owners: Option<Vec<(String, String)>>,
    local_owners: Option<Vec<String>>,
) -> Result<(), ContractError> {
    if let Some(remote_owners) = remote_owners {
        for (remote_owner, remote_chain) in remote_owners.clone() {
            if GATE_ACCOUNT()
                .load(storage, (remote_owner.clone(), remote_chain.clone()))?
                .get_addr()
                == account_addr
            {
                GATE_ACCOUNT().remove(storage, (remote_owner, remote_chain))?;
            } else {
                return Err(ContractError::Unauthorized {});
            }
        }
    }

    if let Some(local_owners) = local_owners {
        for local_owner in local_owners {
            if GATE_ACCOUNT()
                .load(storage, (local_owner.clone(), LOCAL_CHAIN_NAME.to_string()))?
                .get_addr()
                == account_addr
            {
                GATE_ACCOUNT().remove(storage, (local_owner, LOCAL_CHAIN_NAME.to_string()))?;
            } else {
                return Err(ContractError::Unauthorized {});
            }
        }
    }

    Ok(())
}
