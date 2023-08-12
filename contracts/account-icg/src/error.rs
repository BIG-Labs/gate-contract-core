use cosmwasm_std::{Addr, StdError};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ContractError {
    #[error("{0}")]
    Std(#[from] StdError),

    #[error("Unauthorized")]
    Unauthorized {},

    #[error("Local owner {addr} alredy registered")]
    LocalOwnerAlredyRegistered { addr: Addr },

    #[error("remote owner {addr} for chain {chain} alredy registered")]
    RemoteOwnerAlredyRegistered { addr: String, chain: String },

    #[error("Local owner {addr} not found")]
    LocalOwnerNotFound { addr: Addr },

    #[error("remote owner {addr} for chain {chain} not found")]
    RemoteOwnerNotFound { addr: String, chain: String },
}
