use cosmwasm_schema::{cw_serde, QueryResponses};
use cosmwasm_std::{
    to_binary, Addr, Binary, Coin, CosmosMsg, Empty, QueryRequest, StdError, StdResult, Uint128,
    WasmMsg,
};
use cw20::Cw20ReceiveMsg;

#[cw_serde]
pub enum ExecuteMsg {
    /// This msg allow to to gather and collect all `Requests` received during the execution of the binary msg passed.
    ///
    /// The gate contract send the Binary msg to the contract specified.
    ///
    /// The contract have to handle the `ReceiveGateMsg(GateMsg::CollectRequest)` variant.
    CollectRequests { to_contract: Addr, msg: Binary },

    /// Send a list of `GateRequests` to a specific chain.
    SendRequests {
        requests: Vec<GateRequest>,
        chain: String,
        timeout: Option<u64>,
    },

    /// Register the `Permission` for the contract that execute this msg.
    SetPermission {
        permission: Permission,
        chain: String,
    },

    /// Register the `Permission` for a specific contract. The sender of the msg has to be the admin of the contract.
    SetPermissionFromAdmin {
        contract: Addr,
        permission: Permission,
        chain: String,
    },

    #[cfg(feature = "gate")]
    SetVoucherPermission {
        chain: String,
        local_voucher_contract: Addr,
        remote_voucher_contract: String,
    },

    #[cfg(feature = "gate")]
    RegisterChainAndChannel {
        chain: String,
        src_channel: String,
        base_denom: String,
    },

    #[cfg(feature = "gate")]
    Receive(Cw20ReceiveMsg),

    #[cfg(feature = "gate")]
    IbcHook(IbcHookMsg),

    #[cfg(feature = "gate")]
    PrivateSendCollectedMsgs,

    #[cfg(feature = "gate")]
    PrivateRemoteExecuteRequests {
        requests_infos: Vec<GateRequestsInfo>,
        native_denom: Option<String>,
        from_chain: String,
    },

    #[cfg(feature = "gate")]
    PrivateRemoteExecuteQuery {
        queries: Vec<QueryRequest<Empty>>,
        from_contract: String,
        callback_msg: Option<Binary>,
    },
}

#[cw_serde]
#[derive(QueryResponses)]
pub enum QueryMsg {
    #[returns(Permission)]
    /// Return the `Permission` registered for a specific contract.
    Permission { contract: Addr, chain: String },
    #[returns(ChannelInfo)]
    /// Return the `ChannelInfo` for a registered chain.
    ChannelInfo { chain: String },
    #[returns(Config)]
    /// Return the `Config`.
    Config {},
}

#[cfg(feature = "gate")]
#[cw_serde]
pub enum IbcHookMsg {
    ExecutePendingRequest { channel: String, sequence: u64 },
}

#[cw_serde]
pub enum GateMsg {
    /// Receive msg from a remote chain
    ReceivedMsg {
        sender: String,
        msg: Binary,
    },
    RequestFailed {
        request: GateRequest,
    },
    /// Receive the answer of a previously requested query
    QueryResponse {
        queries: Vec<GateQueryResponse>,
        callback_msg: Option<Binary>,
    },
    CollectRequests {
        sender: Addr,
        msg: Binary,
    },
}

#[cfg(feature = "gate")]
impl GateMsg {
    /// serializes the message
    pub fn into_binary(self) -> StdResult<Binary> {
        let msg = ReceiverExecuteMsg::ReceiveGateMsg(self);
        to_binary(&msg)
    }

    /// creates a cosmos_msg sending this struct to the named contract
    pub fn into_cosmos_msg<T: Into<String>>(
        self,
        contract_addr: T,
        funds: Vec<Coin>,
    ) -> StdResult<CosmosMsg> {
        let msg = self.into_binary()?;
        let execute = WasmMsg::Execute {
            contract_addr: contract_addr.into(),
            msg,
            funds,
        };
        Ok(execute.into())
    }
}

#[cw_serde]
pub enum ReceiverExecuteMsg {
    ReceiveGateMsg(GateMsg),
}

#[cw_serde]
pub struct Config {
    pub controller: Addr,
    pub default_timeout: u64,
    pub default_gas_limit: Option<u64>,
    pub cw20_icg_code_id: u64,
    pub voucher_contract: Option<String>,
    pub base_denom: String,
    /// When a Packet fails on destination chain, the gate on set a `max_gas` for every `RequestFailed` msg.
    pub max_gas_amount_per_revert: u64,
}

/// Permission type for contract to receive a `SendMsg` request.
#[cw_serde]
pub enum Permission {
    /// Only from a list of address.
    Permissioned { addresses: Vec<String> },
    /// From any address.
    Permissionless {},
}

/// List of Request that can be forwarded to the `gate`.
#[cw_serde]
pub enum GateRequest {
    /// Send a msg to a specific contract in a remote chain.
    /// The contract that should receive has to:
    /// - Set the `Permission` in the `gate` contract (if Permission::Permissioned, the remote `gate` assert if the contract allows to receive msg from the `sender`);
    /// - Handle the `ReceiveGateMsg(GateMsg::ReceviedMsg)` in its `ExecuteMsg` variant
    SendMsg {
        msg: Binary,
        to_contract: String,
        send_native: Option<SendNativeInfo>,
    },

    /// Perform a list queries in a remote chain.
    /// Once the result returns to the source chain, the gate sends an ExecuteMsg to the requesting contract.
    /// The requesting contract must hanlde the `ReceiveGateMsg(GateMsg::QueryResponse)` in its `ExecuteMsg` variant.
    Query {
        queries: Vec<QueryRequest<Empty>>,
        callback_msg: Option<Binary>,
    },
}
impl GateRequest {
    pub fn send_native(&self) -> Option<SendNativeInfo> {
        match self {
            GateRequest::SendMsg {
                send_native: native_token,
                ..
            } => native_token.clone(),
            GateRequest::Query { .. } => None,
        }
    }
}

#[cw_serde]
#[non_exhaustive]
#[cfg(feature = "gate")]
pub struct GateRequestsInfo {
    pub requests: Vec<GateRequest>,
    pub sender: String,
    pub fee: Option<Coin>,
    pub send_native: Option<SendNativeInfo>,
}

#[cfg(feature = "gate")]
impl GateRequestsInfo {
    pub fn new(
        requests: Vec<GateRequest>,
        sender: String,
        sended_funds: Vec<Coin>,
        base_denom: String,
    ) -> StdResult<GateRequestsInfo> {
        let mut new_send_native_info: Option<SendNativeInfo> = None;

        // Merge all SendNativeInfo in one and assert path and denom
        for request in requests.clone() {
            new_send_native_info = merge_send_native(&new_send_native_info, &request.send_native())?
        }

        let mut fee: Option<Coin> = None;

        // Based on the received funds, assert the fees and the native
        for fund in sended_funds {
            let mut var_amount = fund.amount;
            if let Some(ref with_native) = new_send_native_info {
                if with_native.coin.denom == fund.denom {
                    var_amount -= with_native.coin.amount;
                }
            }

            if base_denom.clone() == fund.denom && var_amount > Uint128::zero() {
                fee = Some(Coin {
                    denom: base_denom.clone(),
                    amount: var_amount,
                });
                var_amount = Uint128::zero()
            }

            if !var_amount.is_zero() {
                return Err(StdError::generic_err(format!(
                    "Denom {} recevied but not used",
                    fund.denom
                )));
            }
        }
        Ok(GateRequestsInfo {
            requests,
            sender,
            fee,
            send_native: new_send_native_info,
        })
    }
}

/// Information about the send of native token with `Requests`.
/// `path_middle_forward` allow to use the packet_forwarding in case the native token has to step in one or more intermediary chains.
///
/// `channel_id` specify the channel to use to transfer the tokens.
/// In case a `path_middle_forward` is setted, the `channel_id` is the last channel to use to send the token to the destination chain.
///
/// Example:
/// `A`->`B`->`C`
/// - `chain_id` is the channel used on chain `B` to send to chain `C`;
/// - `path_middle_forward` will be:
///
/// ```ignore
/// vec![
///     PacketPath{
///         channel_id: "channel-A",       // Channel on chain A used to transfer on chain B
///         address: "bech32ChainBAddress" // Valid bech32 Address on chain B (any valid address)
///     }
/// ]
/// ```
#[cw_serde]
pub struct SendNativeInfo {
    pub coin: Coin,
    pub path_middle_forward: Vec<PacketPath>,
    pub dest_denom: String,
    pub channel_id: String,
    pub timeout: Option<u64>,
}

impl SendNativeInfo {
    pub fn get_first_channel(self) -> String {
        match self.path_middle_forward.first() {
            Some(first) => first.channel_id.to_owned(),
            None => self.channel_id,
        }
    }
}

#[cw_serde]
pub struct PacketPath {
    /// Channel opened to `transfer` port
    pub channel_id: String,
    /// Chain `denom` saved in `gate` contract
    pub address: String,
}

#[cw_serde]
pub struct GateQueryResponse {
    pub request: QueryRequest<Empty>,
    pub response: Binary,
}

#[cw_serde]
pub struct QueryRequestInfoResponse {
    pub queries: Vec<GateQueryResponse>,
    pub from_contract: String,
    pub callback_msg: Option<Binary>,
}

#[cw_serde]
pub struct ChannelInfo {
    /// id of this channel
    pub src_channel_id: String,
    /// the remote port we connect to
    pub dest_port_id: String,
    /// the remote channel we connect to
    pub dest_channel_id: String,
    /// the connection this exists on (you can use to query client/consensus info)
    pub connection_id: String,
    /// base denom of remote chain
    pub base_denom: Option<String>,
    /// base denom of remote chain
    pub voucher_contract: Option<String>,
}

impl ChannelInfo {
    pub fn get_remote_gate(self) -> StdResult<String> {
        let slice: Vec<&str> = self.dest_port_id.split('.').collect();

        if slice.len() != 2 {
            return Err(StdError::generic_err("dest_port_id is invalid"));
        }

        return Ok(slice.last().unwrap().to_string());
    }
}

/// --- FUNCTIONS ---

#[cfg(feature = "gate")]
pub fn merge_send_native(
    from: &Option<SendNativeInfo>,
    with: &Option<SendNativeInfo>,
) -> StdResult<Option<SendNativeInfo>> {
    match from {
        Some(from) => match with.clone() {
            Some(with) => {
                if from.coin.denom != with.coin.denom {
                    return Err(StdError::generic_err("Multiple native coin denom detected"));
                }

                if from.path_middle_forward != with.path_middle_forward {
                    return Err(StdError::generic_err(
                        "Multiple path_middle_forward detected",
                    ));
                }

                if from.dest_denom != with.dest_denom {
                    return Err(StdError::generic_err("Multiple dest_denom detected"));
                }

                if from.channel_id != with.channel_id {
                    return Err(StdError::generic_err("Multiple channel_id detected"));
                }

                Ok(Some(SendNativeInfo {
                    coin: Coin {
                        denom: from.coin.denom.clone(),
                        amount: from.coin.amount + with.coin.amount,
                    },
                    path_middle_forward: from.path_middle_forward.clone(),
                    dest_denom: from.dest_denom.clone(),
                    channel_id: from.channel_id.clone(),
                    timeout: lowest_timeout(from.timeout, with.timeout)?,
                }))
            }
            None => Ok(Some(from.to_owned())),
        },
        None => Ok(with.to_owned()),
    }
}

#[cfg(feature = "gate")]
pub fn lowest_timeout(from: Option<u64>, with: Option<u64>) -> StdResult<Option<u64>> {
    match from {
        Some(from) => match with {
            Some(with) => {
                if with > from {
                    Ok(Some(from))
                } else {
                    Ok(Some(with))
                }
            }
            None => Ok(Some(from)),
        },
        None => Ok(with),
    }
}
