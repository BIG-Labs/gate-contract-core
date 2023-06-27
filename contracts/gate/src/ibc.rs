use cosmwasm_std::{
    attr, entry_point, DepsMut, Env, Ibc3ChannelOpenResponse, IbcBasicResponse, IbcChannel,
    IbcChannelCloseMsg, IbcChannelConnectMsg, IbcChannelOpenMsg, IbcPacketAckMsg,
    IbcPacketReceiveMsg, IbcPacketTimeoutMsg, IbcReceiveResponse, Never,
};
use gate_pkg::ChannelInfo;

use crate::{
    error::ContractError,
    on_dest, on_src,
    state::{CHANNEL_INFO, ICG_ORDERING, ICG_VERSION},
};

#[entry_point]
/// Enforces ordering and versioning constraints
pub fn ibc_channel_open(
    _deps: DepsMut,
    _env: Env,
    msg: IbcChannelOpenMsg,
) -> Result<Option<Ibc3ChannelOpenResponse>, ContractError> {
    assert_order_and_version(msg.channel(), msg.counterparty_version())?;
    Ok(Some(Ibc3ChannelOpenResponse {
        version: msg.channel().version.clone(),
    }))
}

/// Not handled yet
/// Should the contract remove the channel from the storage?
#[entry_point]
pub fn ibc_channel_close(
    _deps: DepsMut,
    _env: Env,
    _channel: IbcChannelCloseMsg,
) -> Result<IbcBasicResponse, ContractError> {
    unimplemented!();
}

#[entry_point]
/// Record the channel in CHANNEL_INFO
pub fn ibc_channel_connect(
    deps: DepsMut,
    _env: Env,
    msg: IbcChannelConnectMsg,
) -> Result<IbcBasicResponse, ContractError> {
    assert_order_and_version(msg.channel(), msg.counterparty_version())?;

    let channel: IbcChannel = msg.into();

    let info = ChannelInfo {
        src_channel_id: channel.endpoint.channel_id,
        dest_channel_id: channel.counterparty_endpoint.channel_id,
        dest_port_id: channel.counterparty_endpoint.port_id,
        connection_id: channel.connection_id,
        base_denom: None,
        voucher_contract: None,
    };

    CHANNEL_INFO.save(deps.storage, info.clone().src_channel_id, &info)?;

    Ok(IbcBasicResponse::default())
}

#[entry_point]
/// Receive a ibc packet.
/// packet.data will be deserialized into GatePacket.
/// If the packet contain `SendNativeInfo`, we store the packet and set into the ack the key for this packet (it will be executed when the contract will receives the native token).
/// Otherwise we proceed executing the `Requests` contained in the packet.
pub fn ibc_packet_receive(
    deps: DepsMut,
    env: Env,
    msg: IbcPacketReceiveMsg,
) -> Result<IbcReceiveResponse, Never> {
    let packet = msg.packet;

    on_dest::run_ibc_packet_receive(deps.storage, env, packet, msg.relayer).or_else(|err| {
        Ok(IbcReceiveResponse::new()
            .set_ack(on_dest::set_ack_fail(deps.storage, err.to_string()))
            .add_attributes(vec![
                attr("action", "receive"),
                attr("success", "false"),
                attr("error", err.to_string()),
            ]))
    })
}

#[entry_point]
/// Matching the result in ack.data with `AckType` and execute the variant
pub fn ibc_packet_ack(
    deps: DepsMut,
    env: Env,
    msg: IbcPacketAckMsg,
) -> Result<IbcBasicResponse, ContractError> {
    on_src::run_on_ack_receive(deps, env, msg)
}

#[entry_point]
/// Same case handled on `ibc_packet_ack` in `Error` scenario
pub fn ibc_packet_timeout(
    deps: DepsMut,
    _env: Env,
    msg: IbcPacketTimeoutMsg,
) -> Result<IbcBasicResponse, ContractError> {
    on_src::run_on_ack_timeout(deps.storage, msg)
}

// --- FUNCTIONS ---

fn assert_order_and_version(
    channel: &IbcChannel,
    counterparty_version: Option<&str>,
) -> Result<(), ContractError> {
    if channel.version != ICG_VERSION {
        return Err(ContractError::InvalidIbcVersion {
            version: channel.version.clone(),
        });
    }
    if let Some(version) = counterparty_version {
        if version != ICG_VERSION {
            return Err(ContractError::InvalidIbcVersion {
                version: version.to_string(),
            });
        }
    }
    if channel.order != ICG_ORDERING {
        return Err(ContractError::OnlyUnorderedChannel {});
    }
    Ok(())
}
