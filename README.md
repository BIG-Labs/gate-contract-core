# Interchain Gate Core

Interchain Gate Core is a repository containing a series of smart contracts written in CosmWasm using Rust for the Cosmos ecosystem.
The project consists in contracts and packages designed to enable interchain communication using the Gate contract.

## Contracts

| Contract                         | Description                            
|----------------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
[`gate`](./contracts/gate)         | Core contract of interchain Gate                                                                                                                                                           |
[`cw20-icg`](./contracts/cw20-icg) | Exstension of [cw20-base](https://github.com/CosmWasm/cw-plus/tree/main/contracts/cw20-base). It implements the Gate interface, enabling bridge, receiving cw20 token on destination chain |

## Packages

| Packages                            | Crates.io                                                                                                      | Description   
|-------------------------------------|----------------------------------------------------------------------------------------------------------------|------------
[`gate-pkg`](./packages/gate)         | [![cw1 on crates.io](https://img.shields.io/crates/v/gate-pkg.svg)](https://crates.io/crates/gate-pkg)         | Package for `gate` implementation
[`cw20-icg-pkg`](./packages/cw20-icg) | [![cw1 on crates.io](https://img.shields.io/crates/v/cw20-icg-pkg.svg)](https://crates.io/crates/cw20-icg-pkg) | Package for `cw20-icg` implementation

## Purpose

The purpose of this repository is to enable `smart contract` interchain communication within a Cosmos chain. The `gate` contract serves as a core component and offers a range of functionalities to facilitate seamless communication between interconnected chains.

The `gate` contract allows `contracts` within the same chain to send messages to remote `contracts` in other Cosmos chains or perform `queries` on remote chains. It achieves this by leveraging `IBC packets` to securely transfer information between chains. Additionally, the `gate` contract provides support for transferring up to ***one*** native token within the `requests`, allowing the seamless exchange of assets across chains. Multiple `requests` can send different amount of native token, but the channel used to transfer and the denom must be the same.

One notable feature of the `gate` contract is its ability to process multiple `requests` within a single transaction. Developers can include multiple `requests` in a single transaction sent to the gate contract, and all these `requests` will be consolidated into a single IBC packet. This enables multiple executions on the remote chain in an atomic manner, ensuring consistent and reliable interchain interactions.

In situations where a native token needs to pass through an intermediate chain to obtain the correct denomination on the destination chain, the gate contract supports `packet forwarding`. This feature ensures that native tokens can be routed through intermediate chains as needed to ensure the successful transfer of assets to the desired destination chain.

Within the request sent through the gate contract, it is possible to include a fee for the relayer. This fee can be provided from the sender contract as native token. The fee serves as an incentive for relayers to process and forward the request to the destination chain.

The overall goal of the gate contract is to provide a robust and flexible solution for interchain communication for `smart contract`, enabling developers to build complex and interconnected applications within the Cosmos ecosystem.

## Usage

To learn how to use the Interchain Gate Core and integrate it into your own contracts, please refer to the following [document](USAGE.md).

Additionally, you can explore the [inter-chain-gate-plus](https://github.com/Rhaki/inter-chain-gate-plus) repository, which contains deployed examples showcasing the usage of Interchain Gate Core in different scenarios. You can refer to these examples to gain a better understanding of how to integrate and leverage the capabilities of Interchain Gate Core in your own projects.