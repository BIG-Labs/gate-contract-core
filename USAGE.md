# Usage

To implement the `gate` contract interface on your own contract, add the `gate-pkg` on your `Cargo.toml`:

```Toml
[dependencies]
gate-pkg = {version = "0.1.0"}
```

## 1: Permission
It is necessary to register the `permission` on the `Gate` for each contract that wants to receive requests from a specific `chain`.
The `gate` contract will block incoming messages from unwanted addresses.

There are two types of permissions:
```rust
pub enum Permission {
    Permissioned { addresses: Vec<String> }, // Only addresses in this list can send msgs to your contract
    Permissionless,                          // All address can send msgs to your contract
}
```
There are two ways to register `permission`:
- Send a `SetPermission` msg from the contract to the `gate`;
- Send a `SetPermissionFromAdmin` msg from the contract `admin` to the `gate`;

```rust
pub enum ExecuteMsg {
    ...
    SetPermission {
        permission: Permission, // Type of permission
        chain: String,          // Remote chain name, you can query the gate for the registered chain
    },
    SetPermissionFromAdmin {
        contract:Addr,          // Contract to register permission, the sender must be the admin
        permission: Permission,
        chain: String, 
    },
}
```

## 2: Send a request to the gate

Currently, the `gate` supports the following `requests`:

```rust
pub enum GateRequest {
    /// Send a msg to a specific contract in a remote chain.
    /// The contract that should receive the msg has to:
    /// - Set the `Permission` in the `gate` contract (if Permission::Permissioned, the remote `gate` assert if the contract allows to receive msg from the `sender`);
    /// - Handle the `ReceiveGateMsg(GateMsg::ReceviedMsg)` in its `ExecuteMsg` variant
    SendMsg {
        msg: Binary,                         // Binary msg to send
        to_contract: String,                 // Remote contract address to send the msg
        send_native: Option<SendNativeInfo>, // Information about native token to been sent within the request
    },

    /// Perform a list queries in a remote chain.
    /// Once the result returns to the source chain, the gate sends an ExecuteMsg to the requesting contract.
    /// The requesting contract must hanlde the `ReceiveGateMsg(GateMsg::QueryResponse)` in its `ExecuteMsg` variant.
    Query {
        queries: Vec<QueryRequest<Empty>>, // List of queries to be performed
        callback_msg: Option<Binary>,      // Callback msgs that will be return with the QueryResult
    },
}
```

To send a `request` to the `gate`, use the following `ExecuteMsg` variant:

```rust
pub enum ExecuteMsg {
    ...
    /// Send a list of `GateRequests` to a specific chain.
    SendRequests {
        requests: Vec<GateRequest>, // List of requests
        chain: String,              // Destination chain name saved on gate contract
        timeout: Option<u64>,       // Timeout delta (in seconds)
    },
}
```

To send `native token` within a request (if the request type support `native token`), you have to specify the `SendNativeInfo`:

```rust
pub struct SendNativeInfo {
    pub coin: Coin,                           // Amount of coin to be forwarded   
    pub path_middle_forward: Vec<PacketPath>, // List of path for middle packet forwarding
    pub dest_denom: String,                   // Destination denom
    pub channel_id: String,                   // Last channel-id to use to arrive at the destination chain
    pub timeout: Option<u64>,                 // Timeout delta (in seconds)
}
```
In case a `path_middle_forward` is set, the `channel_id` is the last channel to use to send the token to the destination chain.

 Example:
 `A`->`B`->`C`
 - `chain_id` is the channel used on chain `B` to send to chain `C`;
 - `path_middle_forward` will be:

```rust
vec![
     PacketPath{
         channel_id: "channel-A",       // Channel on chain A used to transfer on chain B
         address: "bech32ChainBAddress" // Valid bech32 Address on chain B (any valid address)
     }
]
```

## 3: Fee for relayer

If Some `native token` is sent within the requests, the gate contract perform the following checks:
- Calculate the remaining funds not specified in `send_native` field.
- If the remaining `coins` is **one** and if the denom matches the `base_denom` of the local chain (information saved on the Config of the `gate`).

If all check pass, the `gate` interprets this amount as a `fee` for the `relayer`.

## 4: Add `ReceiveGateMsg` variant in your ExecuteMsg

In your `ExecuteMsg` enum of your contract, insert the following variant: 
  
```rust
pub enum ExecuteMsg {
    ... // Your variants
    ReceiveGateMsg(GateMsg),
}
```

This imports the msgs that the `gate` will send to your contract.

***You should save the correct `gate` contract in your contract state and assert the `info.sender` when this variant is executed***.

`GateMsg` is an enum has the following variations:

```rust
pub enum GateMsg {
    // Called when a contract in a remote chain sends a msg
    ReceiveMsg { 
        sender: String, // Sender address
        msg: Binary,    // Binary msg received
    },

    // Called when a request sent to the gate fails
    RequestFailed {
        request: GateRequest,
    },

    // Receive the responses of the requested queries
    QueryResponse {
        queries: Vec<GateQueryResponse>, // List of queries with the response
        callback_msg: Option<Binary>,    // Binary callback msg
    },

    // Advanced, see below for details
    CollectMsgs {
        sender: Addr,
        msg: Binary,
    },
}
```

- **`ReceiveMsg`**: `Binary` msg received from a remote `sender` (alredy filtered by the `gate` contract).
    The sender is not the wallet that sign the tx, but the contract that send the msg to the `gate` in the remote chain.

    You must to be able to deserialize the `Binary` msg to a known structure/enum.

- **`QueryResponse`**: Response of the queries requested. A `callback_msg` can be set in the request and is returned to help the requesting contract to handle the response.

- **`RequestFailed`**: A request sent to the `gate` fails on destination chain.

    Since the execution on destination chain is not atomic (the `packet` needs to be relayed), if some states are changed within the `msg` that sent the `request` to the `gate`, the fact that the tx fails on the remote chain does not cancel any changes made in this chain. The sender must, therefore, know what to reverse in this case (if a reverse is needed). The sent request is passed to help the revers.

- **`CollectMsgs`**: When the `gate` trigger this GateMsg variant, all request that will be sent to the gate by this exection or any other msgs that this exection triggers, will be stored inside the gate contract instead of beign sent directly.

    Once the entire message is concluded, a single `ibc packet` is prepared containing all the `requests` from the various contracts.

    This is used when your contract needs to send a `request` to a remote chain along with `requests` from other contracts.

    An example would be bridging a loan position with some CW20 tokens as collateral. The contract that stores the loan position needs to send a bridge request to all collaterals (assuming they are cw20-icg) and a `request` to the `gate` containing the loan information.

    When the bridge `request` is sent to the cw20-icg, the token will send a `request` to the `gate`, but it will be stored inside the gate. When all `requests` arrive, the gate sends all of them in one `ibc packet`. This allows performing all the `requests` atomically in the destination chain, and if one `request` fails, all of them fail.

    To use this feature, similar to `ExecuteMsg::Send` for cw20 tokens, the user has to send the msg with the bridge position request (in `binary`) to the `gate` contract. At this point, the `gate` starts recording the requests and sends the collectMsg to the specified contract on behalf of the user.




