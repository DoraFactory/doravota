# Sponsor Contract Transaction Module - Community Review

## Overview

We want to develop a **Sponsor Contract Transaction Module** (`x/sponsor-contract-tx`) that enables smart contracts to automatically sponsor transaction fees for their users. This module addresses the cold start problem in Web3 applications where new users need tokens to interact with cosmwasm smart contracts on cosmos ecosystem.

## Motivation & Background

### The Problem

Current fee payment mechanisms in Cosmos ecosystem have some significant limitations:

1. **Fee Grant Limitations**: Cosmos SDK's native fee grant module requires knowing the grantee address beforehand, making it unsuitable for onboarding new users who haven't interacted with the chain yet.

2. **Security Concerns**: The current fee grant module for contract message sponsorship may be abused because the granularity of fee grant sponsored transactions is at the module level(like: `/cosmwasm.wasm.v1.MsgExecuteContract`). Therefore, for contracts, it only supports wasm messages, which can lead to a user sponsored by contract A consuming on contract B, resulting in abuse.

### Our Solution

We propose a dedicated module that:

- Maintains a registry of sponsorship-enabled contracts
- Implements policy-based sponsorship through contract queries
- Ensures transaction integrity through strict validation rules

## Architecture & Implementation

### Core Components

#### 1. Contract Registry

- **Purpose**: Track which contracts are authorized to sponsor transactions.
- **Structure**: Maps contract addresses to sponsorship status
- **Access Control**: Only contract admins can register/modify sponsorship settings

#### 2. AnteHandler Integration

- **Position**: Placed before fee deduction in the ante handler chain
- **Function**: Validates sponsored transactions and pre-transfers funds
- **Fee-Flow**: Contract → User → Standard fee deduction

#### 3. Policy Enforcement

- **Mechanism**: Contracts must implement a `CheckPolicy` query method
- **Purpose**: Allow contracts to define custom sponsorship criteria (whitelist, usage limits, etc.)
- **Flexibility**: Each contract can implement its own business logic

> Because there is a contract query within the module, which consumes a certain amount of gas, the `query_gas_limit` parameter of node config needs to be adjusted according to the specific contract business to support contract queries.

### Transaction Flow

```
1. User submits transaction to sponsored contract
2. SponsorAnteHandler validates transaction structure
3. Query contract's CheckPolicy method for user eligibility
4. If approved: Contract transfers fee amount to user
5. Standard fee deduction proceeds normally
6. Transaction executes
```

## Security Model

### Strict Transaction Validation

To prevent fee leeching attacks, we enforce rigid transaction structure rules:

**✅ ALLOWED**: Single contract, multiple messages

```
[
    MsgExecuteContract{Contract: "sponsored_contractA"},
    MsgExecuteContract{Contract: "sponsored_contractA"}, // Same contract
    MsgExecuteContract{Contract: "sponsored_contractA"}  // Same contract
]
```

**❌ REJECTED**: Mixed message types

```
[
    MsgExecuteContract{Contract: "sponsored_contract"},
    MsgSend{},           // Trying to piggyback on sponsorship
    MsgDelegate{}        // Trying to piggyback on sponsorship
]
```

**❌ REJECTED**: Multiple different contracts

```
[
    MsgExecuteContract{Contract: "sponsored_contract_A"},
    MsgExecuteContract{Contract: "sponsored_contract_B"} // Different contract
]
```

### Access Control

- **Registration**: Only contract admin can register/update sponsorship status
- **Validation**: Admin ownership is verified through wasm keeper queries
- **Immutability**: Sponsorship settings cannot be modified by unauthorized parties

## Design Decisions

Our chosen approach transfers funds from contract to user before fee deduction:

- ✅ Preserves existing fee validation logic
- ✅ Maintains transaction integrity
- ✅ Enables standard fee deduction flow
- ✅ Compatible with existing signature schemes

### Gas Consumption Considerations

Policy queries consume gas during ante handler execution:

- **Trade-off**: Flexibility vs. gas efficiency
- **Mitigation**: Contracts should implement efficient policy checks
- **Alternative**: Simple boolean flags for basic use cases

## Attention

### 1. **Cosmos Account Initialization**

- **Problem**: Accounts must exist on-chain to have sequence numbers
- **Impact**: Completely new users cannot send transactions
- **Solution**: Separate account activation service (when new user first interacts with the service, they can obtain minimal token airdrop, like 1peaka)


### 2. **Contract Policy Dependency**

- **Risk**: Policy query failures could block legitimate transactions
- **Mitigation**: Graceful fallback to non-sponsored execution
- **Requirement**: All sponsored contracts must implement `CheckPolicy`


## Security Considerations

1. **Admin Verification**: Critical for preventing unauthorized sponsorship registration
2. **Policy Validation**: Contracts must implement secure policy logic
3. **Fund Management**: Contracts need sufficient balance monitoring
4. **Abuse Prevention**: Strict transaction structure validation

## Community Questions

We would appreciate community feedback on:

1. **Architecture Review**: Is the overall design sound and secure?
2. **Security Analysis**: Are there attack vectors we haven't considered?
3. **Integration Concerns**: How might this affect other modules or chains?
4. **Performance Impact**: Are there optimization opportunities?
5. **Alternative Approaches**: Are there better solutions to this problem?

## Implementation Status

- ✅ Core module implementation
- ✅ AnteHandler integration
- ✅ Admin verification system
- ✅ Policy query mechanism
- ✅ Initial testing
- 🔄 Community review (current phase)
- 🔄 Module under improvement. (current phase)


## Test Module/Contract

1. clone git repo
```shell=
git clone https://github.com/DoraFactory/doravota.git && git checkout sponsor-contract-tx
```
2. compile codebase
```shell=
make build
```
3. Set up a simple local network.
5. We implemented a [counter contract](https://github.com/DoraFactory/doravota/tree/sponsor-contract-tx/contracts/counter) with a whitelist feature, allowing only those on the whitelist to count, used to test the sponsor-contract-tx module.


## Usage Example

```go
// Register a contract for sponsorship (only admin can do this)
dorad tx sponsor set-sponsor [contract-address] true --from [admin-key]

// Query sponsorship status
dorad query sponsor is-sponsored [contract-address]

// User sends sponsored transaction (automatically handled)
dorad tx wasm execute [contract-address] '<CONTRACT_FUNCTION>' --from [user-key]
```

## Conclusion

This module provides a secure, flexible solution for contract-sponsored transactions while maintaining compatibility with existing Cosmos SDK patterns. We believe it addresses a real need in the ecosystem but welcome community scrutiny to identify potential improvements or concerns.

**We specifically seek feedback on:**

- Security implications and potential attack vectors
- Integration compatibility with current Cosmos modules
- Performance and gas efficiency considerations
- Alternative design approaches



完整的check流程：
  🎯 使用流程
  1. 用户提交投票交易
  2. Module检查: 用户还有没有grant额度
  3. 合约检查: 投票时间、用户资格、是否已投票
  4. 两者都通过: 转账并扣减用户额度
  5. 任何一个失败: 拒绝交易


TODO list:
- sposnor转账和update user usage limit的顺序，可能需要处理一下，这里有可能会导致用户先收到转账，但是费用不足以支付update的钱
- 如果用户是被准许的，可以先check用户是否有足够的钱，如果有足够的钱支付gas fee的话，我们就不进行grant，也就是说，我们只会sponsor给不足以支付gas fee的用户，如果用户是合规的，但是自己本身有足够的钱，我们还是不会给他sponsor
- client增加设置和更新max_grant_per_user的参数
- 用户只能设置DORA和peaka两种单位，其他token单位是不支持的