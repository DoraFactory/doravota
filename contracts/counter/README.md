# Counter Contract with Whitelist Policy

This is a CosmWasm smart contract that implements a counter with whitelist-based policy control for sponsored transactions.

## Features

### Basic Counter Operations

- **Increment**: Increase counter by 1 (requires user to be in whitelist)
- **Decrement**: Decrease counter by 1 (no whitelist required)
- **Reset**: Set counter to specific value (only owner)

### Whitelist Management

- **AddToWhitelist**: Add user to whitelist (only owner)
- **RemoveFromWhitelist**: Remove user from whitelist (only owner)

### Policy Queries

- **CheckPolicy**: Check if user is eligible for sponsored transactions
- **IsWhitelisted**: Check if user is in whitelist
- **GetCount**: Get current counter value

## Integration with Sponsor Module

This contract integrates with the Cosmos SDK sponsor module to enable sponsored transactions with policy-based eligibility checks.

### How it Works

1. **Sponsor Configuration**: The contract address is configured as a sponsored contract in the sponsor module
2. **Policy Check**: When a user tries to execute an `Increment` transaction, the ante handler calls the contract's `CheckPolicy` query
3. **Eligibility Verification**: The contract checks if the user is in the whitelist
4. **Fee Sponsorship**: If eligible, the contract's account pays the transaction fee instead of the user

### AnteHandler Flow

```
Transaction -> AnteHandler -> CheckPolicy Query -> Contract -> Whitelist Check
     |                                                              |
     v                                                              v
If eligible: Contract pays fee                           If not eligible: User self pay(Standard deduct fee process)
```

## Usage

### Deploy and Initialize

```bash
# Deploy the contract
dorad tx wasm store counter.wasm --from owner --gas auto --gas-adjustment 1.3

# Instantiate with initial count
dorad tx wasm instantiate 1 '{"initial_count": 0}' --from owner --label "counter" --gas auto --gas-adjustment 1.3
```

### Whitelist Management

```bash
# Add user to whitelist (only owner)
dorad tx wasm execute <CONTRACT_ADDRESS> '{"add_to_whitelist": {"address": "dora1..."}}' --from owner --gas auto

# Remove user from whitelist (only owner)
dorad tx wasm execute <CONTRACT_ADDRESS> '{"remove_from_whitelist": {"address": "dora1..."}}' --from owner --gas auto
```

### Query Operations

```bash
# Check if user is whitelisted
dorad query wasm contract-state smart <CONTRACT_ADDRESS> '{"is_whitelisted": {"address": "dora1..."}}'

# Check policy eligibility (used by ante handler)
dorad query wasm contract-state smart <CONTRACT_ADDRESS> '{"check_policy": {"address": "dora1..."}}'

# Get current count
dorad query wasm contract-state smart <CONTRACT_ADDRESS> '{"get_count": {}}'
```

### Execute Operations

```bash
# Increment counter (requires whitelist)
dorad tx wasm execute <CONTRACT_ADDRESS> '{"increment": {}}' --from user --gas auto

# Decrement counter (no whitelist required)
dorad tx wasm execute <CONTRACT_ADDRESS> '{"decrement": {}}' --from user --gas auto

# Reset counter (only owner)
dorad tx wasm execute <CONTRACT_ADDRESS> '{"reset": {"count": 10}}' --from owner --gas auto
```

## Sponsor Module Integration

### Configure Sponsored Contract

```bash
# Set contract as sponsored
dorad tx sponsor set-sponsor <CONTRACT_ADDRESS> true --from owner --gas auto

# Check if contract is sponsored
dorad query sponsor is-sponsored <CONTRACT_ADDRESS>
```

### Sponsored Transaction Flow

1. User executes `increment` transaction
2. Ante handler detects sponsored contract
3. Ante handler calls `CheckPolicy` query with user address
4. Contract checks whitelist and returns eligibility
5. If eligible, contract account pays transaction fee
6. If not eligible, transaction is rejected

## Error Handling

The contract includes comprehensive error handling:

- `NotWhitelisted`: User is not in whitelist
- `AlreadyWhitelisted`: User is already in whitelist
- `Unauthorized`: Only owner can manage whitelist
- `InvalidAddress`: Invalid address format

## Testing

Run the test suite:

```bash
cd contracts/counter
cargo test
```

The tests cover:

- Basic counter operations
- Whitelist management
- Policy queries
- Authorization checks
- Error conditions

## Security Considerations

1. **Owner Control**: Only the contract owner can manage the whitelist
2. **Policy Enforcement**: Increment operations require whitelist membership
3. **Graceful Degradation**: If policy checks fail, transactions continue with normal validation
4. **Event Logging**: All sponsored transactions are logged with policy check results

## Events

The contract emits events for tracking:

- `sponsored_tx`: Emitted when a transaction is sponsored
  - `contract_address`: The contract address
  - `sponsor_address`: The sponsor account address
  - `user_address`: The user address
  - `policy_check`: "passed" if policy check succeeded
