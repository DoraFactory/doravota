# pqcauth Authz, Gas, and Verification-Budget Hardening

This note records the consensus rules and operator workflow introduced for the
P0 `x/authz` boundary and deterministic ML-DSA gas calibration.

## Authz security rules

`x/authz` is a pre-authorized capability: the granter is intentionally not a
transaction signer each time a grantee submits `MsgExec`. Requiring the granter
to add a new PQC signature to every execution would break unattended
delegation, so pqcauth instead enforces the following rules in Ante after the
SDK signature has been verified:

1. A classic account must revoke all existing authz grants before
   `MsgRegisterKey` or before changing `self_enforced` from false to true.
2. As soon as an H+1 `self_enforced=true` transition is pending, the account
   cannot create another grant. This closes both same-block orderings:
   `MsgGrant -> MsgRegisterKey` and `MsgRegisterKey -> MsgGrant`.
3. A protected granter can create a new grant only for a grantee whose own
   transactions are already PQC-enforced. This means a native ML-DSA account or
   a classic account with an active pqcauth signing key and an effective policy
   that requires pqcauth.
4. Existing grants from a protected granter can be executed only by such a
   PQC-enforced grantee. Nested `MsgExec` messages are checked recursively with
   a fixed depth limit, and a nested `MsgGrant` cannot delegate onward to an
   unsafe account.
5. Existing-grant activation checks use the authz store's granter prefix with
   a pagination limit of one. Ante never performs an unbounded global grant
   scan.

These rules protect account-level Cosmos authz capabilities. Wasm contracts,
IBC application logic, group policies, and other modules that implement their
own authorization remain separate security boundaries and require their own
review.

## Deterministic gas model

Consensus code never derives gas from wall-clock duration. The pqcauth
cryptographic component is:

```text
verification_gas =
    pqcauth_transaction_signatures * signature_verification_gas
  + lifecycle_proofs * proof_verification_gas
```

Normal SDK simulation adds transaction-byte gas, SDK signature gas, message
execution, and store reads/writes. The module exposes the fixed component with:

```bash
dorad query pqcauth estimate-verification-gas \
  --signatures 1 \
  --proofs 0 \
  --node <rpc-address>
```

For a complete transaction estimate, clients should continue using
`/cosmos/tx/v1beta1/simulate` or `--gas auto`, followed by a gas adjustment such
as `1.2` to `1.3`. Simulation counts required pqcauth verifications but skips
the real ML-DSA computation, so estimation does not require access to the PQC
private key.

The app also wraps the SDK v0.55 signature gas consumer so governance cannot
set native ML-DSA verification below the SDK's benchmark-backed default of 750
gas. Native ML-DSA public-key and signature bytes remain charged by
`ConsumeGasForTxSize`. pqcauth's separate transaction-signature and lifecycle
proof floors remain 250,000 gas.

## Deterministic transaction and block verification budgets

Gas and transaction bytes remain the economic controls, while a separate
consensus budget is the final CPU-safety boundary. Every operation that can
reach an expensive post-quantum verification counts once:

- a native SDK ML-DSA signature, including an ML-DSA leaf selected by a
  supported SDK multisig;
- a pqcauth transaction signature;
- a lifecycle key proof; or
- a Recovery v2 recovery signature.

The protocol defaults are 16 verifications per transaction and 400 per block.
Governance may schedule stricter or looser values only within binary absolute
limits, and the per-transaction limit cannot exceed the block limit. Legacy
state that predates these fields maps zero values to the protocol defaults.

Ante rejects an over-budget transaction immediately after bounded structural
decoding and before fees, classic signature verification, or ML-DSA work.
`PrepareProposal` admits only transactions that keep the aggregate within the
block budget. `ProcessProposal` first decodes and counts the complete proposal,
rejecting an over-budget proposal before it performs any signature
verification; only a successful preflight proceeds to the normal Ante replay.
This prevents a malicious proposer from hiding an excessive CPU workload
behind otherwise valid gas and byte declarations.

## Target-hardware calibration

Run the calibration binary on the slowest supported validator hardware:

```bash
go run ./cmd/pqcauth-gas-calibrate \
  --samples 20000 \
  --message-bytes 4096 \
  --block-max-gas 100000000 \
  --block-time 5s \
  --pqc-cpu-budget 0.25 \
  --safety-factor 2
```

The JSON result includes valid/invalid p50, p95, and p99 latency, the safe
verification count per block, the raw gas recommendation, and the protocol
floor. Production parameters should use the highest recommendation measured
across the supported validator hardware set and must be validated with
concurrent invalid-signature and full-block `ProcessProposal` tests.

One development-machine run using 5,000 samples, a 4 KiB sign document,
100,000,000 block gas, a 5 second block interval, a 25% PQC CPU budget, and a
2x safety factor measured a worst p99 of approximately 0.50 ms. It derived a
raw recommendation of about 79,618 gas. The enforced recommendation remained
250,000 gas because the protocol floor is intentionally more conservative.
This result is diagnostic only and must not replace target-validator
calibration.
