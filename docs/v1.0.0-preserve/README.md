# 1.0.0 dependency and migration notes

This candidate retains Wasm, IBC, transfer and ICA while upgrading to Cosmos SDK
0.55. It retires the legacy params/group stores only after source-state preflight.
Contract upload, instantiation and migration remain disabled; existing contract
queries and execution remain available.

- Wasmd is pinned to the organization fork recorded in [WASMD-FORK.json](WASMD-FORK.json).
- IBC-Go uses the exact replacement revision in go.mod. Its channel migration
  requires special handling; read [IBC migration policy](../../app/upgrades/sdk055/IBC-MIGRATION.md)
  before changing that dependency.
- Internal host details, execution logs and reviewer materials are maintained
  outside the public source tree. A historical test result does not certify a
  newly built release artifact.

Release validation must bind the source commit, dependency versions, toolchain
and artifact checksum to upgrade, retained-contract and existing-channel tests.

## Parameter policy

Version 1.0.0 intentionally retains these Cosmos SDK v0.55.0 defaults through
the SDK migrations, without an application-level override:

| Parameter | Value on Vota | Meaning |
| --- | --- | --- |
| `staking.KeyRotationFee` | `1000000peaka` (`0.000000000001 DORA`) | Additional validator consensus-key rotation fee, deducted from the operator account's available balance and burned. It is not an additional staking requirement; transaction fees are separate. |
| `auth.SigVerifyCostMlDsa65` | `750` gas | Cost of one ML-DSA-65 signature verification. Transaction byte costs and other operations are charged separately. |

These parameter choices do not activate ML-DSA consensus keys. The consensus
key type remains Ed25519 for this release. Release validation should verify the
resulting on-chain parameter values after migration.
