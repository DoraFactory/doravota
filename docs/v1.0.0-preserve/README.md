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
