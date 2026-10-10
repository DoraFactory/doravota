# CHANGELOG

## [Unreleased]

## [v1.0.0]
Coordinated upgrade from 0.5.0. Release tag and binary version: `v1.0.0`; governance upgrade plan and Cosmovisor directory: `1.0.0`.
- Upgrade to Cosmos SDK 0.55.0 and CometBFT 0.40.0. Existing consensus key types remain unchanged; this release does not activate ML-DSA consensus or add a custom pqcauth module.
- Add SDK-native ML-DSA account support. New accounts use hash-derived uint64 account numbers (at least 2^63); integrations must preserve full integer precision. See docs/CLIENT-1.0.0.md.
- Remove Wasm execution and all wasmd/wasmvm dependencies. Preserve the original Wasm store with read-only raw-state queries; smart queries, contract execution, withdrawals and NAV writes stop.
- Close non-closed Wasm-port IBC channels locally during migration without calling contracts. Retain packet records without settlement or refunds. Ordinary IBC transfer and ICA channels/state remain supported.
- Use the exact pinned IBC-Go v11 development commit recorded in go.mod; this is not an IBC-Go v11.2.0 stable release.
- Delete deprecated group and params stores, including group data, without an emptiness prerequisite. Preserve historical message decoding, not execution.
- Migrate IBC channel sequences with pre/post checks and retain their values. Pin the compatible LevelDB implementation to preserve empty-value semantics.
- Initialize ML-DSA verification gas to 750, consensus key rotation fee to 1000000 peaka, and mint max_supply to 0 (no supply cap). Keep the new consensus authority unset; normal module governance remains in effect. Preserve existing inflation and governance parameters.
- Distribute verified static Linux amd64 artifacts with source commit and SHA-256. Consult docs/VALIDATOR-1.0.0.md for upgrade and archive-query limitations.
- Require the historical Wasm codec, authorization and governance regression tests to execute in Linux CI; skipped or missing required tests fail validation.

## [0.5.0]
Dora Vota 0.5.0. The application version and on-chain upgrade plan name are `0.5.0`.

### Upgrade from 0.4.5
- Upgrade to Cosmos SDK 0.53.6, CometBFT 0.38.21 and IBC-Go 10.5.0, with updated CosmWasm dependencies, built with Go 1.24.7. Exact dependency versions are recorded in `go.mod` and the binary build information.
- Use the exact on-chain plan name `0.5.0` and Cosmovisor path `cosmovisor/upgrades/0.5.0/bin/dorad`.
- Preserve existing consensus and module parameter values during migration. Initialize the new governance fields with `min_deposit_ratio=0`, `proposal_cancel_ratio=0` and expedited minimum deposit of 110,000 DORA. The expedited voting period is 23 hours and threshold is 0.667; preflight checks compatibility with existing governance parameters.
- Preserve historical upgrade handlers and production behavior except required SDK/IBC/Wasmd compatibility and reviewed safety fixes. Remove obsolete capability and ICS-29 stores only after migration preflight passes.
- Set the new-node minimum gas price default to `10000000000peaka`. Existing operator configuration is not overwritten.
- Include empty IAVL restart compatibility, ICA wiring/CLI corrections and SDK startup/configuration compatibility.

### Artifacts and validation
- Distribute a static Linux amd64 binary with its SHA-256 checksum. Verify the binary version, embedded commit and checksum before deployment.
- Preserve existing upload and instantiation permissions during migration.
- Use the newly distributed artifact and checksum even if a previously staged binary also reports `0.5.0`.
- Verify migration prerequisites before the upgrade and prepare a manual binary-switch procedure if automatic switching fails.
- Validate the final artifact before distribution. After it commits upgraded state, do not start a 0.4.x binary against the same database.

## [0.5.0-rc.1] - 2026-09-12
Release candidate for long-running testnet validation; not approved for mainnet deployment.

### Upgrade
- Bridge the 0.4.4 state to Cosmos SDK 0.53.6, CometBFT 0.38.21, IBC-Go 10.5.0, Wasmd 0.61.14 and WasmVM 3.0.7.
- Retain the on-chain upgrade plan name `sdk-v0.53-bridge`.
- Validate legacy stores and migration prerequisites before loading the upgrade boundary; preserve legacy empty IAVL restart compatibility.
- Correct ICA middleware and CLI configuration, SDK genesis loading, release identity and module CLI address codecs.
- Add Linux static artifact checks, explicit simulations and snapshot rehearsal evidence.

### Validation scope
- Isolated snapshot upgrades, controlled-counterparty in-flight ICS-20 transfers, ICA and selected existing aMACI operations have passed on the preceding candidate.
- Full business proof/tally/settlement, long-running testnet acceptance and final mainnet readiness remain required. See `docs/upgrades/sdk-053-mainnet-upgrade-plan.md`.

## [0.4.4] - 2026-02-26
This is a non-consensus breaking patch to the 0.4.0 release line.
### Update
Align CLI wasm store validation with the chain's 3MB wasm code limit by initializing wasm size overrides on CLI paths as well.

## [0.4.3] - 2025-05-22
This is a patch to the 0.4.0 release line.
### Update
Bump Cosmos SDK from `v0.47.16` to `v0.47.17` to resolve [ISA-2025-002](https://github.com/cosmos/cosmos-sdk/security/advisories/GHSA-47ww-ff84-4jrg) security advisory.

## [0.4.2] - 2025-02-26
This is a consensus breaking patch to the 0.4.0 release line.
### Update
Bump Cosmos SDK from `v0.47.15` to `v0.47.16` to resolve [ASA-2025-003](https://github.com/advisories/GHSA-x5vx-95h7-rv4p) security advisory.

## [0.4.1] - 2024-12-17
This is a non-consensus breaking patch to the 0.4.0 release line.
### Update
Bump Cosmos SDK from `v0.47.10` to `v0.47.15` to resolve [ABS-0043/ABS-0044](https://github.com/cosmos/cosmos-sdk/security/advisories/GHSA-8wcc-m6j2-qxvm) security advisory.
