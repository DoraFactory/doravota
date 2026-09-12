# CHANGELOG

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