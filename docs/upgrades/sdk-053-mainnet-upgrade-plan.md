# Historical SDK 0.53 upgrade plan

Historical English summary. Results apply only to the recorded artifact and environment; see the [documentation index](../README.md) for current guidance.

This is an archive of the September 2026 plan for **0.4.4 → SDK 0.53**, not an instruction to downgrade or deploy today's candidate. Later releases have their own [validator](../VALIDATOR-1.0.0.md) and [v1.0.1](../VALIDATOR-1.0.1.md) guidance; PQCAuth uses its [current rollout plan](../PQCAUTH-ROLLOUT-PLAN.md).

## Historical identity and scope

Final naming decision: binary/tag/plan/Cosmovisor directory 0.5.0; prerelease designation during long-term testnet acceptance. Earlier RC c529f8d used sdk-v0.53-bridge and could not execute the renamed plan. Its hashes and tests were not interchangeable with later builds.

The bridge targeted SDK 0.53.6, Comet 0.38.21, IBC-Go 10.5.0, Wasmd 0.61.14 and WasmVM 3.0.7. It did not introduce PQC accounts or validator signatures.

The scope was corrected to retain original behavior: required interfaces/migrations and evidenced fixes remained; custom proposal fallback policy, optional callbacks and IBC v2 business routes were removed. Approved governance overrides and restored historical handlers/capabilities are described in the [baseline review](../security/sdk-053-baseline-preservation-2026-09-12.md).

## Release gates

1. Inventory exact source state, software/hardware, validators by voting power, contracts, channels, permissions and operational owners.
2. Close known defects and pass ordinary tests plus explicitly enabled simulations.
3. Freeze source/toolchain/native libraries and verify actual target-architecture binaries, metadata and hashes.
4. Restore a consistent source snapshot into an isolated network using test keys. Record every synthetic checkpoint change; do not substitute a fresh genesis for migration.
5. Run the real upgrade boundary and compare business invariants and same-height hashes across new nodes. A legitimate migration can change the old AppHash.
6. Exercise restarts, missing plan files, interruption, offline-node return and tested snapshot/backup recovery. Preserve signing-state safety.
7. Complete applicable wallet/relayer/Wasm/IBC, sustained-load and stability acceptance; recheck mainnet fee state, balances, versions, parameters and in-flight governance immediately before scheduling.
8. Coordinate all validators, with strictly more than two-thirds ready voting power plus margin, exact plan/artifact identity, monitoring and an agreed incident procedure.

The plan proposed at least 1,000 post-upgrade blocks **and** 24 hours of observation; proposals are not evidence those targets were achieved. Long unbonding and other delayed events needed separate cases.

Source preflight had to inspect feeibc and its balances **before** StoreLoader deletion. Nonempty state required an explicit settlement/migration design, not manual clearing. Historic zero-state evidence did not guarantee future H−1 state.

Recovery was not a universal rollback command: after committing migrated state, do not reopen it with 0.4.4, reset signing records or run duplicate validator identities. A failing node and a coordinated chain-wide recovery are different operations.

## Evidence and exceptions

- [Old-version baseline](snapshot-rehearsal-2026-09-11.md)
- [Initial snapshot migration and recovery](sdk-053-snapshot-upgrade-2026-09-11.md)
- [In-flight packets and Wasm](sdk-053-inflight-wasm-2026-09-11.md)
- [Legacy asset/NFT preservation](sdk-053-legacy-assets-check-2026-09-11.md)
- [RC1 artifact/state-sync tests](sdk-053-rc1-2026-09-12.md)
- [Final d37fa73 snapshot/ICA/restart](sdk-053-final-d37fa73-2026-09-12.md)
- [Fixed-height governance preflight](../security/sdk-053-mainnet-gov-check-2026-09-12.md)

Controlled new counterparties did not establish end-to-end old Cosmos Hub/Osmosis/Noble paths. Full channel-16 NFT business and old INIT handshake recovery were explicitly deferred; historical contracts/assets still had to be preserved. Expired clients and small balances were not permission to delete channels.

The d37fa73 run bypassed voting delays in an isolated checkpoint and did not prove real governance voting, final CI artifacts, production Wasm or sustained capacity. No status in this archive authorizes a current mainnet release, tag, governance proposal or deployment.

[Original detailed record](https://github.com/DoraFactory/doravota/blob/eb5bbec2a88a36224bd27c5b487f3d726a6bfeda/docs/upgrades/sdk-053-mainnet-upgrade-plan.md). Raw evidence is unchanged.
