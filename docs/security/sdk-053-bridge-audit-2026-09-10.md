# SDK 0.53 bridge security review — 2026-09-10

Historical English summary; not current deployment instructions or a new audit. See the [documentation index](../README.md) for current guidance.

Baseline: 0.4.4 `1b0774785111d8a6e693cd155053c19a5a1d8bdc`; reviewed bridge: `6d03e3b7f80b485cbc2e10665657056e8613e5de`. The historical on-chain plan was sdk-v0.53-bridge, not the Git branch name.

This was a cross-version SDK/Comet/IBC/Wasmd/WasmVM migration, not PQC account or validator-consensus support. The review did **not** recommend scheduling mainnet activation at that point.

| Finding | Historical evidence / release condition |
| --- | --- |
| F1: feeibc deletion | Outstanding ICS-29 escrow records/balances could be stranded. Require verified empty state or a designed settlement before deletion. Later fixed-height inspection found no such funds at that height only. |
| F2: empty-IAVL compatibility | A real GoLevelDB sample failed to load when upgrade-info.json was missing/replaced. Compatibility must not depend on that temporary local file. |
| F3: release toolchain | Old Go/WasmVM release settings did not match dependencies. Actual matching Linux artifacts needed building and execution. |
| F4: duplicate ICA middleware | Conditional duplicate callbacks required wiring correction and old-state regression; universal ICA failure was not proved. |
| F5: simulation evidence | Explicit determinism testing stopped on a shared Wasm-cache lock. This was not a demonstrated AppHash divergence. |
| F6: proposal policy | Added finite gas/byte fallbacks and selection rules were policy changes, not mandatory SDK adaptation. |
| F7: source-state acceptance | Version-map checks, real snapshot migration and preserved business invariants were not yet established. |

Ordinary full tests passed; the empty-root probe reproduced the defect; explicit determinism did not finish. Linux artifacts, production-snapshot recovery and deployed-contract compatibility were not tested in this round. Logs: [default tests](sdk-053-bridge-tests.log) and [simulation](sdk-053-bridge-simulation.log).

[Mainnet store inspection](mainnet-store-check-2026-09-10.md) subsequently narrowed F1. [Fixes](sdk-053-bridge-fixes-2026-09-11.md), [preflight](sdk-053-preflight-ci-2026-09-11.md) and [baseline preservation](sdk-053-baseline-preservation-2026-09-12.md) record later changes.

Safety boundary: never reopen committed migrated state with an old binary, reset signing state, or duplicate validator keys to bypass a failure. Recovery must coordinate application/Comet data and validator signing state. Matching new-node hashes and business invariants matter; migration need not preserve the old AppHash.

[Original detailed record](https://github.com/DoraFactory/doravota/blob/eb5bbec2a88a36224bd27c5b487f3d726a6bfeda/docs/security/sdk-053-bridge-audit-2026-09-10.md). Raw evidence is unchanged.
