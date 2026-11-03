# SDK 0.53 change-necessity review — 2026-09-12

Historical English summary; not current deployment instructions or a new audit. See the [documentation index](../README.md) for current guidance.

Compared 0.4.4 with `917c53b650afdc592873e956b32e41fa720e97a5` and subsequent local corrections. Upstream examples were not treated as authorization to enable optional features.

Removed the extra custom proposal policy, gas/byte overrides, observed-parameter fallback, transfer/ICA callbacks and IBC v2 business routes. Kept required interfaces, cumulative migrations, source consensus reads, empty-IAVL compatibility and pre-deletion checks. Restored solo-machine registration/routing and the historical feeibc account's bank-send restriction.

Retained approved minimum gas price 10,000,000,000 peaka and migration overrides: min_deposit_ratio=0, proposal_cancel_ratio=0, expedited deposit=110,000 DORA. Ordinary governance values remained intact. Incompatible expedited constraints were rejected, not repaired by changing ordinary policy.

No protocolpool, epochs, unordered transactions or PQC functionality was enabled in this bridge. The msgpack replace retained a specific upstream truncated-extension-frame bounds fix; this did not certify all dependencies.

[Change provenance CSV](sdk-053-change-provenance-2026-09-12.csv) classified 376 changed files: 338 documentation/evidence, 19 node/CLI, nine dependency/build, eight tests and two offline tools. File/line totals did not represent equal quantities of runtime code.

Go 1.24.7/Darwin full tests and three explicit ten-block simulations passed. Tests covered SDK default proposal handling, unchanged source consensus values, real gov migration with preserved old fields, conflicting-policy rejection, IBC routes and read-only preflight. [Evidence](sdk-053-necessity-review-evidence-2026-09-12.json).

Later same-day corrections restored the original historical handler, params governance route, Wasm capability list, Ante structure and Docker Ledger configuration; [baseline preservation](sdk-053-baseline-preservation-2026-09-12.md) takes precedence over intermediate choices here.

New wiring/policy invalidated reuse of old RC acceptance. Final Linux builds, snapshot, legacy IBC/Wasm business, physical-wallet and long-running tests were still needed. Offline database tools must run on stopped copies, not live production stores.

[Original detailed record](https://github.com/DoraFactory/doravota/blob/eb5bbec2a88a36224bd27c5b487f3d726a6bfeda/docs/security/sdk-053-necessity-review-2026-09-12.md). Raw evidence is unchanged.
