# SDK 0.53 baseline-preservation review — 2026-09-12

Historical English summary; not current deployment instructions or a new audit. See the [documentation index](../README.md) for current guidance.

Baseline: tag 0.4.4; working tree based on `917c53b`. This correction preserved existing behavior except required version adaptations, evidenced migration fixes and explicitly approved settings.

Restored the original 0.4.4 upgrade handler/store-loader registration, legacy params governance route and CLI, Ante error/assembly structure, original Wasm capability list, group/export structure and Docker Ledger build support. The 0.4.4 handler body matched after removing the required context adaptation; app/wasm.go matched byte-for-byte.

Required changes retained: SDK 0.53.6 store/service and ABCI interfaces, upgrade/auth PreBlock order, IBC-Go 10.5.0 removal of fee/capability middleware, Wasmd 0.61.14 / WasmVM 3.0.7 integration, source-state preflight and empty-IAVL compatibility. Removed upstream legacy upgrade/IBC proposal handlers were not replaced with invented compatibility behavior.

Approved defaults/policies: minimum gas price 10,000,000,000 peaka; migrated min_deposit_ratio and proposal_cancel_ratio zero; expedited minimum deposit 110,000 DORA. Existing consensus/governance fields retained their source values. Unapproved proposal gas/byte fallback policy was removed.

Go 1.24.7 on Darwin/AMD64: full tests and three explicit ten-block simulations passed. Historical completed upgrade records were recognized by actual SDK PreBlocker without repeated migration. Ledger-tag local compilation, script syntax and diff checks passed. No Linux Docker build, hardware-wallet signing or remote-chain change was performed.

[Source and test evidence manifest](sdk-053-baseline-preservation-evidence-2026-09-12.json). A negative test was corrected to use a genuinely unregistered handler; a nil map value is not handler removal.

[Original detailed record](https://github.com/DoraFactory/doravota/blob/eb5bbec2a88a36224bd27c5b487f3d726a6bfeda/docs/security/sdk-053-baseline-preservation-2026-09-12.md). Raw evidence is unchanged.
