# Wasmd v0.70.4 SDK 0.55 compatibility snapshot

Upstream: github.com/CosmWasm/wasmd v0.70.4 (public security-fixed release).
WasmVM remains the official github.com/CosmWasm/wasmvm/v3 v3.0.8; no VM fork.
This directory includes x/wasm non-test sources and embedded fixtures. Upstream
`_test.go` files are not included and are NOT claimed to have passed here.

## Maintained differences
1. Ignore the legacy test_common.go helper importing removed x/params runtime;
   remove its CreateTestInput / TestHandler public aliases.
2. Add WithDeploymentDisabled(), a fixed application keeper option. Reject at
   the shared create / instantiate / migrate entrypoints BEFORE state or VM work.
   Both instantiate forms, nested messages, direct and privileged keeper calls
   converge here. Existing execute/query, genesis import and snapshot restore
   remain available. App.New ALWAYS enables this; no operator bypass flag.

The guard is a chain policy, not a fix for arbitrary existing contract execution
vulnerabilities. Genesis import can restore pre-existing code/contracts; it is
not a transaction upload bypass. Governance changing Nobody alone cannot undo
this guard: re-enabling deployment requires a reviewed binary upgrade.

Historical x/params ParamSet types come from a separate codec-only compatibility
module. No x/params runtime or keeper is restored. Legacy migration must already
have completed in 0.5.0. See app/upgrades/sdk055 for boundary validation.

## Review and maintenance
Dora Vota owns these local differences until an upstream-compatible replacement
is adopted. upstream-files.json lists changed/unchanged/omitted files and module
checksums. upstream-diff.patch is generated against the downloaded v0.70.4 source.
snapshot-sha256.json covers every shipped file except itself. Run
`python3 scripts/verify-wasmd-snapshot.py` from the repository root.
Module-cache checksums do not validate local replacements; use both verifiers.
