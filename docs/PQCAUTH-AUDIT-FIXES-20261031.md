# PQCAuth audit fixes — 2026-10-31

Historical English summary. Results below belong to the recorded revision, not current release acceptance. Current behavior: [module README](../x/pqcauth/README.md).

Baseline: `d3099314cbb14ff7c5a10e167e1c1b0e780ffe12`. Findings: P2-A, P2-B, F1–F3. This round predates fixed extension caps and removal of verification-count quotas.

## Changes at that revision

- P2-A: compute the minimum extension size with generated protobuf `Size()`, maximum-width fields, 1,023-byte address input and complete ML-DSA signatures. Validate active, pending, genesis and governance values. Boundary tests cover 2/8/32 entries; these synthetic structures are not authenticated accounts.
- P2-B/F3: require at least two PQC signers, three verifications per transaction, transaction budget at least signer limit, and block budget at least transaction budget. Defaults remained 8 signers, 64 KiB, 16/transaction and 400/block. Native multisig tests: 2/3 leaves fit minimum settings, 4 did not; 7 fit defaults.
- F2: on governance price/budget changes, require `max(signature_price, proof_price) × transaction_budget < finite block.max_gas`, using overflow-safe comparison. No dynamic BeginBlock failure; emergency/cancellation paths stay available. This was a sanity check, not full gas estimation.
- F1: registration, enabling protection and later recovery print Authz/Feegrant warnings and query commands to stderr. No automatic enumeration, revocation, index or enrollment prerequisite was added.

Real signed application tests covered registration, rotation, recovery and protection changes with an independent protected payer. Invalid proposals did not write pending state. Existing poisoning, activation and sequence-dependency assertions remained.

## Recorded validation

14 packages, 582 test/subtest pass events, three separately enabled simulations, seven Python tests and 906 pinned IBC files passed. Build, vet and diff checks passed. A 500-malformed-proposal overlay passed, followed by valid transactions and state audit. Twenty-second fuzz runs completed 101,342 extension and 2,031 crypto executions.

The synthetic four-validator run recorded 92 successes and six expected rejections; final height 112 agreed across nodes. It was not a mainnet snapshot, public IBC or physical Ledger test.

- Logs: `build/test-results-audit-fixes/`, `build/test-results-audit-closeout/`.
- Network evidence: `/tmp/doravota-audit-fixes.RVEimp/four-validator/evidence/result.json` and `history-restart-agreement.json`.
- Binary: `/tmp/doravota-audit-fixes.RVEimp/dorad`.
- Binary SHA-256: `e96689e7ad06acf1239087c8a921ba29eaae2dc3b3347f90216dbeb1209476d6`.

Claude re-reviewed `a2de29d3ede7a2aefd1551543dd7b8a5e2fd391f` and closed the five findings within that review's scope. The original report hashes were `3bf03061e45a4b03d1947d7077ed476531985ce48f7bb426484c69be22cff69f` (initial) and `f5bdc495d9ed52ec12e99cb08995e020f3ccc366454a7ec335cd88d7a2a91f9f` (with re-review). These identify the original documents, not this English summary. Later CLI/documentation closeout was locally tested, not independently re-audited.

## Subsequent fresh-account simulation fix

At `967cd07`, an SDK empty secp256k1 simulation placeholder was incorrectly compared with a funded account's address before its public key had been stored. Only trusted simulation with no known key was exempted; arbitrary nonempty mismatches and malformed native keys remained rejected. CheckTx and proposal/execution paths remained strict.

Regression gates included `TestBudgetSimulationPlaceholderIsolation`, `TestPQCAuthFreshClassicSDKDryRun` and `TestPQCAuthProtectedSimulationVersusDeliveryGas`. Recorded result: 585 pass events, 14 packages, three simulations, seven Python tests, 906 IBC files and vet passed. Logs: `/tmp/pqcauth-simulation-fix-gate-20261101/` and the matching `.log`. No new network rehearsal was claimed for this patch.

Direct-only is a protocol/client support boundary, not an ML-DSA limitation. Amino support requires a separately reviewed signing and wallet design. Supported production input remained pre-PQC v1.0.1; incompatible experimental databases required a separate migration.

[Original detailed record at the documentation-cleanup baseline](https://github.com/DoraFactory/doravota/blob/eb5bbec2a88a36224bd27c5b487f3d726a6bfeda/docs/PQCAUTH-AUDIT-FIXES-20261031.md). Original evidence files were not translated or modified.
