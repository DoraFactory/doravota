# PQCAuth emergency scheduling and recovery fixes — 2026-11-01

Historical English summary. Results below belong to the recorded revision, not current release acceptance. Current behavior: [module README](../x/pqcauth/README.md).

Baseline: `8a8b6892a7458f4cfe752332a2b5fe3835fe54ae`; historical implementation: `23dfcf8`. Its automatic emergency-intent classification was subsequently replaced by explicit `emergency_only` for GOV-02. Numeric cutoff and 16/400 budgets below are historical, not current parameters.

## GOV-01

A real MsgServer reproduction queued cutoff 111 at H=100 for activation 110; emergency updates at H=101–109 failed or, for a distant cutoff, incurred a fresh full delay. New `Params.pending_emergency` (protobuf field 20) stores emergency mode, activation and expiry separately. A pure emergency update could activate at H+1 without moving the ordinary plan or its irreversible cutoff.

Non-emergency request fields could match the complete active or pending set. Copying pending restrictions did not activate them early; copying active cutoff 0 did not revoke the committed cutoff. The future ordinary bundle's emergency component was synchronized to the new expiry, or NORMAL if it would already have expired. Governance could not inject internal schedules or expiry. Zero-height export still rejected pending schedules. No account scan/index was added.

This revision's shape-based intent inference and incomplete same-block guard were later corrected; see [GOV-02](PQCAUTH-GOV02-FIXES-20261101.md) and [same-block protection](PQCAUTH-SAMEBLOCK-EMERGENCY-FIX-20261102.md).

## OBS-REC-01

The full-pause structural exception now accepts exactly one top-level `MsgRecoverKey` or `MsgCancelRecovery`, allowing a protected independent payer's required extension. Account/classical signatures, recovery signature, new-key proof, payer authorization, DIRECT and gas/budget checks remained. This did not permit ordinary sends, batches or indirect lifecycle execution, or add multi-signer CLI orchestration.

Nine real signed application cases covered normal/paused, self-funded/ordinary/protected payer and five invalid-signature/proof cases. Failures did not change balances/sequences; later blocks and state audit passed.

## Recorded validation

Go 1.26.10, two workers/packages: 725 test/subtest passes, 14 packages, three explicit simulations, seven Python tests, 906 IBC files, vet and local build passed. GOV-01 included 72 combinations (two pause modes, near/far cutoff, active/pending request and H=101–109), expiry/activation order, direct/stepwise normalization, codec and genesis round trips at H=101/102/109/110/122.

Logs: `/tmp/pqcauth-gov01-review.log`, `/tmp/pqcauth-emergency-gate-release.log`, `/tmp/pqcauth-emergency-gate-release/{unit,simulations}.jsonl`, `/tmp/pqcauth-emergency-{vet,build}.log`. The initial `.../pqcauth-emergency-gate/unit.jsonl` captured a test-code codec compilation failure; it was not a passing result.

Build-only binary: `/tmp/pqcauth-emergency-check-dorad`, SHA-256 `109d30f0eca6a1f6506f23c1234da818c8f3538e4b44ad12d1946401e7e6f6e9`, with `vcs.modified=true`; not a frozen release artifact. Generated state code used gogoproto v1.7.2, not handwritten wire changes.

The default/floor became 750 per verification, without rewriting stored higher prices. This round retained shared 16/400 quotas and did not establish fairness/capacity. No network deployment, new snapshot/load rehearsal, dependency rescan or physical Ledger test was claimed. New persistent scheduling was a coordinated consensus change, not safe for mixed binaries.

[Original detailed record at the documentation-cleanup baseline](https://github.com/DoraFactory/doravota/blob/eb5bbec2a88a36224bd27c5b487f3d726a6bfeda/docs/PQCAUTH-EMERGENCY-FIXES-20261101.md). Original evidence files were not translated or modified.
