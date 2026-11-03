# PQCAuth parameter simplification — 2026-11-02

Historical English summary. Results belong to the recorded revision, not current release acceptance. Current behavior: [module README](../x/pqcauth/README.md).

## Implementation

Baseline: `a63c69a8912efb5a342dc7a408898f9e1598e07f`.

Removed the 16-per-transaction and 400-per-block verification quotas, budget tracker/decorator, custom proposal selection and dependent-signer filtering, and retired fresh-registration capture. Prepare/ProcessProposal returned to SDK defaults. Classical/PQC authentication, canonical decoding, structure checks and gas charging remain.

The deleted quotas were conservative application settings, not SDK requirements or benchmark-derived limits. SDK `tx_sig_limit` is governable; a real 17-leaf native multisig test with an increased SDK limit passed. Default NoOp ProcessProposal is not complete Ante authentication; FinalizeBlock still authenticates.

## Parameter and compatibility boundaries

- Three mutable settings remain: enforcement mode, verification gas and emergency mode.
- Network ID and three delay settings are immutable after initialization.
- Only ML-DSA-65 is supported. Extension limits are fixed at eight entries / 64 KiB, with independent wire preflight limits of 32 entries / 256 KiB.
- Terminal key-history retention is fixed at 16 records per role.
- Registration mode/cutoff were removed. Enforcement accepts OPTIONAL and REQUIRED_FOR_REGISTERED.
- Unified verification gas defaults to 750. A governance price-capacity check against a finite block gas limit remains; it is not a verification-count quota or a promise about total transaction gas.
- Explicit emergency intent and same-block protections were retained.

Retired protobuf field numbers are reserved. Params reserves 3–9, 16, 18 and 19; unified gas uses 21. ScheduledParams reserves 2–8 and 11–13; unified gas uses 14. QueryParamsResponse reserves field 4.

Module version 4 rejects unsupported experimental versions 1–3 rather than silently migrating old two-price state. The supported production entry remains pre-PQCAuth v1.0.1.

## Recorded checks and limits

Go 1.26.10: 773 passing test/subtest events across 14 packages, three simulations, seven Python tests, 906 IBC source checks, vet, build and race checks. Tests included a 402-transaction mixed block exceeding the removed quota, SDK signature-limit behavior, lifecycle payer authentication and descriptor reservations.

Shared-host microbenchmarks for a 256-byte message recorded SDK verification at 80.7–84.2 µs and wrapper verification at 77.6–84.4 µs. These were not pinned target-hardware capacity measurements.

Direct ABCI tests of 5,000 seven-signer transactions recorded 8.655 s first admission and 1.697/1.814/1.645 s recheck. Each transaction was 25,687 bytes and consumed 586,770 gas, unchanged on recheck. This was not a real network mempool benchmark.

Local evidence: `/tmp/pqcauth-simplify.qFvtC8/`, including gate, vet, race, crypto-benchmark and recheck-5000 logs. Development binary SHA-256:

```text
08be69d5aea979d31ac258f7c79e27aca30a3e41a41cdbb03481d8c3749004fe
```

Local socket restrictions prevented four-node acceptance in this round. The new isolated capacity script and CI integration were not evidence that capacity had passed. Later results are recorded in [VAL-01](PQCAUTH-VAL01-FIX-20261102.md) and [network acceptance](PQCAUTH-NETWORK-ACCEPTANCE-20261102.md).

[Original detailed record](https://github.com/DoraFactory/doravota/blob/eb5bbec2a88a36224bd27c5b487f3d726a6bfeda/docs/PQCAUTH-SIMPLIFICATION-20261102.md). Raw evidence was not modified.
