# PQCAuth integration with v1.0.1 — 2026-10-30

Historical English summary. Results belong to the recorded revision, not current release acceptance. Current behavior: [module README](../x/pqcauth/README.md).

## Revision and compatibility scope

PQCAuth revision `9c68a78cfc143a80a94bc6a5e8a5d478321ccc42` was merged with released v1.0.1 `39759f09a438ebc0e1fdc4b6af748a1d7d03e142`, producing `31766d43fe4a1663ef4c093840b4cded3aab473f`.

The merge preserved the two pinned IBC Amino compatibility patches and 906 source checks, DIRECT behavior, routes and stores. The supported production ordering required v1.0.1 first; the PQC candidate was not a substitute for executing the historical v1.0.1 handler. Fresh genesis chains had a separate activation marker.

The feegrant index present in this round was removed later; this report is not current module behavior.

## Recorded isolated results

Tests ran in network-disabled containers on an isolated operator host, without public transactions or production-node changes.

- 568 passing test/subtest events across 14 packages; three explicit simulations, vet and build.
- Sequential v1.0.1/PQC upgrades, early-install rejection, transfers and restart.
- Four-validator lifecycle: 86 successful transactions, six expected rejections, 40 mixed transfers over four rounds, and agreement after an offline node rejoined.
- A clean build of the fixed merge was rerun through the sequential upgrade. Candidate SHA-256: `b85ef656dac4e71a5ad7bd39fad4d333c1e6e0d0bbb4654a20aed6601d3957d6`.

Evidence: [summary](pqcauth-v101-evidence/summary.json) and [fixed result](pqcauth-v101-evidence/fixed-result.json). Original working records: `/root/pqcauth-v101-integration-20261030/` and `/Users/bun/DoraFactory/review-records/pqcauth-v101-integration-20261030/`.

CI run 41024158290 had passing tests but still-running builds when this report was written; it did not claim completed CI. No final snapshot, public IBC, physical-wallet or production deployment acceptance was established.

[Original detailed record](https://github.com/DoraFactory/doravota/blob/eb5bbec2a88a36224bd27c5b487f3d726a6bfeda/docs/PQCAUTH-V101-INTEGRATION-20261030.md). Raw evidence was not modified.
