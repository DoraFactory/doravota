# PQCAuth historical snapshot rehearsal — 2026-11-01

Historical English summary. Results belong to the recorded revision, not current release acceptance. Current behavior: [module README](../x/pqcauth/README.md).

## Fixed inputs

Candidate: `b3f289d3882e495c6c1d8ad08f44ce8979a1c842`, then module version 3 and Go 1.26.5. This is not acceptance evidence for a later version-4 candidate.

Snapshot: `doravota_2026-11-01_18029707_snap.tar.lz4`, height 18,029,707; compressed size 4,977,990,807 bytes, extracted size 7,070,452,244 bytes.

```text
Snapshot SHA-256:
680b7c73deb36aacce4ba2158064e50bef0be9d78286cc286070dd8cd2f5b59b
Database AppHash:
7D3C5D5DCC4C1D0E16785B45DC93E18BDF19646DCBC312EF3D4D28F093C67B93
Candidate binary SHA-256:
120968a45d6ade0da1efc78c4745197f43a5e0e2051759844cba27f8723a228f
```

The archive hash was locally computed, not a vendor signature. Header comparison with two RPC sources was not light-client verification.

## Isolated execution

Docker networking was disabled. Only test validator keys and copied databases were used; no production home was modified. A synthetic checkpoint at 18,029,708 changed only account/authz/bank/gov/slashing/staking state needed by the rehearsal; other store roots were preserved.

The copied network upgraded to v1.0.1 at 18,029,778 and the PQC candidate at 18,029,848. Two forced interruptions exercised replay: one after upgrade start, one after finalization but before commit. Restart without upgrade-info succeeded. With one node stopped, three advanced; the fourth rejoined with matching state at 18,029,866.

Eight transactions covered two proposals, two delegated votes and four transfers. Existing Wasm, IBC, feegrant and authz store roots were checked for preservation.

## Resource and evidence boundaries

The container had four CPU cores and a 12 GiB memory limit, with per-process GOMAXPROCS=2 and GOMEMLIMIT=2 GiB. Combined process RSS peaked near 916 MiB, but cgroup usage including cache reached the 12 GiB limit and reclaimed memory; OOM count was zero. This is not evidence that production needs only 1 GiB RAM or that minimum physical hardware passed.

Evidence: [snapshot evidence directory](upgrades/pqcauth-phase1-snapshot-20261101/), including source manifest/RPC proof, fork report, result, final agreement, post-upgrade roots and summary. Original local evidence was under `/tmp/doravota-snapshot-20261101.hj0o2X/evidence/`.

This did not test power loss, disk corruption, cross-machine behavior, public IBC or physical wallets. Later source/dependency changes require a new final-artifact rehearsal.

[Original detailed record](https://github.com/DoraFactory/doravota/blob/eb5bbec2a88a36224bd27c5b487f3d726a6bfeda/docs/PQCAUTH-SNAPSHOT-REHEARSAL-20261101.md). Raw evidence was not modified.
