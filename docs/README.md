# Documentation

Start with the version-specific guides below. Dated audit and rehearsal reports
are historical evidence, not current configuration or deployment instructions.
Passing tests on an older artifact do not approve a newer release.

## Current guides

| Topic | Document |
| --- | --- |
| PQCAuth candidate: behavior, parameters and CLI | [Module README](../x/pqcauth/README.md) |
| PQCAuth phase-one scope and release gates | [Rollout plan](PQCAUTH-ROLLOUT-PLAN.md) |
| v1.0.1 coordinated validator upgrade | [Validator guide](VALIDATOR-1.0.1.md) |
| v1.0.0 validator/client compatibility | [Validator](VALIDATOR-1.0.0.md), [client](CLIENT-1.0.0.md), [release](RELEASE-v1.0.0.md) |
| Archived Wasm behavior | [Wasm retirement](WASM-RETIREMENT.md) |

The PQCAuth candidate has three mutable policy fields and no separate
per-transaction/per-block verification-count quota. Registration is open unless
paused. Older reports mentioning 16/400 quotas, mutable extension caps, registration
cutoffs, two verification prices or global REQUIRED describe retired designs.
Use the module README rather than copying those historical settings.

## PQCAuth review and test history

| Area | Records |
| --- | --- |
| Initial integration and validation | [Integration](PQCAUTH-INTEGRATION.md), [2026-10-20 validation](PQCAUTH-VALIDATION-20261020.md) |
| Initial module fixes and follow-up | [Module fixes](PQCAUTH-MODULE-FIXES-20261027.md), [follow-up](PQCAUTH-FOLLOWUP-20261027.md) |
| v1.0.1 integration | [Integration rehearsal](PQCAUTH-V101-INTEGRATION-20261030.md) |
| Initial independent audit | [Audit/re-review](PQCAUTH-CLAUDE-AUDIT-20261031.md), [fixes](PQCAUTH-AUDIT-FIXES-20261031.md) |
| Shared audit and dependency/proposal follow-up | [Shared findings](PQCAUTH-SHARED-AUDIT-FIXES-20261101.md), [round four](PQCAUTH-ROUND4-FIXES-20261101.md) |
| Governance/emergency fixes | [Independent scheduling/recovery](PQCAUTH-EMERGENCY-FIXES-20261101.md), [explicit intent](PQCAUTH-GOV02-FIXES-20261101.md), [same-block protection](PQCAUTH-SAMEBLOCK-EMERGENCY-FIX-20261102.md) |
| Gas, recheck and parameter decisions | [750 alignment](PQCAUTH-GAS-ALIGNMENT-20261101.md), [recheck](PQCAUTH-RECHECK-FIXES-20261102.md), [launch settings](PQCAUTH-LAUNCH-SETTINGS-20261102.md), [simplification](PQCAUTH-SIMPLIFICATION-20261102.md) |
| Historical governance/load fixtures | [Governance and load](PQCAUTH-GOVERNANCE-LOAD-TESTS-20261102.md) |
| Snapshot upgrade | [2026-11-01 fixed-artifact rehearsal](PQCAUTH-SNAPSHOT-REHEARSAL-20261101.md) |
| Network tools and acceptance limits | [VAL-01](PQCAUTH-VAL01-FIX-20261102.md), [port isolation](PQCAUTH-REHEARSAL-PORTS-20261102.md), [network acceptance](PQCAUTH-NETWORK-ACCEPTANCE-20261102.md), [restart CheckTx](PQCAUTH-RESTART-CHECKTX-20261103.md) |
| Offline key-target checks | [Recovery record](PQCAUTH-RECOVERY-TARGET-20261103.json), [rotation record](PQCAUTH-ROTATION-TARGET-20261103.json) |

Test/subtest pass events are not counts of independent security properties.
Direct ABCI probes, shortened test delays, synthetic balances and controlled
counterparties must not be presented as production network acceptance. Target
hardware capacity work is deferred to the intended testnet, not declared passed.

## IBC Amino compatibility history

- [Initial two-file upstream patch and validation](ibc-amino-compat/IMPLEMENTATION-REPORT.md)
- [v1.0.1 activation and four-validator rehearsal](ibc-amino-compat/UPGRADE-REPORT.md)
- [Pinned patch](ibc-amino-compat/upstream.patch) and [source manifest](ibc-amino-compat/upstream-manifest.json)

## SDK 0.53 historical archive

These September 2026 documents describe the old 0.4.4 bridge upgrade. They are
retained for migration provenance, fixed-height state checks and recovery evidence;
their versions, endpoint observations and release status are not current advice.

### Reviews

- [Bridge audit](security/sdk-053-bridge-audit-2026-09-10.md)
- [Mainnet fee/capability state](security/mainnet-store-check-2026-09-10.md)
- [Bridge fixes](security/sdk-053-bridge-fixes-2026-09-11.md)
- [Preflight and candidate CI](security/sdk-053-preflight-ci-2026-09-11.md)
- [Change necessity](security/sdk-053-necessity-review-2026-09-12.md)
- [Baseline preservation](security/sdk-053-baseline-preservation-2026-09-12.md)
- [Configuration review](security/sdk-053-config-review-2026-09-12.md)
- [Parameter checklist](security/sdk-053-parameter-checklist-d37fa73.md)
- [Mainnet governance check](security/sdk-053-mainnet-gov-check-2026-09-12.md)

### Rehearsals

- [Historical upgrade plan](upgrades/sdk-053-mainnet-upgrade-plan.md)
- [0.4.4 snapshot baseline](upgrades/snapshot-rehearsal-2026-09-11.md)
- [Snapshot migration/recovery](upgrades/sdk-053-snapshot-upgrade-2026-09-11.md)
- [In-flight IBC and Wasm](upgrades/sdk-053-inflight-wasm-2026-09-11.md)
- [Legacy assets/NFT state](upgrades/sdk-053-legacy-assets-check-2026-09-11.md)
- [RC1 artifact/state-sync validation](upgrades/sdk-053-rc1-2026-09-12.md)
- [d37fa73 snapshot/ICA/restart](upgrades/sdk-053-final-d37fa73-2026-09-12.md)
- [Raw rehearsal evidence index](upgrades/sdk-053-rehearsal-evidence/README.md)

## Evidence and cleanup policy

The November 2026 cleanup converted Chinese Markdown reports into explicitly
labeled English summaries. Each summary links to the detailed original at fixed
commit `eb5bbec2a88a36224bd27c5b487f3d726a6bfeda`. No tests were rerun merely by
translating a report; original report hashes refer to those originals, not summaries.

Raw JSON/CSV, logs, scripts, response files and checksum manifests are preserved
byte-for-byte. In particular, the historical configuration-diff CSV/JSON retain
their original Chinese annotations to preserve evidence identity. They are data,
not current operator guides. Old `/tmp`, workstation and remote-host paths identify
where evidence was recorded; this repository does not guarantee those paths still
exist. Historical scripts must not be replayed against a live node home.

Two superseded documents were removed from the working tree:

- [Original audit handoff](https://github.com/DoraFactory/doravota/blob/eb5bbec2a88a36224bd27c5b487f3d726a6bfeda/docs/PQCAUTH-AUDIT-HANDOFF-20261031.md): a rolling status aggregation, replaced by this index, the module README and topic-specific reports.
- [Original pending parameter decisions](https://github.com/DoraFactory/doravota/blob/eb5bbec2a88a36224bd27c5b487f3d726a6bfeda/docs/PQCAUTH-PARAMETER-DECISIONS-20261102.md): superseded by the launch-settings and simplification records.

Both remain recoverable from Git history. No raw audit/rehearsal evidence was
deleted. `docs.go`, `static/` and `template/` are application-embedded API assets,
not obsolete audit notes, and remain unchanged.
