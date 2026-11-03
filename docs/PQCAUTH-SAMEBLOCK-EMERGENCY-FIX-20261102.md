# PQCAuth same-block emergency guard — 2026-11-02

Historical English summary. Results below belong to the recorded revision, not current release acceptance. Current behavior: [module README](../x/pqcauth/README.md).

Baseline: `59dddd8dc25c289f969b2b9d6a9b2d18eab072ef`. Finding G-1: without an ordinary pending plan, a same-block full update could overwrite a newly queued pause.

## Change and governance semantics

Move assignment of `PendingEmergency` to the common exit of both scheduling branches before `SetParams`. Every explicit emergency-only update is now guarded until H+1. Existing validation accepts equal ordinary/emergency activation heights. No new protobuf field, store prefix or scan was added. Gas and cryptography were unchanged.

| Sequence | Result |
| --- | --- |
| Separate proposals, emergency-only then full update in one block | Emergency succeeds; full update fails; pause activates at H+1. |
| Same proposal, emergency-only then full update | Second message fails; entire proposal including pause rolls back. |
| Full update then emergency-only | Both may succeed; original ordinary plan retains its activation. |
| Full update after emergency activation | Same-block guard no longer blocks it; other checks still apply. |
| Later explicit emergency-only in the same block | Authorized replacement/renewal/release follows message order. |

Use separate proposals for pauses. Failed proposals are not retried automatically: re-query and submit a new proposal after activation. H+1 is an execution boundary, not a promise that a fresh vote completes in one block. Old experimental states lacking the marker are not retroactively repaired by this patch; mixed binaries are not supported.

## Recorded validation

Claude's original probe was run unchanged via overlay: both baseline cases lost the pause; fixed cases returned `wait for the H+1 emergency activation` and activated PAUSE_PQC_TRANSACTIONS at H=101.

- Baseline probe: `/tmp/pqcauth-round7-review.aiiieW/probe.log`.
- Fixed probe: `/tmp/pqcauth-sameblock-claude-probe-fixed-20261102.log`.
- Keeper: 12 full-update rejection combinations plus six explicit emergency replacements; rejected writes, response state, H+1 clearing, expiry and normalization checked.
- Application: 20 updated EndBlock ordering/rollback cases plus four ordering/resubmission cases. Two real signed submit/deposit/vote cases retained atomic rollback and balance/sequence assertions.
- Genesis export/import covered both scheduling branches; critical tests became mandatory gates.

Go 1.26.10, two workers/packages: 794 test/subtest passes, 14 packages, three separately enabled simulations, seven Python tests, 906 IBC files, vet and build passed. Build `/tmp/dorad-pqcauth-sameblock-20261102` was only a development compile check, not a frozen release.

Logs use `/tmp/pqcauth-sameblock-`: `targeted-20261102.log`, `export-20261102.log`, `gate-20261102.log`, `gate-20261102/{unit,simulations}.jsonl`, `vet-20261102.log`, `build-20261102.log`.

| Evidence | SHA-256 |
| --- | --- |
| Fixed Claude probe log | `18a38c0781a4e7eeb60738489c21f918cd20b3bfac50bbfbd5a7332821155527` |
| unit.jsonl | `318129987d09df62e10503f58799f09269d43812e16f9d36e896c583dc078ca7` |
| simulations.jsonl | `e889ffbbf2444ddf7d4944c914fa5ed48b26867748501a69331b5534cfc2888e` |

No new multi-node snapshot, target-hardware load or public-testnet work was claimed. Numeric cutoff and quota references in original tests describe that historical revision.

[Original detailed record at the documentation-cleanup baseline](https://github.com/DoraFactory/doravota/blob/eb5bbec2a88a36224bd27c5b487f3d726a6bfeda/docs/PQCAUTH-SAMEBLOCK-EMERGENCY-FIX-20261102.md). Original evidence files were not translated or modified.
