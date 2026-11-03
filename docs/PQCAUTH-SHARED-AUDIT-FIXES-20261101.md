# PQCAuth shared-review fixes — 2026-11-01

Historical English summary. Results below belong to the recorded revision, not current release acceptance. Current behavior: [module README](../x/pqcauth/README.md).

Baseline: `3890a193981cac6f034c7e4094bfdb0d4e5e2790`; implementation: `c292744`. Its prefix selector, registration modes and unresolved dependency status are historical; see the later [round-four record](PQCAUTH-ROUND4-FIXES-20261101.md) and [simplification](PQCAUTH-SIMPLIFICATION-20261102.md).

## Findings addressed

| Finding | Change and boundary |
| --- | --- |
| PQC-01 | Zero-copy wire preflight walks TxRaw → TxBody → Any before generated decoding. Reject over 256 KiB / 32 entries, duplicates, truncation and unsupported group wire types, including noncritical options. Later canonical/cryptographic checks remain. |
| PQC-02 | Reject FRESH_ACCOUNTS_ONLY in active/pending/genesis/governance and execution. OPEN/CLOSED were retained at this revision. This removed the supported trigger, not implemented a persistent safe-retry protocol. |
| PQC-03 | Registration requires DIRECT for all signers; CLI rejects non-direct and the SDK's Amino-only Ledger backend. Ordinary unprotected Amino transactions remain unaffected. |
| PQC-04 | Stop at a structurally valid over-budget candidate to preserve the selected prefix. This was later replaced because it could delay independent transactions. |
| PQC-05 | Audit effective current signing/recovery references for matching ID, role and validity; report `inactive_current_key`. Diagnostic coverage changed, not authentication. |

Decoder regression inputs contained 33, 32,760 and 500,000 empty entries in both extension locations. Rejection happened before downstream decoding, with measured cumulative allocation below 1 MiB; old comparable inputs allocated about 12.6/202.6 MB. TotalAlloc is not peak RSS or an SDK-wide resource guarantee.

Real signed tests covered registration OOG/retry with advanced sequence, DIRECT registration and later authorization, and the B-registration/A-registration/A-sequence-1 proposal dependency. Invalid native keys still could not poison tracking. Initial H+1 registration was not falsely reported by the new audit check.

## Recorded validation and limitations

Go 1.26.5, two Go workers/packages, 4 GiB soft Go memory target, cached offline dependencies. Full gate: 598 test/subtest passes, 14 packages, three explicit simulations, seven Python tests, 906 IBC sources; vet passed. Twenty-second wire fuzz: 25,100 executions.

- Final logs: `/tmp/pqcauth-shared-fixes-handoff-gate.log` and `/tmp/pqcauth-shared-fixes-handoff-gate/{unit,simulations}.jsonl`.
- Fuzz/vet: `/tmp/pqcauth-shared-fixes-fuzz.log`, `/tmp/pqcauth-shared-fixes-vet.log`.
- Old-behavior probes: `/tmp/pqcauth-share-verification.npTdBY/`; their PASS meant reproduction, not remediation.

DEP-01 was still open in this record: Go 1.26.5, x/net 0.58.0 and OTel log 0.20.0 remained because dependency downloads failed. No checksum fabrication or untested version-only claim was made. Later dependency work is recorded separately. No public transactions, release, node deployment or new network load test occurred.

[Original detailed record at the documentation-cleanup baseline](https://github.com/DoraFactory/doravota/blob/eb5bbec2a88a36224bd27c5b487f3d726a6bfeda/docs/PQCAUTH-SHARED-AUDIT-FIXES-20261101.md). Original evidence files were not translated or modified.
