# PQC Auth SDK-keyring integration — 2026-10-20

Status: development candidate for the GitHub development branch. Not deployed
to a public network and not approved for mainnet activation.

Current scope: [phase-one core-signature rollout plan](PQCAUTH-ROLLOUT-PLAN.md).
This supersedes the experimental delegation-index design described in older
evidence below. Historical performance and rehearsal results are not acceptance
of the simplified candidate.

Current integration baseline: released `v1.0.1` (`39759f0`). Existing networks
must complete that upgrade with its released binary before the `v1.1.0`
PQCAuth upgrade. See [integration evidence](PQCAUTH-V101-INTEGRATION-20261030.md).

Latest build repairs and packaged-binary lifecycle/outage evidence:
[2026-10-27 follow-up](PQCAUTH-FOLLOWUP-20261027.md).

Branch: `feature/pqcauth-sdk-keyring`, based on CLI-warning commit `439218c`.
Port commit: `71d6f06`. This ports module functionality, not the old app branch.
Candidate version: `v1.1.0-dev`. Internal upgrade plan: `v1.1.0`.
The existing `v1.0.0` release and its on-chain plan are not reused.

## Implemented

- SDK keyring ML-DSA signing adapter for proofs, protected transactions and
  offline/recovery bundles. Removed module-specific keygen. Explicit legacy
  raw-file adapters remain for recovery; mnemonic restoration remains allowed.
- A local-owner check rejects newly introduced factors derived from that
  owner's secp256k1 private key. Applies at enrollment, both rotations, and
  introduction of a replacement signing key during recovery. Existing factors
  can still authorize migration. Ledger/watch-only/external owner keys require
  explicit `--acknowledge-independent-factors` when the private key cannot be
  inspected. This acknowledgment never overrides detected local reuse.
- This does **not** change SDK derivation or prove a mnemonic is globally unused.
  Separate fresh mnemonics remain required for the signing and recovery factors.
  Recovery replaces the PQC factor; it does not recover a lost classical key.
- App/module/store/query/CLI integration, canonical decoding, ordered Ante
  checks, bounded proposal verification work and SDK gas policy preservation.
- Native SDK Authz/Feegrant semantics, including nested ordinary operations,
  expiry, rollback and fee consumption. No PQC delegation index or wrapper;
  existing grants do not block enrollment and remain effective afterward.
  Direct signers still follow their own PQC policy. Indirect lifecycle messages
  and message-server calls without exact Ante authorization remain rejected.
- Post-v1.0.1 upgrade initializes OPTIONAL enforcement and a network domain
  without scanning account or delegation stores. PQC module version 3 rejects
  old experimental PQC databases; supported activation starts without PQC state.
- Archive startup validation accepts only explicitly known additional stores,
  matching module versions and valid committed roots. Unknown layouts and
  live-Wasm/archive conflicts still fail.
- Candidate CI includes required app regressions and permits prerelease artifacts
  only on `feature/pqcauth-sdk-keyring`. The public-release path still rejects
  prerelease tags by default.

## Phase-one simplification validation — 2026-10-31

Implementation and local verification are complete; production acceptance is
not. Phase two is deferred. See [the rollout plan](PQCAUTH-ROLLOUT-PLAN.md) for
the direct-signature security boundary and remaining release gates.

- Full release-candidate test gate: 561 passing test/subtest events across 14
  packages, zero failures; all three normally skipped simulations explicitly
  enabled and passed. Seven release-tool tests, the 906-file pinned IBC snapshot
  check, `go vet ./...`, and short (20-second each) crypto/extension fuzz runs pass.
- Regression tests cover enrollment with existing grants, SDK grant/revoke/fee
  semantics, protection reactivation, a protected grantee's own factor, recovery
  without revoking delegations, all seven indirect lifecycle operations, and
  message-server rejection without exact Ante authorization.
- Upgrade initialization passes with 1,000 canonical Feegrants and guards that
  fail on account/bank/Authz/Feegrant store access, including cached branches.
  It preserves the allowances and only initializes PQC parameters. This is a
  no-scan property test, not an upgrade-time or peak-memory benchmark.
- The newly built binary passed the isolated four-validator lifecycle rehearsal:
  92 successful transactions, six expected rejections, 40 mixed-load transfers,
  one validator offline for two load rounds, recovery-pending restart, retained
  history compaction and another full restart. AppHashes agree on all four nodes
  at each checkpoint, including state height 114 after the final restart.
  Registration and recovery preserve ordinary delegated execution/fee payment.
  The balance reconciliation includes the grantee's two Authz transaction fees.

Evidence: `build/test-results-phase1/{unit,simulations}.jsonl`, plus
`/tmp/doravota-phase1.yoZGn3/` for the binary, fuzz logs and
`four-validator-lifecycle-retry/evidence/`. Candidate binary SHA-256:
`290dbfee55ca11ce3b1fc451a1dc997e8fe77298bde1ac99e0b434b44d2190a9`.
It was built from the local development working tree, not a published artifact.
The first node attempt was blocked before startup by socket permissions; the
separate retry passed after permissions were opened. All rehearsal nodes stopped.

This fresh synthetic network uses a shortened recovery period and reduced
verification budgets. It is not final-artifact snapshot upgrade acceptance,
upgrade-time crash recovery, public IBC validation, long soak or independent
security review. No public node, wallet, governance plan or release was changed.

## Review hardening — 2026-10-31

- Revoking a retired key first persists any activated policy rotation, so
  compaction cannot leave the stored policy pointing at the removed key.
- The earlier Feegrant-index expiry fix is superseded by phase-one removal of
  the entire custom index. Canonical SDK expiry behavior remains covered.
- Candidate CI permits prereleases for pull requests **targeting**
  `feature/pqcauth-sdk-keyring`, or pushes/manual runs on that branch. A PR
  from the candidate branch into a release branch does not enable this opt-in.
- **Zero-height export is intentionally unsupported when PQC account state or
  effective height-based parameters exist.** It now fails before zero-height
  preparation instead of producing genesis with unusable keys. Export without
  `--for-zero-height` and preserve the returned initial height. Empty PQC state
  without height-based parameters still permits zero-height export. Full rebasing
  of keys, recovery delays and governance schedules remains future work.

These changes are development-branch fixes, not a public-network deployment.

Pre-simplification local verification: `scripts/test-release-candidate.sh` passed with 582 passing
test/subtest events across 14 packages and no failures. The three simulations
skipped by the default run were explicitly enabled and all passed. Release-tool
tests (7), the pinned IBC Amino snapshot check and `go vet ./...` also passed.
Logs: `build/test-results-review-fixes/{unit,simulations}.jsonl`. This does not
replace a public-network rehearsal or Linux release-artifact validation.

## Baseline validation at `33d5b54`

| Check | Result and scope |
| --- | --- |
| Full repository tests | 508 passing test/subtest events, 13 passing packages; zero failures |
| Enabled SDK simulations | Determinism, import/export, simulation after import: all three pass; these are the three normally skipped by the default test run |
| Feegrant app transactions | Failed grant/messages, successful grant, failed/successful authz-nested revoke, exhausted fee payment followed by failed message: pass |
| Hybrid account app transactions | SDK-keyring proofs/enrollment, rejection of classic-only send, successful hybrid send, replay rejection: pass |
| Proposal / upgrade checks | PQC per-block budget, existing SDK proposal limits, OPTIONAL initialization, feegrant index and archive sentinel preservation: pass |
| SDK keyring / CLI | Correct signing domains, altered-message rejection, restored dedicated keys, local coupling rejection, watch-only warning path, real offline proof command: pass |
| Disposable local chain | v1.0.0 governance upgrade, store addition, existing feegrant preservation, ordinary transfer, SDK-keyring enrollment, online protected operation, classic-only rejection, offline bundle transfer, restart and continued blocks: pass |
| Dependencies | go.mod/go.sum unchanged; no wasmd or wasmvm dependency |
| Local build | Native macOS candidate binary built and executed; not a published Linux release artifact |

Local rehearsal transaction hashes and heights are in `local-upgrade-results.json`
in the review record directory. They belong to a disposable localhost chain,
not mainnet/testnet, and therefore have no public explorer URLs.

## Failure → fix → retest

- Retired Wasm/Sponsor test dependencies removed during port; package suites pass.
- Ante feegrant prediction and governance-delay omissions reproduced and fixed
  in the port; full app regressions now also pass.
- Initial CLI fixtures assumed raw-file defaults; updated to explicit legacy
  mode and added real SDK-keyring tests. Temporary API-name and command-removal
  assertion errors were corrected; final suites pass.
- Upgrade fixture incorrectly assumed SetModuleVersionMap deletes omitted keys;
  fixed the fixture to explicitly remove the old test marker. Invalid budget
  fixture now lowers both per-tx and per-block limits coherently.
- **Actual node restart failed after a successful upgrade:** archive validation
  assumed exactly the old store count. Added strict extension-store/version/root
  checks and seven positive/negative cases. Repeated full binary upgrade,
  keyring transaction and restart rehearsal successfully.

## Evidence and remaining release work

Local evidence directory:
`/Users/bun/DoraFactory/review-records/pqcauth-integration-audit-20261020/`

- `ci-final.log`, `ci-final/unit.jsonl`, `ci-final/simulations.jsonl`
- `cli-smoke.log`, `dependency-check.log`, `verification-summary.json`
- `local-upgrade-results.json`, `local-upgrade-driver.log`, `local-*-node.log`
- `before-boundary-fix-local-restart-node.log` preserves the real restart failure
- `REVIEW.md` and the independent earlier `REVIEW-CROSSCHECK.md`

Before release: independent review of the integrated change, a current real
snapshot rehearsal, final candidate rehearsal and Linux artifact validation,
then public testnet activation and operational acceptance. No consensus-key or
IBC signature-algorithm migration is included in this module.

## v1.1.0 hardening follow-up — 2026-10-20

- Unavailable owner private keys now require explicit factor-independence
  acknowledgment at registration, both rotations and recovery with a replacement
  factor. Added Ledger-record and watch-only tests; no physical Ledger device
  test has been performed.
- Documented that PQCAuth cannot enroll any composite multisig, including an
  all-ML-DSA multisig. OPTIONAL permits ordinary SDK multisig transactions;
  REQUIRED rejects composites. Native ML-DSA multisig is not a REQUIRED-mode
  migration workaround.
- Unified the development version as `v1.1.0-dev` and upgrade plan as `v1.1.0`.
  Historical `v1.0.0` identity remains unchanged. Prerelease CI allowance is
  restricted to the development branch.
- Added four-application proposal tests around scheduled budget activation:
  below/at/above the limit, malformed transactions and repeated proposals.
  These exposed an SDK error fallback that could reintroduce the original
  unfiltered transaction list. PrepareProposal now filters malformed input
  before SDK selection and returns an empty proposal on handler error/panic.

### Evidence and exact verification scope

The runtime source at `d78350775f809d1a219b6be144c945b181ee897b` has now completed
full tests and remote rehearsals. Subsequent changes correct the CI package gate
and document results; no runtime Go source changed. Detailed evidence and limits:
[PQCAuth validation report](PQCAUTH-VALIDATION-20261020.md).

| Check | Observed result |
| --- | --- |
| Full repository tests | 522 passing test/subtest events, 13 packages, zero failures |
| Enabled simulations and go vet | All three simulations pass; go vet passes |
| Four-application proposal regression | Budget activation, malformed input filtering and repeated decisions pass |
| Remote four-validator network | 40 operations; multisig/native/hybrid transactions, scheduled parameters, REQUIRED restrictions, AppHash agreement and restart pass |
| Real mainnet snapshot fork | v1.0.0 to v1.1.0 upgrade, bank transfer, unchanged Wasm/IBC/feegrant roots, all 2,139,783 feegrant indexes and four-validator restart pass |
| Linux amd64 release-format artifact | Build, static linkage checks, version and CLI/startup smoke tests pass |
| Physical Ledger, public testnet activation, live IBC packet exchange for this candidate | Not performed |

Initial snapshot failures were test-driver errors: stale upgrade-info detection,
comparison of changing RPC response heights, and broadcasting before catch-up
completed. All are retained in the report with fixes and successful resumption.
The CI required-test gate also used the wrong package for a CLI test; it now
checks the CLI package explicitly. The original passing Go logs pass that gate.

This completes the requested isolated development validation. It is not approval
for mainnet activation: independent review, public testnet acceptance and release
artifact approval remain outstanding. No release tag or public activation was
performed.
