# PQC Auth SDK-keyring integration — 2026-10-20

Status: development candidate for the GitHub development branch. Not deployed
to a public network and not approved for mainnet activation.

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
- Feegrant routing includes authz-nested calls. Predicted writes are discarded;
  real message writes roll back with failed messages. Actual fee consumption
  and exhaustion-index reconciliation remain persisted in successful Ante.
- Post-v1.0.0 upgrade initializes OPTIONAL enforcement, a network domain and
  existing feegrant indexes. Index rebuild runs once through module InitGenesis.
- Archive startup validation accepts only explicitly known additional stores,
  matching module versions and valid committed roots. Unknown layouts and
  live-Wasm/archive conflicts still fail.
- Candidate CI includes required app regressions and permits prerelease artifacts
  only on `feature/pqcauth-sdk-keyring`. The public-release path still rejects
  prerelease tags by default.

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
