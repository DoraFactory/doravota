# PQC Auth SDK-keyring integration — 2026-10-20

Status: implemented and locally verified development candidate. Not deployed,
not pushed, and not approved for mainnet activation.

Branch: `feature/pqcauth-sdk-keyring`, based on CLI-warning commit `439218c`.
Port commit: `71d6f06`. This ports module functionality, not the old app branch.
Candidate version: `v1.0.0-pqcauth-dev`. Internal upgrade plan: `pqcauth-v1`.
The existing `v1.0.0` release and its on-chain plan are not reused.

## Implemented

- SDK keyring ML-DSA signing adapter for proofs, protected transactions and
  offline/recovery bundles. Removed module-specific keygen. Explicit legacy
  raw-file adapters remain for recovery; mnemonic restoration remains allowed.
- A local-owner check rejects newly introduced factors derived from that
  owner's secp256k1 private key. Applies at enrollment, both rotations, and
  introduction of a replacement signing key during recovery. Existing factors
  can still authorize migration. Watch-only/external owner keys produce a
  warning because this check cannot inspect their private key.
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
  explicitly. The public-release path still rejects prerelease tags by default.

## Actual validation

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
snapshot rehearsal, final release/upgrade naming and Linux artifact validation,
then public testnet activation and operational acceptance. No consensus-key or
IBC signature-algorithm migration is included in this module.
