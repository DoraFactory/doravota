# PQCAuth v1.1.0 development validation — 2026-10-20

Runtime source: `d78350775f809d1a219b6be144c945b181ee897b` on
`feature/pqcauth-sdk-keyring`. Candidate version `v1.1.0-dev`; future upgrade plan
and Cosmovisor directory name `v1.1.0`. Historical `v1.0.0` stays unchanged.
Subsequent CI gate/documentation edits do not change runtime Go source.

## Result and scope

Requested isolated validation passed. No public deployment, mainnet transaction,
production consensus key change, or release tag was made. Remote tests used
synthetic keys, separate homes and loopback ports. Genesis-only limits/voting
durations were shortened for the synthetic network. Snapshot fork governance,
validator identities and faucet funds were changed only in isolated copies.

| Test | Result |
| --- | --- |
| Full Go suite | 522 passing test/subtest events across 13 packages; zero failures |
| SDK simulations | Determinism, import/export and simulation after import all pass |
| Static analysis | `go vet ./...` passes |
| Ledger/watch-only safeguards | All four new-factor entry points require explicit acknowledgment when local independence cannot be checked; detected reuse remains blocked even with acknowledgment |
| Four independent applications | Identical decisions before/at/after scheduled budget activation; below/at/above budget, malformed input filtering and repeated rounds pass |
| Four live validators | 40 recorded operations, equal AppHashes and restart pass |
| Mainnet snapshot fork | Upgrade, OPTIONAL initialization, transfer, full retained-store roots/index audit and four-validator restart pass |
| Linux amd64 artifact | Release script builds static artifact; version, CLI and startup smoke tests pass |

Ledger tests use genuine SDK Ledger/watch-only record types without a physical
device. They verify CLI safeguards, not actual hardware signing.

## Multisig and four-validator results

- Classical 2-of-3 and all-ML-DSA 2-of-3 SDK multisigs: actual signed bank sends
  succeed in OPTIONAL mode. One signature fails signature verification.
- Both multisigs fail PQCAuth enrollment with the explicit composite-account
  eligibility error. Both fail transactions under global REQUIRED mode.
- Native single-key ML-DSA and enrolled hybrid accounts work in REQUIRED mode.
- Classic-only transactions from an enrolled protected owner fail with missing
  PQC authorization. SDK keyring proof registration and hybrid operation succeed.
- Eight concurrent native ML-DSA transfers occupy two blocks with four each under
  the test budget of four. Budget increases/decreases and delayed REQUIRED
  activation execute through governance; four nodes agree before/after restart.
- Malformed and above-budget candidate proposals are exercised at the application
  layer across four replicas. The live network test does not inject a malicious
  proposer or prove Byzantine fault tolerance under every network condition.

Support remains deliberately limited: all composite multisigs are unsupported by
PQCAuth enrollment and global REQUIRED mode, including all-ML-DSA composites.
Keep production enforcement OPTIONAL until a separately reviewed multisig policy
and migration/support implementation is accepted.

## Real mainnet snapshot rehearsal

Provider snapshot: `doravota_2026-10-20_17852274_snap.tar.lz4`.
Compressed SHA-256: `1ebd3f5dd9f067afe2a693ffc9fdb5afb2d95ba435539948c6f50bc048292d8d`.
Source height: **17,852,274**. Its committed AppHash was independently matched
against two public mainnet RPCs:
`3C58CF491FC06A351232D0268BA5BFA51A2EDDE0DF0B07A1F47D6918A1F539E2`.

Isolated chain: `pqc-v110-snapshot-20261020`.
Upgrade executed at **17,852,348**, with `v1.1.0` as plan name.
All four validators agreed after upgrade and after restart at height
**17,852,361**. A post-upgrade bank transfer succeeded.

- Wasm raw-store root and prefix counts remain unchanged, including **4,177,236**
  contract-state entries under prefix `03`; raw query samples match.
- All **18** IBC channel records and the complete IBC store root remain unchanged.
- The original feegrant store root remains unchanged. All **2,139,783** canonical
  grants have matching new reverse-index values; index cardinality matches.
- Checks compare state content, not the expected changing query response height.

IBC coverage here is preservation of state, not new packet/acknowledgment or
return-transfer testing with live counterparties for the v1.1.0 candidate.

| Store | Identical pre/post root |
| --- | --- |
| wasm | `7b1ce8c7505709b965a23d53153334e659744b50769bac804ad56d3851a09852` |
| ibc | `ef335a3fbdb7653cb4aa17fba09d57b072ac5c412abf247409959aa79c9e7e3c` |
| feegrant | `a29cb8a9dcea281dd72bedf83d71f5b2094a46d1ffdbab05707e9da07b6da6b3` |

The following transactions belong only to the isolated fork, so there are no
public explorer links for these hashes:

| Operation | Height | Hash |
| --- | --- | --- |
| upgrade-submit | 17852279 | `B3E3E462EE6A8FC6DAB8C457AABC467842A7404A42C8CF911516715D865F6F2B` |
| upgrade-authz-votes | 17852280 | `D401034E62186B6C13B3728E02C61C2C8B4D90A832C272AE0CCB782B55583A73` |
| post-upgrade-transfer | 17852356 | `6A73912C145A6A56217DEA5E4412EA4633F747B2862E17907A992EF4D08F9EEB` |

## Failures, corrections and retests

1. Proposal regression before this submission exposed SDK PrepareProposal error
   fallback restoring the original malformed transaction list. The d783507 handler
   filters malformed input and returns an empty proposal on handler error/panic;
   regression and full suites pass on that source.
2. CI required-test gate searched for the new CLI test in the app package. The
   test itself passed. The script now validates its exact CLI package separately;
   the original full-suite JSON passes corrected gates. Earlier GitHub CI failure
   is retained: https://github.com/DoraFactory/doravota/actions/runs/39433332301 .
3. Snapshot fixture treated an existing v1.0.0 `upgrade-info.json` as proof of
   reaching v1.1.0, replacing the binary prematurely at 17,852,290. New binary
   correctly rejected missing store initialization. The driver now requires the
   exact name and height; the preserved fork resumed with v1.0.0 and reached the
   real upgrade boundary successfully.
4. Snapshot comparison included RPC response height. Heights differed as expected;
   channel records and raw values matched. Compare content separately from height.
5. A resumed driver attempted transfer while CometBFT was still catching up;
   the RPC rejected it. Added all-node sync and fresh-block readiness checks.
   Subsequent transfer, full state/index audit and restart all pass.

The snapshot sequence resumed preserved state after fixture corrections. It is
an evidenced upgrade-and-restart sequence, not a claim that the original driver
completed without intervention. Failed logs remain preserved.

## Artifacts and evidence

Both Linux binaries embed runtime commit d783507; their build flags differ:

| Artifact | SHA-256 | Verification |
| --- | --- | --- |
| Rehearsal binary `dorad-d783507` | `05ce7f3888653ec683314a7b35d52771ca92a22e364ee8858e3ee91dcdd27215` | Used for both four-node rehearsals |
| Release-format `dorad-v1.1.0-dev-linux-amd64` | `91ea8a809c99d4dd6150adc603f3f059eef7cb44ae7b20817f10f3b551f91277` | netgo/osusergo, static-link and CLI/startup smoke checks |

The release-format binary has not independently repeated the full snapshot
rehearsal. These are development artifacts, not approved public release assets.
ARM64 execution was not tested in this remote session.

Local evidence directory:
`/Users/bun/DoraFactory/review-records/pqcauth-integration-audit-20261020/`

- `commit-d783507-tests/`, `commit-d783507-gate-retest.log`, `commit-d783507-vet.log`
- `four-validator-d783507-result.json`, `four-validator-d783507-checks.json`
- `snapshot-d783507-verified.json`
- `four-validators-d783507.py`, `snapshot-network.py`, `snapshot-resume-d783507.py`,
  `snapshot-finish-d783507.py`, `snapshot-verify-d783507.py`
- `REVIEW.md`: chronological execution and failure/fix/retest record

Remote evidence is under `/root/pqcauth-v110-rehearsal-20261020/evidence/`:
`fresh4-d783507/`, `snapshot/`, `snapshot-retest-d783507/`,
`snapshot-final-d783507/`, `snapshot-verified-d783507/`, and corresponding driver
and build logs. Full per-grant audit files remain remote to avoid copying millions
of records; the local verified summary records roots, cardinality and value match.

Before mainnet: independent review, public testnet activation/acceptance, a tested
release artifact, validator coordination and explicit release approval are still
required. Consensus signatures and IBC light-client signature algorithms are
unchanged by this module.
