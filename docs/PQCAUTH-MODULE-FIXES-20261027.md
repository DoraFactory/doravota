# PQCAuth module review fixes — 2026-10-27

Branch: `feature/pqcauth-sdk-keyring`. Reviewed baseline:
`f1a393d8e53946cd799d98bf0ac241cc8856a1fb`. Candidate remains `v1.1.0-dev`.

## Confirmed failures and changes

| Finding | Reproduction on reviewed baseline | Fix | Required regression |
| --- | --- | --- | --- |
| P1: fresh-account key poisoning bypassed verification budgeting | An invalid classic-key transaction preceding two valid native ML-DSA transfers made ProcessProposal accept a block with budget 1; FinalizeBlock failed the poison transaction and executed both native transfers | Match a newly discovered public key to its signer address before caching it; reject malformed key addresses without panic; persisted keys still take precedence | Application ProcessProposal rejects the poisoned block; PrepareProposal skips the invalid transaction and includes one native transfer; both transfers succeed in separate blocks; omitted follow-up keys remain counted |
| P1: cancelled recoveries blocked later signing-key rotation | 17 recover/cancel cycles compacted key 3 while key 1 remained active; exported genesis was rejected and later rotation failed when retiring key 1 | Interpret the history field as the maximum compacted ID, allow later retirement of smaller pinned IDs, and align genesis validation with that meaning | Keeper lifecycle, accumulator order 3→4→1, idempotence, state audit, actual module genesis export/import |
| P2: native ML-DSA gas floor missed multisig leaves | 1-of-1 native ML-DSA multisig with auth cost 1 consumed 1 instead of the 750 floor | Clamp native ML-DSA cost before delegating to the SDK recursive consumer | Direct and nested mixed multisig with costs 0/1/750/12345; classical cost unchanged |
| P2: history retention only visited the first 100 records | With 132 alternating-role terminal records and retention 64, the first page contained only 50 per role and nothing was compacted | Read the complete owner prefix and close the iterator before writes; reads remain gas-metered | 64 records retained per role, then reduction to 16; compacted counts 2 and 50 per role |

The gas change does not add PQCAuth enrollment support for multisig accounts.
OPTIONAL enforcement, existing key derivation, consensus key algorithms, and IBC
client algorithms are unchanged. No public-chain transaction or deployment is
part of this work.

## Compatibility

No protobuf field or key layout changed. The accumulator is a sequential hash
chain in compaction order, with ascending key IDs within each batch. Its maximum
ID is not a contiguous deleted-key frontier. Older pinned keys can remain and
later join the accumulator exactly once. The maximum compacted ID itself may not
also exist as a full key record, and the next key sequence must exceed all known
IDs. A compacted hash alone cannot reconstruct which earlier IDs were deleted.

These are consensus-visible fixes to an unreleased development candidate. All
validators in a candidate rehearsal must use the same fixed build. This document
does not authorize mixing pre-fix and fixed development binaries or deploying to
mainnet; production activation still needs a coordinated upgrade and acceptance.

## Validation completed before push

- `scripts/test-release-candidate.sh`: PASS on macOS; 13 tested packages,
  530 passing test/subtest events. The 3 normally opt-in application simulations
  were then explicitly enabled and passed (seed 42, 10 blocks, block size 5).
- `go vet -p 2 ./...`: PASS.
- Release tooling negative gates: 6 Python tests passed.
- New critical regressions are named in the mandatory CI test-result checker,
  which rejects skipped or missing tests.
- The first new genesis round-trip fixture used the legacy default network ID;
  InitGenesis intentionally normalized it. The fixture now uses the chain-derived
  network ID before export. No production normalization behavior was changed.

Evidence directory:
`/Users/bun/DoraFactory/review-records/pqcauth-module-fixes-20261027/`.
The baseline reproduction remains in the adjacent
`pqcauth-module-review-20261027/REVIEW.md` and `confirmed-probes.log`.

## Remote four-validator validation — PASS

The remote host was checked before starting (98 GiB available disk, 56 GiB
available memory). A new isolated directory and ports 48756/48757 plus 100 per
validator were used. The two existing `dorad` processes remained running after
our four nodes exited; no public-chain wallet or service was changed.

- Fixed runtime source and rehearsal script matched the pushed commit
  `37fdb6fa1bf1243c96d217341045ce7c36ea0e57` across a 146-file SHA-256 manifest.
  This remote binary was built from the worktree and identifies itself as such;
  the commit-stamped CI release artifacts are validated separately.
- **86 successful transactions, 6 expected rejections**. This includes the
  existing registration/rotation/recovery/offline signing/mixed traffic checks,
  a validator offline during load rounds 1–2 and rejoining in round 3.
- Additional regression: **17 signed recovery/cancel pairs**, then two signing
  rotations and a hybrid transfer with the final key.
- Before rotation: signing key 6 remained active, while 4 terminal signing keys
  were compacted with maximum ID 7. After rotations to keys 24 and 25, the count
  was 6, maximum ID 8, and retired key 6 was absent from the full record list.
- Recipient balance increased by exactly **92 peaka**, as calculated from the
  synthetic transfers.
- Four validators agreed on state height 102:
  `4A8E9F3DD3576AF19F0040B63B58CB34C566E3AC58D8796CF0E68E633E3158FC`.
- After restarting all four validators, account policy and compacted history
  were unchanged. All agreed on state height 105:
  `55F4F1EB37E47D415977F1039A9EEBF79DFFF6056AB395B1BABD18EC226A8445`.
  Different heights have different hashes; each comparison is between all four
  nodes at the same height.

Representative isolated-network transaction hashes (not public explorer links):

| Operation | Transaction hash |
| --- | --- |
| Rotate to key 24 after churn | `B427307AE47A583D183F7913184B7B8FC09E82047716B71FA4FCCE9E58C1B324` |
| Rotate to key 25 | `1F22299C37A0D4A628C43BA39572F6E397628348A1F5F038BCD544DEA07270D6` |
| Transfer with final key | `3B86FA19487C77768254A2D2A340B531E326F2EF58F4167ECA036910FFCF6A4E` |

Remote evidence: `/root/pqcauth-module-fixes-20261027/four-validator/evidence/`.
Local copy: `pqcauth-module-fixes-20261027/remote-evidence/` under the review-records
directory above. `result.json` contains the operation-to-transaction mapping;
individual receipt files retain height, code, gas, and events.

## GitHub CI

Run: https://github.com/DoraFactory/doravota/actions/runs/40431813652
Commit: `37fdb6fa1bf1243c96d217341045ce7c36ea0e57`.
**Completed: all jobs passed.** GitHub unit results also contain 530 passing
test/subtest events, plus all 3 explicitly enabled simulations. AMD64 and ARM64
each passed native builds, release smoke checks, Docker validation, and the
packaged-binary four-validator rehearsal (**86 successful transactions and
6 expected rejections per architecture**).

The downloaded public evidence ZIPs matched GitHub's SHA-256 digests. Every
successful receipt matched its recorded hash and code 0, and all five agreement
checkpoints contained four identical hashes at the selected height.

| Executed CI binary | SHA-256 |
| --- | --- |
| Linux AMD64 | `9a5a20e75724dc037f9ecac0f4e358e9c29bc408f6facf5a7202b598874c8dab` |
| Linux ARM64 | `89f96fd7757e7eb7e025f4557dfacb0e174e3566bf94653d9e66ad29cfbb9f5f` |

CI artifacts are attached to the run: `test-results`, `bridge-linux-amd64`,
`bridge-linux-arm64`, `pqcauth-rehearsal-amd64`, and `pqcauth-rehearsal-arm64`.
The two rehearsal evidence bundles and test logs were archived locally in
`ci-artifacts/`; `ci-run.json` records the successful run and exact source SHA.
No release tag was created and no candidate binary was deployed to public nodes.

The candidate remains unactivated on public networks. These tests do not provide
physical Ledger testing, live-counterparty IBC testing, a long-duration soak, or
an independent security audit. The previously completed snapshot exercise belongs
to the earlier candidate and has not been repeated with this commit.
