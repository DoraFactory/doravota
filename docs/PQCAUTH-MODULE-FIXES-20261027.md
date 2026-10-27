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

## Remote and CI validation

The four-validator script now also signs and broadcasts 17 recovery/cancellation
pairs, rotates twice, transfers with the final key, verifies the older key was
compacted, and checks all validators agree before and after restart. It uses only
synthetic funds and loopback endpoints. Remote execution and GitHub results will
be recorded after completion; the prior candidate's CI is not evidence for this
runtime change.
