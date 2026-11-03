# PQCAuth recheck / parsing / phase-one enforcement fixes

Historical implementation/test record, not current configuration guidance. Old quotas,
registration rules and enforcement modes mentioned below may have been retired.
Use the [module README](../x/pqcauth/README.md) for the current candidate.

Date: 2026-11-02 UTC. Baseline: `cc301bc92ee7cd85eef471e39264b03fd1db0b7e`.
Branch: `feature/pqcauth-sdk-keyring`. This document is delivered with the fix
commit; it is not a release approval. No tag, public transaction, deployment,
live node restart or wallet operation is part of this work.

Input: Claude's `AUDIT-PARAMS-SECURITY-cc301bc.md` and `bench/recheck-fix.diff`
under `/root/claude-pqcauth-audit-20261031/`. Confirmed code/performance issues
are handled separately from protocol/product decisions. See
[the original decisions for follow-up review](https://github.com/DoraFactory/doravota/blob/eb5bbec2a88a36224bd27c5b487f3d726a6bfeda/docs/PQCAUTH-PARAMETER-DECISIONS-20261102.md).

## 1. Repeat cryptography on recheck

Three paths now skip only their ML-DSA verification call when the trusted SDK
context is `IsReCheckTx()`:

| Path | Retained work |
|---|---|
| `ante/verify.go` transaction extension authorization | Extension structure, signer matching, required-factor logic, DIRECT mode, algorithm, effective key and policy binding, signing document construction, gas |
| `ante/lifecycle.go` recovery authorization | Exact top-level lifecycle authorization, recovery/key/state/delay checks, bound recovery document construction, gas |
| `keeper/msg_server.go` key proof helper | Existing caller validation, key ID and lifecycle constraints, algorithm, proof document construction, gas |

SDK account sequence/fee checks and PQC verification-count admission also remain.
No cached key discovery or proposal-budget rule was changed. A transaction
previously rejected by CheckTx(New) cannot enter the actual CometBFT mempool and
therefore is not a valid real-world recheck candidate. A synthetic direct ABCI
Recheck call with those bytes is no longer a signature-validation oracle.

CheckTx(New) and FinalizeBlock still verify all signatures/proofs. Tests inject
invalid extension, enrollment/rotation/recovery proofs, recovery authorization
and protected payer signatures: first admission and final execution both reject
them, with owner balance/sequence unchanged. Calling synthetic Recheck between
those two checks cannot make FinalizeBlock accept them. Do not expose an
untrusted raw ABCI connection and treat Recheck as initial admission.

### Ordered-transaction precondition

This application does **not** enable SDK unordered transactions. Having that
SDK feature in the dependency is not the same as enabling it in AccountKeeper.
Lifecycle transactions require the owner's account signature and sequence;
owner operations advance sequence, key IDs are not reused, and effective
key/policy constraints are rechecked. This is important because recovery
documents derive the current policy version from state.

`TestPQCAuthRecheckRequiresOrderedLifecycle` checks the actual AccountKeeper
setting and ABCI rejection of unordered transactions. Before enabling unordered
transactions, redesign/review that binding and cryptographic-result reuse (for
example, explicit immutable signed version fields or appropriately keyed
verified-document caching). Simply deleting the test is not an acceptable fix.

### Gas semantics

Configured crypto gas is consumed **before** skipping the crypto call. Defaults
and floors remain 750; no stored explicit price is rewritten. Recording-meter
tests assert 750 separately for extension authorization, key proof and recovery
authorization. Total transaction gas also includes store/height-dependent work:
registration and pending-recovery cancellation can have different total gas
between first admission and a later-height recheck. Do not confuse that with
removing crypto gas.

## 2. Redundant public-key parsing

`crypto/mldsa65.go` no longer calls CometBFT `NewPubKeyFromBytes` and discards
its result immediately before SDK `PubKey.VerifySignature` repeats the parse.
The SDK verifier still parses/validates the key and returns false on failure.
Algorithm, exact public-key/signature lengths, domain separation and the actual
signature verification remain. Existing malformed-length, changed-key/message/
signature/context tests pass. This does not replace cryptography with a length
check, nor change the signed envelope.

## 3. Disallow global REQUIRED in phase one

Shared parameter validation rejects `ENFORCEMENT_MODE_REQUIRED` in genesis,
active/pending state and governance requests (including emergency-only requests).
The protobuf enum is reserved; it is not renumbered or silently mapped to
OPTIONAL. Runtime fail-closed handling for this reserved value remains.

OPTIONAL, DISABLED and REQUIRED_FOR_REGISTERED remain supported. This prevents
governance from globally forcing unregistered multisig/Ledger/relayer accounts
into an unsupported phase-one workflow; it does **not** make protected multisig
or Amino signing supported. Already self-protected accounts remain protected.
Tests assert rejected authority requests do not write state. Existing scheduling,
cancellation and same-block tests now use the still-supported restrictive
REQUIRED_FOR_REGISTERED mode; their delay/cancellation/expiry assertions remain.

Experimental databases already using or queuing global REQUIRED need a separately
reviewed migration/reset. Do not hot-swap this binary into such a chain. This is
not an automatic migration of existing stored parameters. No message/protobuf
schema changes were necessary for these fixes.

## 4. Executed validation

Local host, Linux AMD64, Go 1.26.10, dependency/build caches reused offline.
Build/test parallelism capped at two; no production node processes touched.

| Executed check | Result |
|---|---|
| `scripts/test-release-candidate.sh` full unit gate | 14 packages, 828 test/subtest pass events, zero failures |
| Explicit seed-42 chain simulations | State determinism, import/export, simulation-after-import all pass (10 blocks, block size 5, commit enabled) |
| Python release-tool tests / pinned IBC snapshot | 7 tests pass / 906 source files checked |
| `go vet ./...` | Pass |
| `go build ./cmd/dorad` (development artifact) | Pass; binary build information reports Go 1.26.10 |
| Actual signed application admission/recheck/delivery | Registration, send, signing/recovery-key rotation, recovery, protected recovery payer, cancellation pass |
| Revoked/expired keys, changed policy/sequence, activated pause | Rejected as expected on recheck |
| Invalid crypto at New and Finalize | Rejected, even if a synthetic Recheck returns success |
| Bounded seven-signer application workload | 200 admitted transactions, three empty-block/recheck rounds pass; first transaction subsequently executes successfully |

The bounded workload has 25,687-byte transactions and a declared gas limit of
1,000,000. First-transaction gas used was 599,099 in all four rounds. This run
measured New at 1,891.8 us/tx and rechecks at 457.0, 396.5 and 431.6 us/tx.
Signing is outside the measured interval; test setup and final execution are not
part of those timings. These are application measurements on a shared host, not
a CometBFT 5,000-entry mempool or four-validator timing claim.

The existing `BenchmarkMLDSA65GasBaseline` was run with `GOMAXPROCS=1`, three
300-ms samples; key derivation/signing are outside timed loops. CPU was Intel
Core Ultra 7 265, without CPU-affinity pinning:

| Signed message size | SDK range, us/op | PQCAuth wrapper range, us/op |
|---|---:|---:|
| 256 bytes | 65.035–66.022 | 66.525–67.469 |
| 4,096 bytes | 77.011–78.283 | 77.055–79.604 |
| 65,536 bytes | 176.608–177.154 | 195.773–201.335 |

SDK receives the already-built envelope; the wrapper builds it. Both verify the
same signature over that envelope. SDK allocates 41,474 B / 6 allocations;
the wrapper allocates 43,810 / 48,386 / 117,250 B respectively, 8 allocations.
This supports removing duplicate parsing, not the claim that every full Ante
shape costs exactly 750 gas or that all size/capacity limits are redundant.

### Reproduction and raw local evidence

Run in the repository with Go 1.26.10 and the pinned dependencies:

```sh
GOMAXPROCS=2 GOFLAGS=-p=2 RESULTS_DIR=/tmp/pqcauth-review-results bash scripts/test-release-candidate.sh
GOMAXPROCS=2 GOFLAGS=-p=2 go vet ./...
GOMAXPROCS=1 GOFLAGS=-p=1 go test ./x/pqcauth/crypto -run '^$' -bench '^BenchmarkMLDSA65GasBaseline$' -benchmem -benchtime=300ms -count=3
```

This host used `GOTOOLCHAIN=local GOPROXY=off`,
`GOMODCACHE=/tmp/doravota-go-mod`, `GOCACHE=/tmp/doravota-go-build`, and the
cached Go 1.26.10 toolchain. Raw local outputs (temporary, not GitHub artifacts):

- `/tmp/pqcauth-recheck-fixes.ngPN4r/gate/unit.jsonl`
- `/tmp/pqcauth-recheck-fixes.ngPN4r/gate/simulations.jsonl`
- `/tmp/pqcauth-recheck-fixes.ngPN4r/vet.log` (empty on success)
- `/tmp/pqcauth-recheck-fixes.ngPN4r/crypto-benchmark.log`
- `/tmp/pqcauth-recheck-fixes.ngPN4r/build.log` (empty on success)

The development build is `/tmp/pqcauth-recheck-fixes.ngPN4r/dorad`, SHA-256
`fd0b567441f6850d64e2054d33234fad19577f142841e3ab33d50decd3c0b411`.
It was built from the pre-commit worktree, not through the release pipeline;
it is **not** a frozen or distributable release candidate.

New security regressions are required by the release gate, not optional tests.
Test event counts include subtests; do not add them to prior audit totals.

## 5. Remaining acceptance boundaries

No 5,000-transaction real four-validator load, lowest-target-hardware run,
new final-artifact mainnet-snapshot upgrade, public IBC acceptance or physical
wallet test was performed here. No exact DORA/day attack cost is claimed.
First admission and failed admission still do cryptographic work; recheck
optimization does not replace RPC/P2P admission controls. Shared block-budget
competition and recovery latency under saturation remain open capacity work.

750 gas, 16/400 budgets, 8 signer / 64 KiB dynamic caps, immutable delay values,
registration cutoffs and emergency scheduling were not changed by this patch.
The global REQUIRED prohibition is a consensus parameter-validity change and
must be included in the coordinated candidate, not deployed as an unreviewed
mixed-version live upgrade. This fix does not freeze the release candidate.
