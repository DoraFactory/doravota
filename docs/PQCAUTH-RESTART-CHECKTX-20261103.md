# Startup CheckTx context repair

Date: 2026-11-03. Baseline: `a7c2f1ec8071ef79c86e9fc1ea4356c74122568c`.
Scope: application startup admission, not PQC pricing or capacity tuning.

## Confirmed cause

SDK v0.55.0 `baseapp.BaseApp.Init` initializes CheckTx with an empty header
containing only the configured chain ID, even after loading a nonzero database
version. `x/auth/ante.SigVerificationDecorator` treats height zero as genesis
and uses account number zero for signature verification. `BaseApp.Commit`
replaces the CheckTx context with the newly committed header.

A real application with an on-disk GoLevelDB database reproduced this for
classic and hybrid accounts numbered 20: valid admission before restart,
signature rejection immediately after reopen, and successful admission of the
identical bytes after an empty committed block. A classic transaction signed
with the wrong account number zero could pass startup admission, but failed
FinalizeBlock without changing balance or sequence. The reproduction is not
evidence of a final-execution authentication bypass.

The pre-fix safety regression failed for both classic and hybrid accounts with
the expected account-number-zero signature error. This explains the earlier
network preparation failure recorded in `PQCAUTH-NETWORK-ACCEPTANCE-20261102.md`;
it is not attributable to hardware capacity or 750 gas.

## Implementation

`app/startup_context.go` captures the loaded store version and its committed
timestamp after `LoadLatestVersion` or `LoadVersion`. Missing or inconsistent
commit metadata fails loading instead of silently guessing. Fresh databases
with version zero retain their existing genesis behavior.

Before the existing Ante handler runs, a narrow application wrapper restores
height and time only when all of these conditions hold:

- A nonzero version was loaded at startup.
- The incoming context still has block height zero.
- The execution mode is CheckTx, ReCheckTx, or simulation.

Both `BlockHeader` and `HeaderInfo` height/time are updated. Chain ID, mode,
gas meters, stores, signature checking flags, and other context fields are
preserved. The timestamp is committed chain time, not wall-clock time, and the
height is the loaded height, not the next block's height.

SDK v0.55.0 exposes no public check-state header setter. This is therefore an
Ante-context compatibility repair, not a rewrite of BaseApp's internal state
manager or a reconstruction of a full historical block header. It does not
invent header hashes or AppHash fields. Metadata is immutable after startup;
the repair performs no database reads per transaction and no persistent writes.

FinalizeBlock, PrepareProposal, ProcessProposal, nonzero live contexts, and true
genesis do not use the repair. All original Ante decorators still run. No SDK
dependency fork, account-number override, signature bypass, artificial commit,
gas price change, quota restoration, or parameter migration is introduced.

## Regression coverage

`TestRestartAdmissionUsesCommittedContext` closes and reopens the actual
application database with real signatures. It covers classic, hybrid, and
native ML-DSA accounts and checks:

- Immediate valid admission before any new block; gas matches pre-restart.
- Restored height and committed time in both SDK context header views.
- Invalid PQC authorization and expired transaction rejection.
- Simulation uses the loaded context without committing account sequence.
- Wrong-account-number signatures fail both admission and final execution;
  failed final execution preserves balance and sequence.
- Subsequent empty blocks and valid final execution work normally.
- Both latest-version loading and explicit `LoadHeight` loading.
- Admission and reopening leave the committed AppHash/version unchanged.

`TestStartupCheckContextScope` covers all eight SDK execution modes, true
genesis, and already-initialized contexts. Both tests are mandatory in
`scripts/test-release-candidate.sh` rather than optional network fixtures.

Reproduce with the repository's Go 1.26.10 toolchain:

```sh
go test ./app -run '^Test(RestartAdmissionUsesCommittedContext|StartupCheckContextScope)$' -count=3 -v
go test -race ./app -run '^Test(RestartAdmissionUsesCommittedContext|StartupCheckContextScope)$' -count=3 -v
go vet ./...
bash scripts/test-release-candidate.sh
```

## Acceptance boundary

Local verification completed with Go 1.26.10, `GOMAXPROCS=2`, `GOFLAGS=-p=2`:

- Full release regression runner: 783 test/subtest pass events, 14 packages,
  zero failures; all mandatory-test presence gates passed.
- Three separately enabled chain simulations passed: determinism, import/export,
  and simulation after import.
- `go vet ./...` passed. Focused restart/scope tests passed three repetitions
  with the race detector enabled.
- Release-tool Python tests (10), capacity-script unit tests (21), and pinned
  IBC source verification (906 files) passed. These are not network load tests.

Raw local records: `/tmp/pqcauth-restart-diagnosis.RfDFfp/`.
`before-fix.log` records the failing regression before the application patch;
`final-suite.log`, `final/unit.jsonl`, `final/simulations.jsonl`,
`final-vet.log`, and `final-race.log` record the final verification.

SHA-256 of the final raw records:

```text
unit.jsonl        b2cfab902a555ccb06c87760a6f38379926c811709d13db3b3966bae962fbe3a
simulations.jsonl 05c758fc070aa978ec1e4a6bd5c156620507888cd26b5be004c978f0aa4c06ac
final-race.log    9235906d7bc635e84ca8fbdde4d3765dcbe423f2137240752fee213fc0e7e45c
```

These are actual application/SDK/crypto/database tests, not extracted control
flow with substitutes. They do not constitute a new multi-machine benchmark
or a rerun of the previous snapshot rehearsal with a newly built artifact.
Final hardware capacity acceptance remains deferred to the actual testnet at
the user's direction; no performance threshold is reclassified as passed.

Remove or revisit this compatibility wrapper when upgrading the pinned SDK to
a version that initializes loaded CheckTx context correctly. Do not relax
authentication or sign transactions with account number zero as a workaround.
