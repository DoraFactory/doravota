# VAL-01 capacity observer fix — 2026-11-02

Baseline: `74ec135b1485fa797ba37653c6c5960d8c829356`.

## Scope and cause

This change fixes the acceptance harness, not PQCAuth consensus code. CometBFT
v0.40.0 can expose a saved block before its FinalizeBlock response is available.
The old scanner advanced its cursor and immediately queried `block_results`;
the resulting HTTP 500 aborted the experiment and its cleanup stopped the test
nodes. This was not evidence of a node halt.

No changes to authentication, 750 verification gas, fixed extension limits,
parameters, proposal handling or the removal of verification-count quotas.
No public transactions, production nodes, release tags or deployment changes.

## Fix

- Retry only HTTP 500 with JSON-RPC code `-32603` and the exact data string
  `could not find results for height #<requested height>`.
- Share the drain deadline with result polling; bound each RPC timeout by the
  remaining time. An unavailable result at the deadline fails the run.
- Preserve error bodies (bounded to 64 KiB), status, retry classification,
  remaining time, owned-process exit codes and a best-effort node status in
  `evidence/block-results-errors.jsonl`. Truncated/unrecognized errors fail.
- Check block/result heights, require an explicit result field, require one
  result per included transaction, and reject every nonzero execution code.
  Only a genuinely empty block may have null/empty transaction results.
- Advance the scan cursor only after validating and recording the height.
- Keep all other HTTP/network errors fatal; do not translate errors into empty
  blocks, skip heights or report timeout as success.
- Add 16 offline observer regression tests to the release-candidate test gate.
  The shared lifecycle RPC helper only gains an optional timeout argument; its
  existing callers retain the five-second default.

## Executed here

Go 1.26.10, offline dependency cache, `GOMAXPROCS=2`, build parallelism `-p=2`.

| Check | Result |
| --- | --- |
| Observer regression tests | 16 test functions passed; fake RPC and clock, not live nodes |
| Existing release-tool Python tests | 7 passed |
| Pinned IBC source verification | 906 source files checked |
| Full Go suite, `-count=1` | 773 test/subtest pass events, 14 packages, zero failures |
| Separately enabled chain simulations | 3 passed, zero failures |
| `go vet ./...` | Passed |
| `git diff --check`, release gate shell syntax | Passed |

The release gate includes real application/keeper regression tests; the three
simulations are not a four-process CometBFT network or a mainnet snapshot test.
Test/subtest event counts are not independent attack-scenario counts.

Local evidence directory: `/tmp/pqcauth-val01.J4n0I3/` (temporary host-local data,
not uploaded CI artifacts). SHA-256:

```text
4ad4ac6f044aa0805fcb6b160eb0e7a8adeebcaab2a2c9bb933f94f4e3f4188b  tests/unit.jsonl
dff7beac6539b8a4da89fde8c9578142cefe3777adef0c2121cc60b5e55ecee5  tests/simulations.jsonl
647042dba86b3f95dba355005ef28db8d146582489e2f78ad0d2014126879808  release-gate.log
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855  vet.log
```

## Still pending — not reported as passed

The current execution sandbox rejects socket creation with EPERM, including
localhost sockets; GitHub shell access also fails DNS resolution. Consequently
this run cannot launch the four validators or complete their RPC-driven tests.
Do not reuse the prior failed run as evidence for this fix.

On a host that permits the existing isolated test workflow, run:

1. The packaged candidate lifecycle rehearsal.
2. All three capacity groups separately: classic, hybrid and native, each with
   5,000 transactions and seven signers. Preserve per-group evidence and failure
   status; do not regard successful admission alone as successful execution.
3. The packaged candidate's v1.0.0 → v1.0.1 → PQCAuth sequential upgrade.
4. Separately, the supported real-snapshot upgrade acceptance when the approved
   snapshot is available. Synthetic sequential upgrade is not a substitute.

The existing CI defines items 1–3. Its first capacity failure currently skips
later groups and sequential upgrade, so confirm each group's actual result,
not only a workflow badge. No CI run of this fix has been observed here.

Capacity measurements must include block intervals, pool drain, execution
results, node resource observations and state consistency. The script's
functional success flag alone is not minimum-hardware certification or proof
that its reported latency comparison passed. No release approval or candidate
freeze follows from these offline results.

## Reproduce offline checks

With the required Go toolchain and dependencies available:

```sh
GOMAXPROCS=2 GOFLAGS=-p=2 bash scripts/test-release-candidate.sh
GOMAXPROCS=2 GOFLAGS=-p=2 go vet ./...
python3 scripts/test-pqcauth-capacity.py -v
```
