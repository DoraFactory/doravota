# PQCAuth network acceptance progress — 2026-11-02

This is a partial acceptance record, not release approval. Production module
code, signature verification, 750 gas and removed quotas are unchanged.

## Completed real network experiment

Source/binary commit: `6fd5c8d1f2adb2225cc70ceccb0f7336db305d28`.
Built with the release script and actual Go 1.26.10; version remains
`v1.1.0-dev`, no release tag. Binary SHA-256:

```text
67447a0fd8d8c55b66679054ba6d20b6447dad5f75f4664807d58b77de83d3ca
```

Four synthetic validators in one `--network none` container, limited to three
CPU equivalents, 7 GiB memory (no swap allowance) and 256 PIDs. GOMAXPROCS=2 per
process. The existing Go 1.26.5-bookworm image was a runtime only; it did not
compile the candidate. Production nodes and other users' containers untouched.

Classic group: 5,000 transactions, seven classical signers each, all execution
codes zero, final four-node AppHash equal at state height 115:

```text
C45F1696462172FFCDC7D6FB828CA6E0B56B3F2772404545B968E1AC1CDCEE65
```

- Admission: 10.589 s; drain after resuming quorum: 522.013 s.
- Sampled peak sum of four node RSS: 1,309,065,216 bytes (~1.22 GiB).
- 24 exact missing-result HTTP responses were logged and successfully retried.
  This exercises VAL-01 in a real network, not just mocks.
- Node0 retained the backlog while the other three pools were observed empty.
  There were no adjacent loaded blocks, so `loaded_p95_seconds` is null and
  `p95_within_15_percent_baseline` is false. Functional completion is established;
  the intended sustained-load latency comparison is **not established**. This is
  not a PQC CPU benchmark, recheck timing measurement, or worst-case capacity
  certification. The cause of the pool propagation pattern was not established.

Evidence root: `/tmp/pqcauth-val01-network.DByRGW/` (host-local temporary files).
See `classic/evidence/`, `classic.log`, and `classic-pool-observation.json`.

## Newly exposed hybrid fixture defect and fix

The original hybrid experiment failed at InitChain, before admission. The
generator populated PQC policies/keys but `genesis add-genesis-account` left
the owners' SDK public keys null. The real module correctly rejected those
pre-enrolled owners as ineligible. This is malformed synthetic genesis, not a
normal transaction causing a production chain halt.

The test generator now exports each deterministic test account's public key.
The harness installs the seven classical public keys only for hybrid's
pre-enrolled owners, checks exact owner coverage and expected account/key types,
and leaves other accounts unchanged. Classic/native still publish keys through
their normal transaction path. No private key is added to the output.

New mandatory `TestPQCAuthNetworkLoadGenesis` uses the real generator output,
codec, InitChain, FinalizeBlock and Commit for classic/hybrid/native; hybrid also
passes the state audit. Its negative case retains rejection of null owner keys.
Two Python tests check the actual genesis merge helper. These are not a rerun
of the 5,000-transaction hybrid network experiment.

## CI findings and port follow-up

`eacb1028f204fce68b0eef37d0c3f891c79cfaf4` is confirmed on GitHub.
[Run 41460466270](https://github.com/DoraFactory/doravota/actions/runs/41460466270):

- Tests passed.
- ARM64 job 125329036575 passed, including packaged lifecycle/restart.
- AMD64 job 125329036766 passed build, Docker verification and packaged
  lifecycle/restart; capacity failed in the initial listener bind preflight.
- Sequential upgrade skipped after that capacity failure. No native/hybrid
  capacity success is inferred from this run.

The lifecycle and capacity defaults reused the same port group. The preflight
used Python's non-reusable bind, unlike Go's listener, so it can reject a closed
listener's TIME_WAIT port. The log establishes EADDRINUSE, not the exact socket
owner/state. Follow-up uses SO_REUSEADDR plus listen (never SO_REUSEPORT), still
fails on active listener conflicts, and gives the CI stages disjoint port groups
below the usual ephemeral range. Unit mocks verify preflight calls/error
propagation; the revised live preflight awaits network-enabled execution.

CI now runs all three capacity groups serially, remembers any failure and exits
nonzero after the groups. The existing sequential upgrade may run after capacity
failure only if the packaged lifecycle succeeded and the job was not cancelled.
This preserves failure status while collecting independent missing evidence.

## Latest local verification

Offline Go 1.26.10, GOMAXPROCS=2, build parallelism 2:

- Full Go suite: 778 test/subtest pass events, 14 packages, zero failures.
- Three separately enabled chain simulations passed.
- `go vet ./...` passed.
- 18 capacity/fixture Python tests and 10 release-tool tests passed.
- 906 pinned IBC source files verified.
- Workflow YAML parse, embedded shell syntax and `git diff --check` passed.

Evidence: `fixture-tests/{unit,simulations}.jsonl`, `fixture-gate.log`,
`fixture-vet.log` under the evidence root. The final preflight mock was added
after the full gate and separately rerun as part of the ten Python tests.

```text
fb6c3a78f95f99d6c543dc55f717d2eb58e890048c0a16e24b9190f6b8aa9a09  classic/evidence/result.json
16ff473c1167f5afaddaa1f215a0419918bd0fb324f98972997c3ca73d057a04  hybrid/evidence/result.json (FAILED original run)
11b01260567e8388df63ec130be5710f66cebdd7b8c78c90f11ecd63d7973fd0  fixture-tests/unit.jsonl
055486068b912773720b6942df7d644da1ad5e62fffbe0705f405f1a2e6e41a0  fixture-tests/simulations.jsonl
```

## Remaining

The session returned to restricted permissions while this work was in progress;
Docker socket access is denied. The original hybrid run has a failure record
and its script performed owned-process cleanup. No network rerun of the fixture
fix, native 5,000-transaction experiment, or sequential upgrade has been completed
here. The new changes need pushing and CI verification when network access is
restored. Existing successful lifecycle results belong to eacb102, not to an
unobserved later CI run.

After functional network checks, sustained-load sampling must establish that the
proposers actually have pending transactions; the empty loaded-p95 sample cannot
be silently accepted. Supported real-snapshot upgrade, minimum-hardware stress
and public testnet/IBC acceptance remain distinct from these synthetic runs.
