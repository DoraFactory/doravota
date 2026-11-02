# PQCAuth network acceptance progress — 2026-11-02

This is a partial acceptance record, not release approval. Production module
code, signature verification, 750 gas and removed quotas are unchanged.

Latest outcome: application commit `91fc459` has fully successful CI, local
sequential upgrade and retained-mainnet-snapshot replay. The new all-pool
experiment completed 5,000 classic, 5,000 hybrid and 5,000 native transactions
with zero execution errors and final four-node agreement in every case.
**Latency acceptance is not closed:** under the shared 3-CPU quota, hybrid and
native still exceed the suggested 15% increase even in the explicitly post-hoc
diagnostic view. No release tag or public-chain deployment was performed.

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

## Historical pause after the fixture fix

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

## Resumed acceptance on 91fc459

Network/runtime access was subsequently restored. The fixture and CI repairs
were pushed as `91fc4592f8ff0038cc0af43969036ba96b78b4ca`. A clean git archive
was rebuilt with the release script and Go 1.26.10, still `v1.1.0-dev`, without
a release tag. Candidate SHA-256:

```text
b10e90aa1db0824a98ca3e59b3b09fad23b8a6ef3ec400fb0383fa334bec9878
```

The independently compiled fixture SHA-256 is
`9d0f9c9c5cf668ecda1e647b9e3d536e2821dbf2346bd1b63590b83039e437f5`.
Evidence root: `/tmp/pqcauth-acceptance91.nGLhyw/`. Experiments run serially,
with the same 3-CPU/7-GiB offline container limits described above.

Hybrid group completed: all 5,000 seven-signer transactions executed with code
zero. Four nodes agreed at state height 115 on AppHash
`383D4F2AC5F671EE452D4477EF2BE159E114C032500ABB4436A1D7D7C0464DA2`.
Admission took 21.512 s and drain took 542.732 s. Sampled peak four-process RSS
was 1,742,139,392 bytes. Maximum recorded PQC verifications per block: 1,400.
This directly exercises blocks exceeding the removed 400-verification quota;
it does not establish worst-case capacity. The loaded-interval sample is again
empty, so the p95 performance acceptance is **not established**.

Hybrid result SHA-256:
`87338b6d2933641d9009ee9c52176f1236fe849eaee6bc9928412ff9d1543d02`.
The original malformed-genesis failure above remains historical evidence; it
has not been relabeled as successful.

Native ML-DSA group also completed all 5,000 transactions with code zero.
Four nodes agreed at state height 117 on AppHash
`2E2FDED580FE882B4C5151CCDB5C3F9331280FEE8EB7F8BE6BC12188663ADAE3`.
Admission took 17.491 s, drain 564.627 s, and sampled four-process RSS peaked at
2,614,280,192 bytes. This run likewise has no adjacent loaded-block intervals,
so it is a functional backlog-drain result, not a passing latency certification.
Result SHA-256:
`77a6769f11221b28e5bfcca31372ceece53f08d12871023344ac39546fb48abf`.

The same candidate passed the synthetic four-validator sequential governance
rehearsal: v1.0.0 -> v1.0.1 at height 85 -> PQCAuth at height 197, premature
candidate starts rejected, transfers successful, four-node agreement before
and after restart without upgrade-info. Initial on-chain params are 750 gas,
107,520 recovery blocks, 46,080 maximum pause blocks and 17,280 safety-delay
blocks. This is a synthetic chain, not the separately planned snapshot replay.
Result SHA-256:
`3183daa15a61ce00fdc6705c8e7043b4e91adfc8853262de096cee6ab1714041`.

Selected public JSON results and four-node agreement records are preserved under
[`upgrades/pqcauth-acceptance-20261102/`](upgrades/pqcauth-acceptance-20261102/).
No node homes, signing keys or wallets are included.

### Retained mainnet snapshot replay with the same candidate

Replayed the retained **2026-11-01** height-18,029,707 snapshot, not a claim of
the latest mainnet state. Recomputed archive SHA-256 and checked the source
database AppHash against the two retained next-block headers. Used the documented
[synthetic checkpoint methodology](PQCAUTH-SNAPSHOT-REHEARSAL-20261101.md), fresh
test keys and fresh node homes; no live node data or public transactions.

The same `b10e90aa...` candidate passed v1.0.0 -> v1.0.1 at 18,029,778 -> PQCAuth
at 18,029,848. Both deliberate SIGKILL cases left committed height 18,029,847
(independently read from the databases), then recovered successfully. Full restart
and one-validator outage/rejoin passed; final four-node agreement at 18,029,866.
Eight test transactions succeeded. Wasm/IBC/Feegrant/Authz roots were unchanged
across the PQC upgrade window. Queried module version is **4**, gas **750**, and
all three configured delays and the upgrade-derived network ID matched assertions.

Container: no network, 4 CPU equivalents, 12 GiB memory/no additional swap,
GOMAXPROCS=2 and GOMEMLIMIT=2GiB per node, configured disk read/write limits
100/60 MB per second, 40 GiB free-space guard. Four-node sampled RSS peak was
969,445,376 bytes, but cgroup memory **including file cache reached 12 GiB**;
reclaim occurred, `oom=0`, `oom_kill=0`. Minimum free disk was 159,050,207,232
bytes. This is not minimum-hardware or cold-cache certification.

Full evidence: `/tmp/pqcauth-snapshot91.fpNgz3/evidence/`; selected results,
actual scripts, store roots, params and version query are archived under
[`upgrades/pqcauth-acceptance-20261102/snapshot/`](upgrades/pqcauth-acceptance-20261102/snapshot/).
The scripts contain actual temporary paths and must use fresh directories on
replay. Offline preparation tools are the retained v1.0.0 tools, SHA-256:
`7dea33d8f811bf3e59e7bbfb812425d55645f305f0c53bd85426bcad94a4ef4a`
(`roots`) and `98ec77352d0254926cdc75be46afd0c17ccac0a840b8ba2dcbe966627f25e185`
(`snapshot-fork`). Their source is in the earlier snapshot archive.
Result SHA-256:
`3e08a309da2f4bd735eab74c77f39b5095e2bd7d37f241a1bda1b900794d97b9`.

## All-validator backlog observation (additional harness mode)

CI for the tested candidate is complete:
[run 41468902452](https://github.com/DoraFactory/doravota/actions/runs/41468902452)
has successful tests, AMD64 and ARM64 jobs. AMD64 job 125357825254's raw log
was read: all three capacity groups report `functional_pass: true`, and the
sequential upgrade reports PASS with candidate SHA-256 exactly matching the
local `b10e90aa...` binary. This is comparison to the CI execution record, not
an independently downloaded/rehashed CI binary. ARM64 sequential/capacity
remain intentionally skipped. CI classic/native have null loaded-p95, while
hybrid has a sample; CI green still does not certify sustained-load latency.

The original single-pool experiment cannot provide sustained loaded intervals
when the other proposers have no transactions. `--all-validator-pools` adds an
explicit offline-only alternative: synthetic validators communicate through four
loopback TCP forwarders with PEX disabled. Baseline and loaded phases use the
same forwarders. Pause/close these links after a new common block, without
restarting the applications; fill all four pools with identical valid signed
bytes in sequence order; require unchanged/equal heights, zero peers and the
exact count in every pool, then resume forwarding. All sockets remain inside a
`--network none` container. No unsafe RPC or host firewall changes are used.

Regression checks cover opt-in peer arguments, link pause/resume and rejection
of mismatched height, peer count or pool size. A failed pool invariant is not
silently retried or reported as success.
The mode measures a preloaded-backlog drain, not organic network propagation,
adversarial admission, minimum hardware, or recheck CPU in isolation. Declared
gas remains 3,000,000 per transaction, so 200 transactions can fill the declared
600,000,000 block allowance even when actual gas used is lower; these experiments
do not establish maximum possible TPS or a worst-case fully utilized gas block.

Two preliminary restart-based approaches were rejected by real smoke tests:
peerless restart left the mempool in catching-up mode; temporary nonvoting peers
completed sync, but before any post-restart block the first classical signature
was rejected with account number 0 rather than the generated 20..26 values.
Neither attempt admitted a transaction, and neither is counted as a load-test
pass. Their failure JSONs are archived. The final approach avoids this startup
context entirely and does not alter SDK authentication or enable experimental
adaptive sync. Original temporary attempts remain at
`/tmp/pqcauth-allpools91.0h6ueq/` and `/tmp/pqcauth-allpools91b.TkA3WZ/`.

### Interpretation of loaded header times

The successful forwarding implementation's executed source SHA-256 values are
recorded in `manifest.json`; the later source-comment correction does not change
its behavior. The original comment claiming that the initial resume interval
was excluded was inaccurate: Comet block header time can derive from votes
preceding the intentional partition. For example, hybrid block 39 has header
time 16:19:49 UTC but was observed committed after admission completed at
16:21:25 UTC. Raw adjacent loaded intervals therefore include 102.883 s and
30.320 s of partition/reconnection effects. They are not pure PQC execution time.

Keep the original result and block arrays unchanged. The `*-diagnostic.json`
files additionally remove the first **three** loaded intervals uniformly across
cases and calculate nearest-rank p95 on the remaining samples. This is explicitly
**post-hoc diagnostic analysis, not a changed acceptance rule or release pass**.
Even under this diagnostic view, hybrid's remaining p95 is 6.562 s versus its
5.327 s baseline, an increase of 23.2%, exceeding the suggested 15% criterion.
Do not label the shared-3-CPU hybrid latency target as passed.

All-pool classic: 5,000 executions succeeded, 24 raw loaded intervals, baseline
p95 5.360 s, raw loaded p95 5.659 s (+5.6%). After the same diagnostic exclusion,
21 samples remain and p95 is 5.407 s. Drain duration: 130.247 s.

All-pool hybrid: 5,000 executions succeeded, 24 raw loaded intervals, baseline
p95 5.327 s, raw loaded p95 30.320 s. After diagnostic exclusion, 21 samples
remain and p95 is 6.562 s. Drain duration: 183.350 s. Four-process sampled RSS
peaked at 2,598,903,808 bytes during drain. All four prefilled pools held exactly
5,000 transactions at the same height before reconnect; final states agreed.

This does not establish an authentication bypass or chain halt. The environment
shares just three CPU equivalents across four validators plus the forwarding
controller, and uses synthetic traffic. A production hardware target, separately
measured recheck duration, maximum-gas/size shapes, and invalid-admission load
still need distinct acceptance. Do not change the 750 price or restore a quota
merely to turn this observation green.

All-pool native also completed 5,000 successful executions with four-node
agreement. Admission to all four pools took 82.142 s (20,000 RPC requests), drain
took 221.612 s, and four-process sampled RSS peaked at 3,669,143,552 bytes during
drain. The three experiments use the same candidate, 3-CPU/7-GiB limits and
forwarding setup. All owned experiment containers stopped after completion.

| Kind | Baseline p95 (s) | Raw loaded p95 (s) | Diagnostic p95 after first 3 intervals (s) | Diagnostic increase |
| --- | ---: | ---: | ---: | ---: |
| Classic | 5.360 | 5.659 | 5.407 | 0.9% |
| Hybrid | 5.327 | 30.320 | 6.562 | 23.2% |
| Native ML-DSA | 5.338 | 50.381 | 7.427 | 39.1% |

Each case has 30 baseline intervals, 24 raw loaded intervals and 21 diagnostic
intervals. Raw values include intentional partition/reconnection effects, not
only execution. The diagnostic exclusion was applied after observing those
effects, uniformly across cases; it cannot retroactively turn the run into a
predeclared passing release test. Neither PQC case meets the suggested threshold
even after this exclusion. No isolated recheck time was measured.

First transaction wire sizes are 2,009 / 25,634 / 38,178 bytes respectively.
These are different transaction shapes, not matched-size cryptographic
microbenchmarks. Native's larger wire representation and test transport, shared
CPU and application work cannot be separated by these aggregate observations.
No fee-economics or single-verification price conclusion is drawn.

Raw result SHA-256:

```text
4694e1b2d98a3280f9d19a96b47ff5a46fd3b0054670f4882da1d012d341d5af  classic
5e92047e728da1fe6254552a6f1d21b67e3be223aaf9742271bbbc7bab63d43d  hybrid
0bb6e01380cd74102c5203d8fd18042087b7c1a87d78befe314a258b533a6e33  native
```

The archived block arrays, timestamped controller logs, full-pool proofs and
agreements accompany these results. Original evidence is at
`/tmp/pqcauth-allpools91c.GJtlhg/`; the recorded `run.sh` requires fresh paths
and container names before replay. The executed harness hashes in `manifest.json`
precede a comment-only correction explaining raw header times. The new harness
has 21 passing Python regression tests; the 10 release-tool tests also pass.

Remaining review items: define target per-validator hardware and a prospective
steady-load sampling protocol, then measure recheck separately and exercise
maximum-gas/size and invalid-admission cases. The restart-before-first-block
account-number observation above should receive a separate SDK startup regression;
it was not fixed by changing authentication. Public testnet/IBC and final-version
artifact acceptance still require their separate authorized workflow.
