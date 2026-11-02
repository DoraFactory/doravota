# Isolated rehearsal restart-port fix — 2026-11-02

During verification of `6fd5c8d`, GitHub Actions run `41458421165`, ARM64 job
`125321747843`, failed in the packaged lifecycle rehearsal after its intentional
four-node restart. The node2 restart log (`node2-6.log`) records:

```text
Error: listen tcp 127.0.0.1:47956: bind: address already in use
```

The harness then timed out waiting for that node's RPC endpoint. This confirms a
listener bind failure, not a PQC authentication failure. The old default RPC base
47757 puts all eight test listeners in the usual Linux ephemeral allocation range
32768–60999. While a listener is stopped, outgoing connections can use its port.
The artifact does not identify the actual owner of the conflicting socket, so
this mechanism is a risk explanation, not a recovered socket-owner trace.

## Change

- Use RPC base 28657 by default (four RPC/P2P pairs, ending at 28957).
- On Linux, read the actual `ip_local_port_range` and reject any intersecting
  listener before initializing the chain. Do not assume every host has the
  default kernel range, and do not modify host sysctls.
- Validate all eight port numbers; preflight their availability as before.
- Save listener ports and the observed kernel range in the evidence directory.
- Explicit custom ports remain supported outside the host's ephemeral range.
  An independent process can still take an unreserved port; this is not a claim
  that arbitrary shared-host port conflicts are impossible.

Only test harness/tool tests change. No application, consensus, gas, signature,
parameter or dependency changes. No node restart retry suppresses the failure.

## Local checks

`test-release-tools.py`: 9 tests passed, including two new tests for old/default
ports, later-validator overlap, nondefault kernel ranges and port boundaries.
`test-pqcauth-capacity.py`: all 16 tests passed. `git diff --check` passed.

The failed ARM64 run is retained as evidence, not relabeled successful. A new CI
run is required after pushing this change. The capacity experiment on the remote
host uses isolated containers with base 28657 and is unaffected by the old
lifecycle-only default. Its completion and performance limits are recorded
separately; successful unit tests are not a substitute for the restart rehearsal.
