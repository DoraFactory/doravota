# Two-node PQC capacity benchmark

This benchmark runs two Docker-constrained Doravota validators and measures
full-block behavior for classic secp256k1 transactions, PQC Auth hybrid
transactions, and native Cosmos SDK ML-DSA-65 transactions. Both validators use
ML-DSA-65 consensus keys.

The default server profile assigns CPUs `0-7` and `8-15` plus 24 GiB of
non-swappable memory to the two validators. CPUs `16-19` remain available for
fixture generation and transaction submission. The containers share the host
kernel, storage, and loopback network, so this is a reproducible capacity test,
not a substitute for a multi-machine latency and fault-tolerance test.

The loader creates one funded genesis account per transaction. This avoids the
ordered-mempool sequence conflict that would otherwise prevent many consecutive
transactions from one account from being admitted before a block commits.
Generated private keys are deterministic test fixtures and must never be used
outside the disposable benchmark network.

The default per-transaction gas limits include measured headroom for first-use
account state writes: 120,000 classic, 400,000 hybrid, and 320,000 native
ML-DSA. Any failed DeliverTx result makes the benchmark fail.

Run on the target Linux server from the repository root:

```bash
PQC_CAPACITY_WORK_DIR=/root/pqcauth-capacity-$(date -u +%Y%m%dT%H%M%SZ) \
  ./tests/performance/pqcauth-two-node/run.sh
```

The work directory contains the genesis fixture manifest, CheckTx results,
per-block transaction/byte/gas records, Docker CPU and memory samples, the
ML-DSA gas calibration result, validator logs, and `capacity-summary.json`.
Genesis bank supply is recomputed with arbitrary-precision integer arithmetic,
so DORA's 18-decimal staking amounts are not rounded by JSON tooling.

The defaults can be changed with environment variables such as
`PQC_CAPACITY_CLASSIC_COUNT`, `PQC_CAPACITY_HYBRID_COUNT`,
`PQC_CAPACITY_NATIVE_COUNT`, `PQC_CAPACITY_NODE_MEMORY`, and the three CPU-set
variables documented at the top of `run.sh`. `PQC_CAPACITY_BUILD_CACHE` can
point multiple disposable runs at the same Go module and compiler cache.

## Steady-state and adversarial profile

The same constrained network can run with both validators continuously online.
This profile sends a 40/30/30 mix of classic, PQC Auth hybrid, and native
ML-DSA transactions at planned 30%, 60%, and 90% block-gas utilization. It then
runs a 60% valid stream concurrently with rejected traffic containing:

- correct-length but invalid ML-DSA signatures;
- canonical pqcauth extensions above the byte limit;
- non-canonical protobuf encodings; and
- validly signed transactions with a bad account sequence.

The default engineering run uses two minutes per phase and 300 rejected
transactions per second. Durations and rates are configurable; a release soak
should use at least 1-2 hours rather than treating the short default as a
long-running stability result.

```bash
PQC_CAPACITY_PROFILE=stress \
PQC_CAPACITY_WORK_DIR=/root/pqcauth-stress-$(date -u +%Y%m%dT%H%M%SZ) \
  ./tests/performance/pqcauth-two-node/run.sh
```

Use `PQC_STRESS_DURATION`, `PQC_ADVERSARIAL_DURATION`,
`PQC_ADVERSARIAL_RATE`, `PQC_STRESS_TARGETS`,
`PQC_STRESS_VALID_WEIGHTS`, and `PQC_STRESS_ATTACK_WEIGHTS` to change the load
plan. The resulting `stress-summary.json` reports confirmation latency, block
intervals, consensus rounds, throughput, gas, bytes, and delivery failures.
The rejected-stream summary groups outcomes by attack class and ABCI error
code. Resource samples remain in `docker-stats.csv`.

This remains a single-host test. It measures validation and consensus behavior
under controlled CPU and memory limits, but it does not replace cross-machine
latency, packet-loss, validator-HSM, or IBC-counterparty testing.
