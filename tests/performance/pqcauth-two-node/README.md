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
