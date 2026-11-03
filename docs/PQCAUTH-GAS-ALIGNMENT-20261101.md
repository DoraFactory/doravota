# PQCAuth verification gas alignment — 2026-11-01

Historical English summary. Results below belong to the recorded revision, not current release acceptance. Current behavior: [module README](../x/pqcauth/README.md).

Baseline: `8a8b6892a7458f4cfe752332a2b5fe3835fe54ae`. Authorization/proof default and minimum prices changed from 250,000 to 750. The original 250,000 was a module-selected value traceable to `71d6f06`, without a reproducible benchmark conversion supporting that exact number.

## Meaning of the price

Both paths eventually use SDK ML-DSA-65 verification. The new value references pinned SDK v0.55.0 `DefaultSigVerifyCostMlDsa65`, with tests locking 750; it is not a dynamic read of x/auth and not the cost of the entire Ante path. Bytes, storage, classical signatures and message execution are separately charged. Native ML-DSA also carries a large signature, so the entire signature size is not the hybrid/native difference.

Protected signing order remains: construct transaction/fee/sequence → PQC-sign the document excluding its self-referential authorization extension → attach extension → classical DIRECT-sign the complete transaction. Both authentications remain required. Ordinary protected send uses one PQC verification; registration and typical rotation use two. Extra payers/proofs add work.

Stored valid higher prices were not rewritten; active/pending heights remained authoritative. Changing a signed bundle's fees requires re-preparation/signing. This historical revision retained 16/400 quotas; they were later removed and the two price fields merged. No public deployment occurred.

## Recorded signed-transaction samples

| Operation | Price | Bytes | Simulated gas | Executed gas |
| --- | ---: | ---: | ---: | ---: |
| Protected send | 750 | 3,730 | 126,523 | 126,523 |
| Protected send | 751 | 3,730 | 126,524 | 126,524 |
| Protected send | 250,000 | 3,730 | 375,791 | 375,791 |
| Two-key registration | 750 | 10,803 | 320,435 | 320,132 |
| Two-key registration | 751 | 10,803 | 320,437 | 320,134 |
| Two-key registration | 250,000 | 10,803 | 818,947 | 818,644 |

These are test-state samples, not fixed production fees. Different encoded parameter lengths contribute to the old/new difference; 750/751 isolate price changes with identical encoding length. Missing PQC authorization still failed. The retry-OOG test switched from a hardcoded limit to simulation minus 1,000, retaining successful CheckTx and failed-message/retry assertions.

## Historical microbenchmark

Intel Core Ultra 7 265, one Go worker, 300 ms per case, three repeats; medians below. Both paths verified identical final bytes. The wrapper additionally built the envelope, copied the public key and performed a then-redundant parse (removed later).

| Message bytes | SDK | Wrapper | Ratio |
| --- | ---: | ---: | ---: |
| 256 | 65.470 µs | 107.651 µs | 1.64 |
| 4,096 | 71.455 µs | 114.904 µs | 1.61 |
| 65,536 | 150.472 µs | 215.592 µs | 1.43 |

SDK: about 41,474 B/op, six allocations; wrapper: 84,834/89,410/158,274 B/op, eleven allocations. These results do not support a 333-fold fee gap, but do not prove full-path equivalence, target-hardware capacity or exact nanoseconds-to-gas conversion.

## Validation and evidence

The gas-only stage passed 617 test/subtest events, 14 packages, three explicit simulations, seven Python tests, 906 IBC files and vet using Go 1.26.10. Tests rejected 749, accepted 750/751/250,000 across parameter paths and verified activation boundaries. The combined emergency-fix stage had a separate result; counts must not be conflated.

Logs: `/tmp/pqcauth-gas750-gate-final.log`, `/tmp/pqcauth-gas750-gate-final/{unit,simulations}.jsonl`, `/tmp/pqcauth-gas750-vet.log`, `/tmp/pqcauth-gas750-benchmark.log`. Initial stale-assertion failures remain in `/tmp/pqcauth-gas750-gate/unit.jsonl`.

Reproduce the benchmark with `GOMAXPROCS=1 go test ./x/pqcauth/crypto -run '^$' -bench '^BenchmarkMLDSA65GasBaseline$' -benchmem -benchtime=300ms -count=3` on the appropriate revision. Network admission, recheck, worst-case payloads, fairness and final-artifact snapshot/testnet acceptance were not established by these measurements.

[Original detailed record at the documentation-cleanup baseline](https://github.com/DoraFactory/doravota/blob/eb5bbec2a88a36224bd27c5b487f3d726a6bfeda/docs/PQCAUTH-GAS-ALIGNMENT-20261101.md). Original evidence files were not translated or modified.
