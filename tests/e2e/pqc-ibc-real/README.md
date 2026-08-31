# Real-node PQC IBC simulation

This harness runs two independent Dora chains on one Linux host and exercises
IBC before and after both validator consensus keys are rotated from Ed25519 to
ML-DSA-65.

Unlike `tests/e2e/pqc-ibc`, this is not an in-memory application test. It uses:

- two real `dorad`/CometBFT processes;
- real RPC, gRPC, keyrings, blocks, transactions and IBC proofs;
- `cosmos/relayer` only for the pre-rotation channel handshake;
- `pqcibc-relayer` for ML-DSA-aware client updates, packet receives and
  acknowledgements;
- a controlled process stop at the H+1 transition header before installing the
  rotated consensus private key.

The runner never deletes an existing work directory. Each invocation creates a
timestamped directory, constrains each node to 10 CPU and 30 GiB, and writes a
machine-readable result plus a Chinese report under `artifacts/`.

```bash
tests/e2e/pqc-ibc-real/run.sh
```

Required host software: Docker, `jq`, `curl`, `sed`, and a Dora v0.55 binary
linked with CometBFT v0.40. The binary directory must also contain the wasmvm
shared library. Override defaults with:

```bash
DORAD_DIR=/path/to/runtime \
WORK_ROOT=/path/to/results \
NODE_CPU=10 NODE_MEMORY=30g \
tests/e2e/pqc-ibc-real/run.sh
```

The normal success path leaves both nodes running for inspection. Set
`KEEP_RUNNING=0` to stop them after evidence collection. The script always
prints the work directory and container names.
