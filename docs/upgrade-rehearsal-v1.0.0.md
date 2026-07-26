# v1.0.0 Upgrade Rehearsal

`scripts/rehearse-v1.0.0-upgrade.sh` performs a production-shaped,
single-validator rehearsal of the upgrade that introduces the Sponsor module.
It is an operator-run tool and is not executed by CI.

## What it exercises

The script:

1. resolves and records exact old/new Git commits;
2. rejects an old revision that already contains `x/sponsor-contract-tx`;
3. builds both binaries from detached Git worktrees;
4. starts an isolated chain with the old binary;
5. optionally stores and instantiates the counter contract with a Wasm admin;
6. submits and passes the real `v1.0.0` software-upgrade proposal;
7. verifies that the old binary halts and writes the matching
   `data/upgrade-info.json`;
8. copies the halted node home for rollback;
9. starts the new binary against the same node home;
10. verifies the applied upgrade, Sponsor store initialization, Sponsor module
    version `1`, Wasm module version `4`, default Sponsor parameters, balances,
    and pre-upgrade contract state;
11. in full mode, verifies ticket consumption, duplicate one-use-ticket
    rejection, user grant accounting, Admin-clear protection, Sponsor
    generation isolation, and Admin clear after Sponsor deletion.

All node data, test mnemonics, binary hashes, logs, transaction responses and
the final summary are retained in a new `.rehearsal/` directory.

## Prerequisites

- Bash
- Git
- Go
- `jq`
- `curl`
- either `sha256sum` or `shasum`
- a prebuilt counter Wasm artifact for full Sponsor testing

The supplied `--old-ref` must be the exact revision used before the Sponsor
module was introduced. For the repository history, `0.4.4` is the expected
baseline, but operators should use the actual deployed commit rather than
assuming a tag.

## Full rehearsal

Build the counter contract separately, then run:

```bash
scripts/rehearse-v1.0.0-upgrade.sh \
  --old-ref 0.4.4 \
  --new-ref audit-review \
  --wasm /absolute/path/to/counter.wasm
```

The script refuses to reuse an existing work directory. To choose an explicit
location:

```bash
scripts/rehearse-v1.0.0-upgrade.sh \
  --old-ref 0.4.4 \
  --new-ref <release-commit> \
  --wasm /absolute/path/to/counter.wasm \
  --work-dir /safe/test/path/doravota-v1-rehearsal
```

## Upgrade-only rehearsal

To validate only the disk upgrade, StoreLoader, migrations and module
initialization:

```bash
scripts/rehearse-v1.0.0-upgrade.sh \
  --old-ref 0.4.4 \
  --new-ref <release-commit> \
  --upgrade-only
```

## Result interpretation

Success produces:

- `PASSED`
- `reports/summary.json`
- `reports/manifest.json`
- `reports/upgrade-info.json`
- `logs/old-node.log`
- `logs/new-node.log`
- `node-home-before-upgrade/`
- the final upgraded `node-home/`

`check_state_reservation_same_height: true` means the duplicate one-use-ticket
transaction was rejected while both submissions were observed at the same
height. A value of `false` still proves that the old ticket could not authorize
two transactions, but the run crossed a block boundary; rerun the rehearsal to
exercise the same-height mempool case.

The generated `secrets/` and node homes contain test mnemonics and use the test
keyring. They must never be reused for a public network.

## Scope

This script intentionally covers one validator. Release approval should also
include a separate four-validator rehearsal, delayed-validator catch-up,
rolling restarts, app-hash comparison across validators, and an isolated
production-snapshot rehearsal.
