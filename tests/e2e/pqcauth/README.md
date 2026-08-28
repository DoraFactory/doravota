# PQCAuth real-node E2E

This harness starts a brand-new Doravota network and exercises `x/pqcauth`
through real CLI transactions, CometBFT consensus, AnteHandler execution and
state commits. It does not reuse or delete an existing node home.

## Run

```bash
# Four validators, full lifecycle and validator restart test.
tests/e2e/pqcauth/run.sh

# Fast single-validator run.
E2E_NODES=1 tests/e2e/pqcauth/run.sh

# Use a prebuilt binary and preserve a successful network for inspection.
DORAD_BIN=/path/to/dorad \
PQCTX_BIN=/path/to/pqctx \
E2E_KEEP_RUNNING=true \
tests/e2e/pqcauth/run.sh --work-dir /new/isolated/directory
```

The default work directory is `.e2e/pqcauth/<UTC timestamp>-<pid>`. It contains
test-only Cosmos mnemonics and ML-DSA private keys and is created with a
restrictive umask. The directory is intentionally preserved after success and
failure so the transaction JSON, state queries and node logs can be audited.

The final machine-readable result is `reports/report.json`. It includes the
source commit, elapsed time, final height/app hash, every assertion, and gas plus
wire-size metrics for each successful transaction. Raw node logs, proposals,
queries, transaction responses and rejection evidence remain beside it.

## Covered lifecycle

- fresh genesis and real validator networking;
- classic compatibility for an unregistered account;
- registration proof validation and H+1 activation;
- self-enforcement and missing-PQC rejection;
- arbitrary bank transactions through offline PQC sign bundles;
- offline bundle mutation detection;
- signing-key rotation and stale-bundle rejection;
- recovery-key rotation and historical-key revocation;
- Recovery v2 transaction-bound offline recovery, including a delayed
  activation challenge window, continued use of the current signing key,
  current-key cancellation, permanent revocation of the cancelled candidate
  key ID, and a second successful delayed recovery;
- H+1 self-protection changes;
- simulation gas estimation without real ML-DSA verification;
- deterministic cryptographic gas estimation against the effective on-chain
  verification parameters;
- native ML-DSA direct transactions in both `OPTIONAL` and `REQUIRED`, plus
  rejection of redundant `pqcauth` registration for native accounts;
- real CheckTx rejection of invalid signature, signer, key, policy, algorithm,
  signer index, canonical encoding, size, placement and extension ordering;
- a cryptographically valid raw transaction rejected by Ante during the
  `PAUSE_PQC_TRANSACTIONS` emergency state (bypassing wallet preflight);
- nested `authz.MsgExec` lifecycle execution rejected in DeliverTx without a
  state change;
- rejection of protection activation with a pre-existing authz grant;
- protected-granter delegation restricted to PQC-enforced classic or native
  grantees, including runtime rejection after a grantee drops protection;
- feegrant creation and use restricted to PQC-enforced grantees, including
  runtime containment of allowances created before the granter enabled PQC;
- unbounded monotonic key IDs with bounded per-role terminal history, including
  preservation of active signing and recovery records;
- governance proposal submission, bonded-validator voting and H+1 activation
  for `OPTIONAL`, `DISABLED`, `REQUIRED_FOR_REGISTERED`, and final `REQUIRED`;
- both emergency modes, including existing-key continuity during
  `PAUSE_NEW_KEYS` and classic-account continuity during a full PQC pause;
- registration migration from `OPEN` to `FRESH_ACCOUNTS_ONLY`, including an
  already-exposed legacy account migrating while open, first-transaction
  registration for a fresh account, and rejection after classic-key exposure;
- observable and irreversible registration cutoff enforcement;
- one-validator outage, continued consensus, restart and catch-up;
- cross-node app-hash convergence.

The test keyring and private key files are not production key-management
examples. They exist only inside the isolated E2E work directory.
