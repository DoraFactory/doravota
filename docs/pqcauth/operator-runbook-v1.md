# pqcauth operator runbook v1

## Rollout order

1. Deploy the binary and add the `pqcauth` store through the `v1.0.0` upgrade.
2. Keep module enforcement in `OPTIONAL` while users register keys.
3. Publish the chain ID, base64 `network_id`, registration cutoff, supported
   algorithm, proof contexts, and activation heights through independent
   channels.
4. Require users to verify their queried key, effective height, and policy
   version before moving funds.
5. Set an irreversible registration cutoff. A cutoff at height `C` rejects
   first registration at every height `>= C`; it does not block rotation or
   recovery of existing accounts.
6. Activate `REQUIRED_FOR_REGISTERED` before considering global `REQUIRED`.

The v1.0.0 binary commits distinct launch-specific `network_id` values for
`vota-ash` and `vota-testnet`. A custom chain derives a chain-specific
development value unless its genesis supplies an explicit value. A same-chain-ID
fork that intends to become a separate security domain must choose a new
network ID before launch; the value is immutable after initialization.

All mutable pqcauth parameters are scheduled as one atomic bundle for H+1.
Parameter queries are normalized at the queried height: a future pending bundle
is included, while a bundle whose activation height has arrived is applied and
cleared from the response.

`max_keys_per_account` is a lifetime key-record quota, not a live-key quota.
The default permits eight total signing and recovery records per account
(including initial registration); retired and revoked records continue to
count, and key IDs are never reused. Before any rotation or recovery, query the
account's key list and confirm capacity remains. Operators should alert before
accounts approach the limit and publish a migration policy rather than raising
the bound reactively. The protocol deliberately keeps this quota finite so
repeated rotate/revoke cycles cannot grow consensus state without bound.

## CLI flow

Generate a private key file and public key:

```text
dorad tx pqcauth keygen account.mldsa65
```

The command refuses to overwrite a file and creates it with mode `0600`.
Generate registration or rotation proofs with `create-key-proof`; obtain
`network_id` from `dorad query pqcauth params`. Registration proofs use policy
version `0`. Rotation and recovery proofs use the currently queried policy
version.

Rotate an offline recovery key by generating a proof with role `recovery` and
purpose `rotate-recovery`, then submit `rotate-recovery-key` using the active
transaction-signing PQC private key. Keep the old recovery key available until
the query at H+1 reports the replacement as `recovery_key_id`; only then may the
inactive historical key be revoked or destroyed.

Protected single-signer transactions use:

```text
--sign-mode direct --pqc-private-key-file account.mldsa65
```

The client queries the effective policy, creates AuthInfo, attaches the
ML-DSA-65 extension, verifies the new signature locally against the on-chain
public key, and only then creates the classical signature.

For `--gas auto` and `--simulate`, the protected client sends a state-bound
placeholder extension with the real signer, key ID, algorithm, policy version,
and exact ML-DSA-65 signature length. Ante validates that structure and current
chain metadata, charges the configured verification gas, but does not perform
ML-DSA verification during simulation. Lifecycle key and recovery proofs follow
the same rule: all structural, policy, quota, emergency, and proof-length checks
remain active, while their configured proof gas replaces the cryptographic
operation. The placeholder is used only by the simulation factory and is never
retained in the transaction that is signed or broadcast. DeliverTx remains
fail-closed and rejects a placeholder or any other invalid PQC signature. A
pure `--simulate` invocation therefore does not require a PQC private-key or
bundle-output flag; `--gas auto` followed by a real broadcast still does.

For an offline or air-gapped ML-DSA key, use the versioned bundle flow. First,
generate the intended transaction as standard Cosmos JSON:

```text
dorad tx bank send alice dora1... 10peaka \
  --from alice --chain-id doravota-1 --fees 1000peaka --gas 200000 \
  --generate-only > unsigned-tx.json
```

On an online machine, freeze that transaction together with the current
account number, sequence, network ID, active PQC key, and policy version:

```text
dorad tx pqcauth prepare-bundle unsigned-tx.json prepared.pqcbundle \
  --from alice --chain-id doravota-1 --node tcp://node:26657
```

Move `prepared.pqcbundle` to the offline machine. Review the decoded transaction
JSON plus the chain ID, signer, account number, sequence, key ID, policy
version, transaction SHA-256, and sign-document SHA-256 printed by:

```text
dorad tx pqcauth sign-bundle \
  prepared.pqcbundle account.mldsa65 signed.pqcbundle
```

Move only `signed.pqcbundle` back online, then revalidate and broadcast:

```text
dorad tx pqcauth broadcast-bundle signed.pqcbundle \
  --from alice --chain-id doravota-1 --node tcp://node:26657
```

The bundle commands create files with mode `0600`, publish them atomically, and
refuse to overwrite an existing path. `broadcast-bundle` refuses fee, gas,
memo, payer, granter, timeout, sequence, and sign-mode overrides because these
fields were frozen before the ML-DSA signature. It re-queries chain state and
fails if the account number, sequence, network ID, active key, public key, or
policy version changed. The classical signature is produced only after this
revalidation and after the PQC extension is attached.

The protected `rotate-key`, `rotate-recovery-key`, `set-protection`, and
`revoke-key` commands can skip the intermediate generate-only JSON by using
`--pqc-sign-bundle-output prepared.pqcbundle` instead of
`--pqc-private-key-file`.

Signing-key recovery never accepts a standalone recovery signature. Prepare a
transaction-bound bundle on the online machine:

```text
dorad tx pqcauth recover-key 2 3 NEW_PUBLIC_KEY NEW_KEY_PROOF \
  --from alice --chain-id doravota-1 --fees 1000peaka --gas 500000 \
  --recovery-sign-bundle-output prepared.recoverybundle
```

Review and sign it on the offline recovery-key machine:

```text
dorad tx pqcauth sign-recovery-bundle \
  prepared.recoverybundle recovery.mldsa65 signed.recoverybundle
```

Return only the signed bundle and revalidate it online before the classical
signature is added:

```text
dorad tx pqcauth broadcast-recovery-bundle signed.recoverybundle \
  --from alice --chain-id doravota-1 --node tcp://node:26657
```

The recovery signature binds fee, gas, payer, granter, tip, memo, timeout,
account number, sequence, signer identity, full AuthInfo, and the sole
`MsgRecoverKey`. None of those fields may be overridden during broadcast.

Lifecycle messages (`register-key`, rotations, recovery, protection changes,
and revocation) must be the sole top-level message in a transaction. They are
rejected when wrapped by `authz`, group proposals, wasm dispatch, governance,
or another module route, even when the inner message contains otherwise valid
proof fields.

Integrations that keep keys outside the node process can implement the Go
client's `PQCSigner` boundary. The client checks the backend's algorithm and
public key against chain state and verifies every returned signature locally
before attaching the critical extension. A remote signer should enforce its own
authenticated transport, request timeout, approval policy, and audit log.

## Fail-closed incidents

- `PAUSE_NEW_KEYS` stops registration, rotation, and recovery but does not
  weaken authentication on ordinary protected transactions.
- `PAUSE_PQC_TRANSACTIONS` freezes PQC-authorized and protected-account
  transactions. It never falls back to classical-only authorization.
- An account with `self_enforced=true` remains protected even if governance
  changes the global mode to `DISABLED`.
- A policy that references a missing, revoked, mistyped, or not-yet-effective
  current signing key is treated as inconsistent consensus state and rejected;
  it never falls back to classical-only authorization.
- The proposal handlers reject any transaction that fails Ante verification;
  they also enforce finite byte and declared-gas totals when legacy consensus
  parameters are unlimited.

Before production, rehearse both modes on a fork and confirm identical results
on amd64 and arm64.

## Release dependency gate

The application currently remains on the Cosmos SDK 0.47 compatibility family.
The PQC implementation does not make the full node production-ready while the
following upstream findings remain reachable:

- CometBFT 0.37 has peer-driven blocksync and block-part denial-of-service
  findings. Their upstream advisories do not share a single compatible minimum
  fix version for this application line.
- Wasmd still has simulation and unbounded-address validation findings whose
  fixes require the 0.52/0.53 line.
- Cosmos SDK `x/crisis` has unresolved fee and halt semantics findings.
- The Cosmos keyring dependency still brings in the unmaintained
  `x/crypto/openpgp` package, for which no patched release exists.

Do not activate production enforcement until an application-wide migration has
been rehearsed with at least Cosmos SDK 0.50.14, a compatible CometBFT release
for which both findings are cleared by the exact-release security scan, Wasmd
0.53.2 or newer, and a keyring/backend decision that removes or explicitly
contains OpenPGP. Run `govulncheck ./...` on the exact release toolchain and
treat any reachable Critical or High result as a release blocker.
These are application dependency gates, not weaknesses in ML-DSA verification,
but they affect the security of the node that enforces it.

## Observability

Lifecycle state changes emit `pqc_register_key`, `pqc_rotate_key`,
`pqc_rotate_recovery_key`, `pqc_set_protection`, `pqc_revoke_key`, and
`pqc_recover_key` events. Verification telemetry uses fixed-cardinality
`pqcauth` / `pqc_verify` counters and timers, split into
`transaction_signature`, `key_proof`, and `recovery_signature`, with only
`success` or `failure` result dimensions. Addresses, key IDs, public keys, and
signatures are never metric labels.

Alert on a sustained verification-failure increase, proposal rejection spikes,
or verification latency approaching the gas calibration envelope. Recalibrate
gas only through an announced H+1 parameter update and retain the existing
finite block limit until the new benchmark has been reproduced by every
supported validator architecture.
