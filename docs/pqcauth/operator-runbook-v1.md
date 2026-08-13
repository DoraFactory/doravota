# pqcauth operator runbook v1

## Rollout order

1. Rehearse and deploy an SDK v0.53 / IBC-Go v10 bridge release for the
   currently deployed SDK v0.47 state.
2. After the bridge state is stable, deploy the SDK v0.55 / IBC-Go v11 target
   binary and add the `pqcauth` store through the `v1.0.0` upgrade.
3. Keep module enforcement in `OPTIONAL` while users register keys.
4. Publish the chain ID, base64 `network_id`, registration cutoff, supported
   algorithm, proof contexts, and activation heights through independent
   channels.
5. Require users to verify their queried key, effective height, and policy
   version before moving funds.
6. Set an irreversible registration cutoff. A cutoff at height `C` rejects
   first registration at every height `>= C`; it does not block rotation or
   recovery of existing accounts.
7. Activate `REQUIRED_FOR_REGISTERED` before considering global `REQUIRED`.

The v1.0.0 binary commits distinct launch-specific `network_id` values for
`vota-ash` and `vota-testnet`. A custom chain derives a chain-specific
development value unless its genesis supplies an explicit value. A same-chain-ID
fork that intends to become a separate security domain must choose a new
network ID before launch; the value is immutable after initialization.

All mutable pqcauth parameters are scheduled as one atomic bundle. Relaxations
and an emergency-only change activate at H+1. Changes that can invalidate a
currently valid transaction wait the genesis-fixed
`governance_safety_delay_blocks`: enforcement escalation, the first
registration cutoff, algorithm removal, verification-gas increases, and lower
signer or extension-size limits. Parameter queries expose the future activation
height and normalize a bundle once that height arrives.

`governance_safety_delay_blocks` and `max_emergency_duration_blocks` are launch
parameters and cannot be changed by governance. Their defaults are 17,280
blocks; calibrate both in genesis against the target block time and document the
resulting wall-clock windows before launch. Governance must submit
`emergency_expires_height=0`; the module computes the real exclusive expiration
height and automatically returns the mode to `NORMAL` in BeginBlock.

`max_retained_key_records_per_role` bounds complete terminal records, not key
creation. Key IDs remain monotonic and are never reused, but accounts cannot be
locked by exhausting a small lifetime quota. The default retains 16 complete
records independently for signing and recovery (hard parameter limit 64).
Older terminal records are folded into a deterministic per-role hash-chain
commitment exposed by the account query. Current and pending signing/recovery
keys are always pinned and do not count toward retention. Operators should
monitor `compacted_count`, retain exported genesis/history commitments, and
archive transaction/event history externally when full historical detail is
required.

Registration always supplies distinct signing and recovery keys and activates
`self_enforced=true` atomically at H+1. A signing-only or non-self-enforcing
registration is invalid. The recovery private key must be generated and backed
up separately from the online signing key before broadcasting registration.

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
the same rule: all structural, policy, retention, emergency, and proof-length checks
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

- `PAUSE_NEW_KEYS` stops registration and ordinary key rotation but does not
  weaken authentication on ordinary protected transactions.
- `PAUSE_PQC_TRANSACTIONS` freezes PQC-authorized and protected-account
  transactions. It never falls back to classical-only authorization.
- Both pauses expire automatically. During either pause, the only account
  lifecycle escape hatch is one top-level `MsgRecoverKey`. Ante still verifies
  the classical signature, the registered recovery key's signature over the
  complete transaction, and the replacement signing key's proof of possession.
  Batched or nested recovery and all other lifecycle messages remain rejected.
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

## Release dependency and migration gate

The target application now builds on Cosmos SDK v0.55.0, CometBFT v0.40.0,
IBC-Go v11.2.0 and Wasmd v0.70.3 compatibility source. pqcauth calls the SDK's
native ML-DSA-65 key API; CIRCL is an indirect dependency of CometBFT rather
than a direct pqcauth API.

The production chain is still an SDK v0.47 / IBC-Go v7 chain. Directly loading
that state with this target is unsupported: SDK v0.55 no longer contains the
legacy `x/params` migrations, and IBC-Go v11 cannot start its migration graph
from the old IBC v7 module versions. The v1.0.0 handler therefore validates the
module version map and rejects a direct jump before changing state.

Production approval requires two independently versioned releases:

- bridge: SDK v0.53.x, IBC-Go v10.x and a compatible Wasmd v0.61.x line;
- target: this SDK v0.55 / IBC-Go v11 / pqcauth release.

Run both upgrades in sequence against an exact production-state snapshot.
Compare app hashes across all validators after each height and exercise bank,
staking, governance, IBC, ICA, Wasm, authz, feegrant and group state before
moving to the next stage. The target removes `params`, `capability` and
`feeibc`, but preserves the historical `group` store through a pinned v0.53.6
compatibility implementation.

Wasmd v0.70.3 officially targets SDK v0.54, so the target currently carries a
pinned compatibility snapshot and a fail-fast stub for the no-longer-supported
Wasm v2→v3 legacy params migration. The bridge must bring Wasm to consensus
version 4 first; the target refuses older Wasm state.

The 2026-08-02 scan in the historical E2E report was for the SDK v0.47
candidate and is not evidence for this dependency graph. On 2026-08-13 the
target was rescanned with Go 1.26.5 and govulncheck 1.6.0:

```text
GOTOOLCHAIN=go1.26.5 go run golang.org/x/vuln/cmd/govulncheck@v1.6.0 \
  -show verbose ./...
```

The scanner reported four symbol-reachable IDs. Manual triage is required
because the vulnerability database did not yet model all 2026 branches and
backports correctly:

- `GO-2026-4513` and duplicate `GO-2026-4740` identify the same malformed
  MessagePack extension-frame panic reached through WasmVM metrics decoding.
  This target pins the upstream v2 security backport commit
  `04a026e9ac24` merged in `shamaton/msgpack#66`. The upstream public API is
  unchanged, and `TestMsgpackRejectsTruncatedExtensionFrames` asserts that all
  fixext markers return an error instead of panicking. Govulncheck continues to
  report the IDs because the Go vulnerability database still says that no v2
  fixed version exists. Replace the pseudo-version with the first tagged v2
  release containing that commit when one is published.
- `GO-2024-2584` is a scanner range false positive for SDK v0.55.0. The Cosmos
  advisory lists only releases through v0.47.9 and v0.50.4 as affected; the
  patched releases were v0.47.10 and v0.50.5. Preserve a link to that advisory
  in release evidence rather than suppressing the ID without explanation.
- `GO-2026-5932` remains an unresolved upstream finding. SDK v0.55.0 uses the
  unmaintained `x/crypto/openpgp/armor` package only as the ASCII-armour framing
  layer for local SDK keyring records; private-key confidentiality and
  integrity use Argon2 plus ChaCha20-Poly1305. This path is not driven by a
  transaction or consensus message, but processing a malicious local keyring
  record remains outside the production trust boundary. Validator and relayer
  production signers must therefore use an OS-backed keyring, HSM, or remote
  signer with protected local files, and must not import untrusted armour. A
  maintained SDK armour replacement or an explicit, reviewed release exception
  is required before final production approval.

The scanner additionally reported three module-level IDs without a vulnerable
symbol call from this application. `GO-2025-3442` is a CometBFT blocksync range
false positive: v0.40.0's `BlockPool.SetPeerRange` already bans a peer that
lowers its previously reported range and includes the malicious-peer regression
tests from the advisory fix. The two `x/crisis` IDs are not reachable because
this application does not mount or execute `x/crisis`.

This triage is evidence for this exact target dependency graph only. Run the
same scan independently on the bridge and final target commits with the release
toolchain. Vulnerability database results change over time; never use the count
or the false-positive decisions as a permanent allowlist. New reachable
Critical or High findings remain release blockers until fixed or reviewed with
equivalent source-level and behavioral evidence.

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
gas only through an announced, consensus-scheduled parameter update and retain
the existing finite block limit until the new benchmark has been reproduced by
every supported validator architecture.
