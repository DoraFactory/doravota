# PQCAuth

PQCAuth adds an ML-DSA-65 signing factor to an existing classical account without
changing its address, assets or account public key. A protected transaction needs
both the account signature and a PQC signature in a critical transaction extension.
The PQC factor is a registered public key, not a second spending account or a new
multisig address. A separate recovery key can replace the PQC signing factor;
it cannot recover the classical private key.

This README describes the current v1.1.0 candidate, not live-chain configuration
or release approval. The candidate version is `v1.1.0`; a version string alone
does not mean a release tag has been published or deployment approved.

## Scope and restrictions

- Enrollment supports single-key classical accounts (`secp256k1`, `ed25519`,
  `secp256r1`, subject to SDK support). Native ML-DSA accounts use SDK signatures
  directly and cannot enroll. Composite/multisig accounts cannot enroll either;
  their ordinary SDK transactions remain supported under phase-one modes.
- Registration enables self-protection; `--self-enforce=false` is rejected.
  Registration, rotation and protection changes normally activate at H+1, where
  H is the successful execution height. Recovery uses its separate delay.
- Registration and transactions requiring a PQC extension require DIRECT mode
  for every signer. The SDK's Amino-only Ledger backend cannot register.
  Ordinary unprotected Amino transactions are unaffected.
- Each lifecycle operation must be the only top-level message. Authz, governance,
  group, contracts and ICA cannot execute these operations indirectly.
- Authz/Feegrant permissions are **not revoked or additionally protected** by
  enrollment or recovery. A grantee can still exercise its grants without the
  owner's PQC factor; a protected grantee needs its own factor. Review unwanted
  grants separately. Consensus keys and IBC light-client algorithms are out of scope.
- The bundled CLI handles single-signer transactions. Chain-level multi-signer
  and independent fee-payer support does not imply CLI orchestration support.

## Parameters

### Governable settings

These are the only three mutable policy fields. Names below omit enum prefixes.

| Field | Default | Meaning / allowed values |
| --- | --- | --- |
| `enforcement_mode` | `OPTIONAL` | `OPTIONAL`: enrolled accounts require PQC when self-protection is on. `REQUIRED_FOR_REGISTERED`: all enrolled accounts require it, even if self-protection is off. Unregistered accounts remain usable. `DISABLED`, global `REQUIRED` and `UNSPECIFIED` are rejected. |
| `verification_gas` | `750` | Gas charged before each PQC authorization, recovery signature or new-key proof; range 750–10,000,000, with the block-gas sanity check below. |
| `emergency_mode` | `NORMAL` | `NORMAL`, `PAUSE_NEW_KEYS`, or `PAUSE_PQC_TRANSACTIONS`; see governance rules below. |

750 is **not the total transaction gas**. Account-signature verification, bytes,
storage and message execution cost additional gas. A protected send adds one
PQC verification; registration has two key proofs. SDK-native ML-DSA signatures
use the separate x/auth price path, with a 750 floor. PQCAuth's price references
the pinned SDK baseline, not the live x/auth parameter.
Lifecycle authorization remains required even when self-protection is off.

### Immutable launch settings

These fields cannot be changed by `MsgUpdateParams` after initialization.

| Field | Default | Purpose / validation |
| --- | --- | --- |
| `network_id` | Launch-specific domain | Separates signatures across networks; 16–64 bytes, displayed as base64. Query the chain; do not hardcode the development default. |
| `governance_safety_delay_blocks` | `17,280` | Delay for stronger enforcement or a price increase; range 2–2,000,000 blocks. |
| `recovery_delay_blocks` | `107,520` | Waiting period before a recovered signing key activates; effective range 2–2,000,000 blocks. Zero uses the default fallback. |
| `max_emergency_duration_blocks` | `46,080` | Duration of each pause activation/renewal; range 2–172,800 blocks. |

At an assumed 5.625 seconds per block, these defaults are approximately 27 hours,
7 days and 72 hours respectively. They are block counts, not wall-clock timers.

### Code constants and runtime state

| Item | Value / behavior |
| --- | --- |
| Algorithm | ML-DSA-65 only |
| Operational extension caps | 8 signer entries / 65,536 bytes |
| Raw-wire pre-decode ceilings | 32 entries / 262,144 bytes, before generated protobuf allocation |
| Terminal key history | Up to 16 records per role; current/pending keys are pinned separately. Older terminal records are compacted into a hash accumulator. Key IDs are never reused. |
| PQC-specific verification-count quotas | None: the former 16/transaction and 400/block limits were removed. SDK signature-count, gas and byte limits still apply. |
| Server-managed parameter state | `pending`, `pending_activation_height`, `pending_emergency`, `emergency_expires_height`; callers cannot set these directly. |
| Module state version | 4; no automatic migration from experimental PQC state versions 1–3 |

Registration is always open unless paused; there is no CLOSED/FRESH mode or
registration-cutoff setting. Raising SDK `tx_sig_limit` does not raise the fixed
PQC extension caps. `last_compacted_key_id` is a maximum compacted ID, not proof
that every lower ID was deleted.

## CLI setup and keys

Examples use Bash, `jq`, an existing funded classical key and the `file` keyring.
Set these variables for your chain before running commands:

| Variable | Value |
| --- | --- |
| `RPC`, `CHAIN_ID` | Node RPC URL and chain ID |
| `OWNER_KEY`, `OWNER` | Classical keyring name and its account address |
| `GAS_PRICE` | Gas price including denomination, chosen for the target chain |
| `TO`, `AMOUNT` | Transfer recipient and amount including denomination |
| `GAS_LIMIT`, `FEES` | Explicit total gas limit and fee including denomination for a frozen transfer |

Use the intended `--home` / keyring directory on each machine. Do not copy private
keys between machines merely to run these examples. Query public state online:

```sh
OWNER=$(dorad keys show "$OWNER_KEY" --address --keyring-backend file)
dorad query pqcauth params --node "$RPC" --output json > params.json
NETWORK_ID=$(jq -er '.params.network_id' params.json)
dorad query pqcauth account "$OWNER" --node "$RPC" --output json
dorad query pqcauth keys "$OWNER" --node "$RPC" --output json
```

`account` returns policy-not-found before first enrollment. After enrollment it
shows effective/pending policy and the active signing key, **not** the next unused
key ID. Immediately after first enrollment the next ID is 3. For later operations,
track allocated IDs across both roles, including cancelled recoveries; do not
assume `current_signing_key_id + 1` or infer the counter from compacted history.
`dorad query pqcauth key OWNER KEY_ID --node "$RPC"` reads one retained record. For only the PQC
cryptographic gas component (not total gas), use
`dorad query pqcauth estimate-verification-gas --signatures 1 --proofs 0 --node "$RPC"`.

Create the signing factor on its trusted signing device and the recovery factor
on a separate offline recovery device:

```sh
# Signing device
dorad keys add pqc-signing --key-type ml_dsa_65 --keyring-backend file

# Offline recovery device
dorad keys add pqc-recovery --key-type ml_dsa_65 --keyring-backend file
```

Use separate, dedicated mnemonics, distinct from the classical owner and each
other. The SDK derivation uses the matching BIP32-derived secp256k1 private key as
the ML-DSA seed; reusing that mnemonic in a classical wallet undermines independence.
Back up each mnemonic separately. Restore with
`dorad keys add NAME --recover --key-type ml_dsa_65 --keyring-backend file` when needed.

The CLI rejects detected coupling with a locally available secp256k1 owner key.
If it cannot perform that check, introducing a new factor requires
`--acknowledge-independent-factors`. This acknowledges responsibility, does not
prove independence and cannot override detected coupling or the Ledger restriction.

## Register

For a new enrollment, signing/recovery IDs are 1/2 and the proof policy version
is 0. Run each proof command on the device holding that key; transfer only its
public JSON output to the preparation machine:

```sh
dorad tx pqcauth create-key-proof pqc-signing "$OWNER" 1 signing register-signing \
  --network-id-base64 "$NETWORK_ID" --chain-id "$CHAIN_ID" \
  --policy-version 0 --keyring-backend file > signing-proof.json

dorad tx pqcauth create-key-proof pqc-recovery "$OWNER" 2 recovery register-recovery \
  --network-id-base64 "$NETWORK_ID" --chain-id "$CHAIN_ID" \
  --policy-version 0 --keyring-backend file > recovery-proof.json

# Owner's online machine, after receiving both public proof files
dorad tx pqcauth register-key 1 \
  "$(jq -er '.public_key_base64' signing-proof.json)" \
  "$(jq -er '.proof_base64' signing-proof.json)" \
  --recovery-public-key-base64 "$(jq -er '.public_key_base64' recovery-proof.json)" \
  --recovery-proof-base64 "$(jq -er '.proof_base64' recovery-proof.json)" \
  --from "$OWNER_KEY" --chain-id "$CHAIN_ID" --node "$RPC" \
  --keyring-backend file --gas auto --gas-adjustment 1.5 --gas-prices "$GAS_PRICE"
```

Wait for successful execution and H+1 before using protection. A successful
broadcast/CheckTx response alone is not execution success. If registration fails
at message execution, re-query the SDK sequence before retrying.

## Send from a protected account

Create the transaction online, sign its PQC authorization on the signing device,
then return the bundle for classical signing and broadcast:

```sh
# 1. Online: freeze the amount, fee and total gas limit in unsigned JSON
dorad tx bank send "$OWNER_KEY" "$TO" "$AMOUNT" \
  --chain-id "$CHAIN_ID" --node "$RPC" --keyring-backend file \
  --generate-only --gas "$GAS_LIMIT" --fees "$FEES" > send.json

# 2. Online: fetch current account sequence, policy and signing key
dorad tx pqcauth prepare-bundle send.json send.prepared.json \
  --from "$OWNER_KEY" --chain-id "$CHAIN_ID" --node "$RPC" --keyring-backend file

# 3. Signing device: review and sign; no RPC needed
dorad tx pqcauth sign-bundle send.prepared.json pqc-signing send.signed.json \
  --keyring-backend file

# 4. Online: revalidate state, attach PQC signature, then sign with OWNER_KEY
dorad tx pqcauth broadcast-bundle send.signed.json \
  --from "$OWNER_KEY" --chain-id "$CHAIN_ID" --node "$RPC" --keyring-backend file
```

Choose `GAS_LIMIT` for the **complete protected transaction**, including the PQC
extension bytes. `prepare-bundle` does not simulate or add a gas allowance.
Preparation/broadcast reject overrides such as `--gas`, `--fees`, `--sequence`,
`--sign-mode` and `--offline`; these fields are frozen. If the transaction or
bound account state changes, prepare and sign a new bundle. Output bundle files
must not already exist. The same flow supports other single-signer SDK messages.

## Rotate and recover keys

Create a fresh target key with `keys add`, then generate its proof with:

```sh
dorad tx pqcauth create-key-proof "$NEW_KEY" "$OWNER" "$NEW_ID" "$ROLE" "$PURPOSE" \
  --network-id-base64 "$NETWORK_ID" --chain-id "$CHAIN_ID" \
  --policy-version "$POLICY_VERSION" --keyring-backend file > new-key-proof.json
```

Use the current effective policy version and next unused ID. Keep a trusted copy
of `public_key_sha256` on the key-generation device. `NEW_KEY` is the local target
key name; set `ROLE` and `PURPOSE` from this table. Read `POLICY_VERSION` from
`.policy.policy_version` in the account query. The proof choices are:

| Operation | Role | Purpose | Authorization |
| --- | --- | --- | --- |
| `rotate-key` | `signing` | `rotate-signing` | Current PQC signing key + classical key |
| `rotate-recovery-key` | `recovery` | `rotate-recovery` | Current PQC signing key + classical key |
| `recover-key` | `signing` | `recover-signing` | Current recovery key + classical key |

### Offline rotation

On the online machine, prepare a signing-key rotation. For a recovery-key
rotation, use `rotate-recovery-key` and the corresponding proof from the table.

```sh
dorad tx pqcauth rotate-key "$NEW_ID" \
  "$(jq -er '.public_key_base64' new-key-proof.json)" \
  "$(jq -er '.proof_base64' new-key-proof.json)" \
  --pqc-sign-bundle-output rotation.prepared.json \
  --from "$OWNER_KEY" --chain-id "$CHAIN_ID" --node "$RPC" \
  --keyring-backend file --gas auto --gas-adjustment 1.5 --gas-prices "$GAS_PRICE"

# Signing device: trusted local record of the NEW key; public/watch-only is enough
dorad tx pqcauth sign-bundle rotation.prepared.json pqc-signing rotation.signed.json \
  --expect-new-key "$NEW_KEY" --keyring-backend file

# Online
dorad tx pqcauth broadcast-bundle rotation.signed.json \
  --from "$OWNER_KEY" --chain-id "$CHAIN_ID" --node "$RPC" --keyring-backend file
```

Instead of `--expect-new-key`, use
`--expect-new-key-sha256 "$TRUSTED_NEW_KEY_SHA256"`. Supply exactly one. Both
rotations activate at H+1, **not** after the recovery delay. For a fully trusted
online signer, replace `--pqc-sign-bundle-output ...` with `--pqc-key pqc-signing`
to sign and broadcast directly; that path is not an offline security boundary.

### Offline recovery

Use a new signing-key proof with purpose `recover-signing`, and obtain
`RECOVERY_ID` from the effective account policy:

```sh
# Online: no recovery private key is needed here
dorad tx pqcauth recover-key "$RECOVERY_ID" "$NEW_ID" \
  "$(jq -er '.public_key_base64' new-key-proof.json)" \
  "$(jq -er '.proof_base64' new-key-proof.json)" \
  --recovery-sign-bundle-output recovery.prepared.json \
  --from "$OWNER_KEY" --chain-id "$CHAIN_ID" --node "$RPC" \
  --keyring-backend file --gas auto --gas-adjustment 1.5 --gas-prices "$GAS_PRICE"

# Offline recovery device: expected key is the NEW signing key, not recovery key
dorad tx pqcauth sign-recovery-bundle recovery.prepared.json pqc-recovery recovery.signed.json \
  --expect-new-signing-key "$NEW_KEY" --keyring-backend file

# Online
dorad tx pqcauth broadcast-recovery-bundle recovery.signed.json \
  --from "$OWNER_KEY" --chain-id "$CHAIN_ID" --node "$RPC" --keyring-backend file
```

Alternatively use `--expect-new-signing-key-sha256 "$TRUSTED_NEW_KEY_SHA256"`.
Recovery activates after `recovery_delay_blocks`; the old signing key remains
valid until then. Recovery is not an account freeze or a remedy for a stolen
classical key. If both classical and signing keys are compromised, do not assume
the recovery key can prevent takeover.

For both offline flows, the expected fingerprint must come from an independent
trusted device, **not the incoming bundle or compromised online host**. It is the
full 64-character SHA-256 of raw public-key bytes. Missing/mismatched targets
reject before signer access; `--yes` cannot bypass the check. Review the operation,
key role, owner, chain and fees as well. The confirmation and result JSON display
the new key's fingerprint, derived from validated transaction bytes.
Transaction hashes alone establish consistency, not intent. A target flag on an
ordinary transfer is rejected.

### Other lifecycle operations

Run these as `dorad tx pqcauth COMMAND`, with the standard `--from`, `--chain-id`,
`--node`, keyring and fee/gas options shown above. Use `--help` for details.

| Command | Purpose |
| --- | --- |
| `set-protection true` / `set-protection false` | Change self-protection at H+1; needs `--pqc-key`. Turning it off does not override `REQUIRED_FOR_REGISTERED`. |
| `revoke-key KEY_ID` | Revoke a non-current, non-pending key; needs `--pqc-key`. |
| `cancel-recovery PENDING_SIGNING_KEY_ID PENDING_POLICY_VERSION` | Cancel a pending recovery using the current signing factor (`--pqc-key`); read both values from `query pqcauth account`. |

These commands also accept `--pqc-sign-bundle-output` instead of `--pqc-key`.
If the recovery key is compromised, cancelling a recovery does not revoke it:
follow cancellation with a recovery-key rotation, as **two separate transactions**
with consecutive sequences. Inclusion/order is not guaranteed or atomic. If the
current signing key is lost, cancellation is not available through the recovery key.
Use fresh keys: the protocol does not prohibit reusing historical public keys.

## Governance and emergency behavior

Use governance message `/doravota.pqcauth.v1.MsgUpdateParams`; there is no dedicated
`tx pqcauth update-params` command. Its fields are `authority`, `params`, and
`emergency_only`. Use the chain's configured authority, preserve immutable fields,
and remove server-managed schedules/expiry from queried parameters before submitting.

- Full update (`emergency_only: false`, the default): stronger enforcement or
  a gas-price increase waits the safety delay; other changes normally use H+1.
  Submitting the active values cancels a pending ordinary plan. Retaining the
  current pause retains its expiry, not a renewed duration.
- Emergency-only update (`true`): change, renew or release the pause at H+1,
  preserving the ordinary plan and its original activation. Non-emergency values
  must match either the complete active or complete pending bundle.
- Until that H+1 activation, full updates are rejected; explicit emergency-only
  replacements remain allowed. Submit pauses in separate proposals: a failed
  later message rolls back the entire proposal. A failed separate proposal is
  not automatically retried. Re-query before resubmitting.
- A price change must satisfy `3 × verification_gas < block.max_gas` when the
  block gas limit is finite. This is a sanity check, not total gas estimation.
  Emergency-only updates and cancellation remain available without this check.

| Emergency mode | Effect |
| --- | --- |
| `PAUSE_NEW_KEYS` | Blocks registration and both rotations. Existing protected transfers, protection changes and revocation remain available. |
| `PAUSE_PQC_TRANSACTIONS` | Also blocks ordinary PQCAuth-protected transactions and other lifecycle operations. It is not a global pause of native ML-DSA or unprotected SDK transfers. |
| Both pause modes | Permit a single top-level recovery or cancellation, including a protected independent payer, with all required signatures/proofs and gas charges. |

Pauses expire automatically. Plan a patch or authorized renewal before expiry;
do not assume the pause remains until an incident is resolved. Recovery exceptions
still use ML-DSA and are not an escape from a broken cryptographic algorithm.
Check `resulting_params` and query active/pending parameters after execution.

## Integration, legacy keys and verification

- Keep `mempool.recheck = true`. Recheck skips only PQC cryptographic calls for
  previously admitted bytes; state, structure, key, policy, sequence and gas
  checks remain. CheckTx(New) and FinalizeBlock verify signatures. Reuse assumes
  ordered transactions and at least one pending block for policy changes;
  unordered transactions are disabled in this app.
- The app uses SDK proposal handlers and an enabled block gas meter. NoOp
  ProcessProposal is not full transaction authentication. Gas/byte limits do not
  guarantee fairness or bound all RPC/P2P work; capacity needs target-network tests.
- Supported production upgrade input is v1.0.1 after the required v1.0.0 archive
  transition. Initialization does not scan/revoke accounts or delegations. Reserved
  protobuf fields do not migrate old experimental PQC databases. Final-artifact
  snapshot, testnet/IBC and release acceptance are separate from unit tests.
- Raw-key compatibility: offline commands accept a file argument with
  `--legacy-key-file`; online commands use `--pqc-private-key-file` or
  `--recovery-private-key-file` instead of keyring flags. Files contain expanded
  private keys, not seeds for `keys import-hex`. `tx pqcauth keygen` is removed.
- Library callers handling untrusted bundles must use
  `SignPQCSignBundleForTarget` or `SignRecoverySignBundleForTarget`. The older
  signing helpers require caller-established intent.

Run from the repository root:

```sh
GOMAXPROCS=2 go test -mod=readonly -p 2 ./x/pqcauth/... ./app ./cmd/dorad/cmd
GOMAXPROCS=2 GOFLAGS=-p=2 bash scripts/test-release-candidate.sh
```

Implementation references: [parameters](types/params.go), [lifecycle/governance](keeper/msg_server.go),
[CLI](client/cli/tx.go), [offline target checks](client/key_target.go).
Historical audit and rehearsal records are under [docs](../../docs/); they describe
their fixed commits, not necessarily the current candidate.
