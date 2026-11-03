# PQC Auth — candidate integration

This module adds an ML-DSA-65 authorization factor to an existing classical
account. Its address, assets and classical public key stay unchanged. Protected
transactions require both the normal SDK signature and the PQC extension.
Native SDK ML-DSA accounts already use PQC signatures and do not enroll here.

Status: development on `feature/pqcauth-sdk-keyring`, based on the released v1.0.1
IBC Amino compatibility runtime and the ML-DSA mnemonic-warning CLI. This is not a published
release or a mainnet activation. The candidate upgrade plan is `v1.1.0`;
the default development binary reports `v1.1.0-dev`.

Phase one protects direct transaction signing and key management. Existing and
new Authz/Feegrant capabilities keep standard SDK semantics: a grantee can still
execute authorized ordinary operations or spend the allowance on fees without
the owner's PQC factor. Enrollment does not revoke these capabilities or require
grantees to enroll. This is **not** an all-asset-movements PQC guarantee. Review
and revoke unwanted delegations separately. A protected grantee still needs its
own PQC factor when signing. Indirect PQC lifecycle execution remains forbidden.
See the [two-phase rollout plan](../../docs/PQCAUTH-ROLLOUT-PLAN.md).

Phase-one enrollment is always open, except during an authorized emergency
pause. There is no registration-mode/cutoff parameter or fresh-account retry
protocol. A failed message-stage registration can be retried with the current
SDK sequence and sufficient gas. Removed protobuf fields are reserved; old
experimental databases require a separate migration, not silent reinterpretation.

Enrollment itself now requires SIGN_MODE_DIRECT for every signer. The CLI
rejects explicit non-direct modes and the current SDK's Amino-only Ledger
backend. Offline/watch-only workflows still need a compatible external signer;
the CLI cannot certify an unknown wallet's PQC-extension support. These rules
do not change ordinary, unprotected SDK Amino transfers or the v1.0.1 IBC fix.

PQC extension decoding enforces absolute 256 KiB / 32-entry bounds before
generated protobuf allocation, including noncritical options that Ante later
rejects. Fixed operational bounds of 64 KiB / 8 entries apply before extension
decoding. These are memory/structure defenses, not governable throughput quotas.
SDK tx_sig_limit independently bounds native account signatures.

There is no PQC-specific transaction/block verification quota or dependency
filter. The app uses the SDK default proposal handlers, finite configured block
gas/byte limits, and an enabled block gas meter. With the SDK NoOp mempool,
ProcessProposal does not authenticate transactions: FinalizeBlock Ante still
verifies every signature and rejects invalid transactions. Removing a parallel
quota is not proof of worst-case capacity or fair inclusion; network admission,
recheck and target-hardware load tests remain necessary.
See the [simplification record](../../docs/PQCAUTH-SIMPLIFICATION-20261102.md).
Earlier audit records describe superseded selection algorithms.

Recheck reuses the cryptographic validity established for the same transaction
bytes by CheckTx(New). It still performs state/structure/key/policy and SDK
sequence checks and charges the configured verification gas; only the three
ML-DSA calls (authorization, recovery authorization, key proof) are skipped.
FinalizeBlock always verifies independently. Recheck is a trusted local ABCI
mode, not a broadcast transaction flag or an API for authenticating new bytes.
This application disables SDK unordered transactions. Review the recovery
document's state-derived policy-version binding before enabling that feature;
the regression gate intentionally rejects such an unreviewed configuration.
Recovery proof reuse also depends on policy-version changes having a pending
window of at least one block, and `mempool.recheck = true` after every commit.
The stale-recovery regression checks eviction during that window and rejection
at FinalizeBlock. Reassess before introducing immediate policy activation.
See the [recheck fixes and executed tests](../../docs/PQCAUTH-RECHECK-FIXES-20261102.md)
and [remaining parameter decisions](../../docs/PQCAUTH-PARAMETER-DECISIONS-20261102.md).

Registration, `set-protection true`, and `recover-key` print a delegation warning to stderr,
including the SDK `query authz grants-by-granter` and
`query feegrant grants-by-granter` commands. They do not query or revoke grants
automatically: review all pages on the intended chain. A compromised classical
grantee can still use the assets/fees authorized by its grants, including after
PQC recovery. Offline generation must not be mistaken for a delegation audit.

## Parameter and resource boundaries

Only enforcement mode, one verification gas price, and emergency mode are
mutable governance policy. Active/pending schedules are server-managed state,
not extra freely settable knobs. ML-DSA-65, extension bounds and key-history
retention are code constants. Network ID and the three delays are immutable.

The single verification price defaults to 750 and is charged before each
extension authorization, recovery authorization, or new-key proof. SDK-native
account signatures retain the SDK price path (with the native 750 floor).
Signature bytes, state access, classic signatures and message execution incur
additional gas. No per-transaction/per-block verification-count parameter exists.

A governance change of verification price must leave room below current finite
block max_gas for three verifications (two proofs plus a protected payer).
This minimal sanity check is not a total-gas prediction or a count quota.
Emergency/cancellation requests do not run it. Independent SDK consensus/auth
parameter changes still need capacity checks; never interpret a successful
parameter update as capacity acceptance.

Fixed extension caps remain 8 entries and 64 KiB; independent raw-wire ceilings
are 32 entries and 256 KiB. Raising SDK tx_sig_limit does not automatically raise
the extension caps. Native ML-DSA multisigs have no additional PQCAuth quota;
the SDK signature limit, gas and byte rules continue to apply. Tests exercise
17 native leaves with an explicitly raised SDK signature limit.

This is module state version 4. Reserved protobuf fields prevent number reuse,
not migration. Do not hot-swap this binary into a version 1/2/3 PQC experiment.
Use a fresh isolated chain or a separately reviewed migration. Production's
supported source remains v1.0.1 before PQCAuth activation.

## Key management

Use the SDK keyring, not a separate PQC key generator:

```sh
dorad keys add pqc-signing --key-type ml_dsa_65 --keyring-backend file
```

Create a **separate** recovery key on the offline recovery machine:

```sh
dorad keys add pqc-recovery --key-type ml_dsa_65 --keyring-backend file
```

Back up each mnemonic separately. Never reuse the owner's classical mnemonic,
and never import these dedicated mnemonics into a non-PQC wallet. SDK v0.55
uses the matching BIP32-derived secp256k1 private key as the ML-DSA seed. The
CLI warning remains in place; this integration does not change derivation.
Restoration with `keys add ... --recover --key-type ml_dsa_65` remains supported.
A restored backup is not inherently unsafe.

Registration checks a locally available secp256k1 owner private key against
both proposed factors. Known coupling is rejected. Watch-only/hardware owner
keys cannot undergo this check and produce an explicit warning. A successful
local check does not prove independence from every other wallet, path or key.
Never export hardware-wallet private keys to enable this check.

Signing and recovery public keys must be distinct. Key generation does not
automatically register a factor or transfer assets. The recovery key replaces
a lost/compromised **PQC signing factor**; the original classical signature is
still required. It cannot recover a lost classical private key.

## Registration and signing

Read the candidate chain's parameters and next key ID first:

```sh
dorad query pqcauth params --node "$RPC"
dorad query pqcauth account "$OWNER" --node "$RPC"
```

`NETWORK_ID` is the base64 network ID from the parameter query. Use the actual
next ID and current policy version; the examples show first enrollment IDs 1/2.
Create proofs on the machines holding the respective keys:

```sh
dorad tx pqcauth create-key-proof pqc-signing "$OWNER" 1 signing register-signing \
  --network-id-base64 "$NETWORK_ID" --chain-id "$CHAIN_ID" --keyring-backend file

dorad tx pqcauth create-key-proof pqc-recovery "$OWNER" 2 recovery register-recovery \
  --network-id-base64 "$NETWORK_ID" --chain-id "$CHAIN_ID" --keyring-backend file
```

The output contains public key and proof in base64, plus `public_key_sha256`
(the full SHA-256 hex digest of the raw public key), never private key material.
Pass those outputs to registration, signed by the existing owner:

```sh
dorad tx pqcauth register-key 1 "$SIGNING_PUB" "$SIGNING_PROOF" \
  --recovery-public-key-base64 "$RECOVERY_PUB" --recovery-proof-base64 "$RECOVERY_PROOF" \
  --from "$OWNER_KEY" --chain-id "$CHAIN_ID" --node "$RPC" \
  --keyring-backend file --gas auto --gas-adjustment 1.5 --gas-prices "$GAS_PRICE"
```

Review outgoing Authz/Feegrant capabilities before enrollment; revocation is
not a registration precondition. Registration must be the only message.
Enrollment and normal rotations activate at H+1.

Protected lifecycle commands accept `--pqc-key pqc-signing`. Recovery accepts
`--recovery-key pqc-recovery`. Generic bank/staking/etc. messages use the bundle
flow, which also supports offline factor signing:

```sh
dorad tx pqcauth prepare-bundle --help
dorad tx pqcauth sign-bundle prepared.json pqc-signing signed.json --keyring-backend file
dorad tx pqcauth broadcast-bundle signed.json --help
```

### Trusted recovery target (required for offline signing)

Generate the replacement signing key on a trusted device, independently of the
online preparation host. Save its public-key fingerprint from that device's
`create-key-proof` output, or keep a trusted local ML-DSA keyring record on the
recovery-signing device. A public/watch-only record is sufficient; the new
signing private key does not need to be copied to the recovery device.

Offline recovery signing requires exactly one trusted target source:

```sh
# Trusted local record of the NEW signing public key, not the recovery key:
dorad tx pqcauth sign-recovery-bundle prepared.json pqc-recovery signed.json \
  --expect-new-signing-key pqc-new-signing --keyring-backend file

# Or a full 64-character SHA-256 hex fingerprint saved on a trusted device:
dorad tx pqcauth sign-recovery-bundle prepared.json pqc-recovery signed.json \
  --expect-new-signing-key-sha256 "$TRUSTED_NEW_SIGNING_KEY_SHA256" \
  --keyring-backend file
```

The fingerprint hashes the **raw public-key bytes**, not their base64 or JSON
encoding. The algorithm and full fingerprint appear in the confirmation screen
and result JSON (`proposed_public_key_sha256`). The fingerprint is derived
locally from the decoded, validated transaction, not accepted as a bundle label.
Missing, malformed or mismatched targets fail before the recovery signer is
loaded. `--yes` skips only interaction, never the target check. Existing offline
scripts must now provide one of these flags, including legacy-file workflows.

Do not copy the expected fingerprint from the incoming bundle, its preparation
output, or an untrusted online host: that would compare the attacker-controlled
key against itself. Transaction hashes prove internal consistency, not that the
replacement key belongs to you. Check the owner, network, fee and other intent
fields as well; a matching target alone does not make every transaction safe.

Library integrations handling untrusted bundles should call
`SignRecoverySignBundleForTarget` with an independently trusted fingerprint.
`SignRecoverySignBundle` and its private-key convenience wrapper remain low-level
primitives for already trusted transactions; they do not establish user intent.

Review the exact transaction before signing. Bundle preparation and
broadcast perform online state checks; offline signing does not require an RPC.
Changing a message, fee, sequence, signer, policy version or domain invalidates
the bound authorization. Protocol envelopes remain byte-compatible with the
ported module; SDK keyring is only the signing backend.

### Recovery response and key reuse

Use fresh signing/recovery key material for rotations. The protocol assigns a
new key ID but does not prohibit reusing a historical public key; a new ID does
not make a previously compromised or revoked key safe again.

If both the classical key and recovery key have leaked, cancelling one pending
recovery does not revoke the compromised recovery key. While you still control
the current signing factor, prepare a cancellation followed promptly by a
recovery-key rotation, with consecutive account sequences and the correct
current policy/key IDs. They must be **two separate transactions**, each with
one lifecycle message, not a multi-message transaction. They can execute in
order in the same block, but broadcasting together does not guarantee inclusion,
atomicity or protection against competing transactions. Rotation is subject to
the emergency mode and activates at H+1. Check both execution results and the
effective recovery key on chain. If the current signing key is lost, do not
assume cancellation is available. Keep the trusted recovery target check even
though recovery has a waiting period.

## Legacy keys

The old `tx pqcauth keygen` command is removed. Existing raw private-key files
are supported only for recovery compatibility:

- `create-key-proof` / `sign-bundle` / `sign-recovery-bundle`: pass the file as
  the key argument and explicitly add `--legacy-key-file`.
- Protected online commands retain `--pqc-private-key-file` and
  `--recovery-private-key-file`, labeled legacy. They cannot be mixed with the
  corresponding keyring flag.

The raw files contain expanded private-key bytes, **not** a 32-byte seed. Do
not pass them to `keys import-hex`. No raw-file-to-keyring import utility is
claimed here. Use the legacy signer to rotate to fresh SDK-managed factors.

## Defaults and boundaries

| Parameter | Initial value |
|---|---:|
| Enforcement | OPTIONAL (enrolled self-protected accounts still require PQC) |
| Registration | OPEN |
| Emergency mode | NORMAL |
| Verification gas (one field) | 750 per crypto operation (SDK baseline) |
| Fixed maximum PQC signers / extension bytes | 8 / 65,536 |
| PQC verification-count quotas | None; SDK gas/byte/signature limits apply |
| Retained key records per role | 16 |
| Governance safety delay | 17,280 blocks (about 27 hours) |
| Recovery delay | 107,520 blocks (about 7 days) |
| Maximum emergency duration | 46,080 blocks (about 72 hours per activation/renewal) |

These are candidate defaults, not a statement of live chain parameters.
Time estimates assume roughly 5.62–5.63 seconds per block, not wall-clock timers.
Recovery keeps the old signing key valid until the scheduled activation; it is
not an account freeze or a cure for stolen signing keys. Recovery still requires
the classical account signature. Notify users of recovery requests, cancellation
instructions and activation height. Pauses automatically expire even if a bug
is unfixed: operators must plan a patch or authorized renewal before expiry.
Explicit stored delay values are not rewritten by changing defaults; the legacy
zero recovery-delay fallback now uses 107,520. Unsupported experimental state
with CLOSED/cutoff/REQUIRED needs a separately reviewed migration, not hot-swap.
See [approved launch settings](../../docs/PQCAUTH-LAUNCH-SETTINGS-20261102.md).
Phase one rejects global `REQUIRED` in active/pending/genesis/governance
parameters. Its enum number is reserved, never silently mapped to OPTIONAL.
`REQUIRED_FOR_REGISTERED` remains available after the governance safety delay.
The single verification price has a 750 floor and references the pinned SDK
constant, not the live x/auth parameter. Changing x/auth prices does not
automatically change PQCAuth's price. Old two-price state is not migrated by this
candidate; explicit new-schema prices can be changed through governance.
An ordinary protected send adds one 750-gas PQC authorization verification to
the SDK account-signature, transaction-byte, store and message-execution costs;
750 is not its total gas. Registration with signing and recovery keys has two
proof verifications (1,500 crypto gas before other costs).
The CLI signs the PQC document, attaches its extension, then signs the complete
transaction with the account key in DIRECT mode; offline bundles preserve the
same ordering and binding. No signature check or domain changes with this price.
There is no separate 400-verification block quota. Gas/byte limits constrain
included work but do not guarantee fairness or bound all incoming RPC/P2P work.
Price increases and stronger enforcement wait for the safety delay; emergency
pauses retain the independently bounded fast path.

`MsgUpdateParams.emergency_only` explicitly selects the operation:

- Omitted/false: a full parameter update. Restoring the active ordinary parameters
  while retaining the active emergency mode cancels a cancellable pending bundle;
  it does not renew the pause. A different ordinary replacement follows the existing
  safety delay rules.
- True: change/renew only emergency mode at H+1. Non-emergency fields must match
  either the complete active or complete queued bundle. The server never infers
  this intent merely because the requested mode is a pause.

When a non-emergency parameter bundle is already queued, an explicit emergency-only
request may copy either the active or queued non-emergency fields. The server
schedules only its emergency mode for H+1 in `pending_emergency`, retaining the
original restrictions and activation height. This does not activate
REQUIRED_FOR_REGISTERED/gas increases early. The queued emergency component
is synchronized to the new mode and bounded expiry so it cannot resurrect an expired
pause. Governance cannot supply the internal schedule or expiration directly.
Until that H+1 activation, any full parameter update is rejected; submit the
emergency update separately, then re-query before a full parameter replacement.
Every explicit emergency-only update sets `pending_emergency`, even with no
pre-existing ordinary plan. A later full update in the same block must fail, not
silently cancel or replace the emergency schedule. Explicit emergency-only
replacement, renewal or release remains authorized and follows message order.

Submit emergency pauses as separate governance proposals, without batching full
parameter updates into the same proposal. A later failed message rolls back all
earlier messages in that proposal, including the pause. Across proposals, a failed
full update does not roll back the already successful emergency proposal. The
failed proposal remains FAILED and is not automatically retried at H+1: after the
pause activates, re-query parameters and submit a new proposal if still needed.
If the full update executes first, a subsequent emergency-only update preserves
its ordinary schedule. See the [same-block guard fix and execution regressions](../../docs/PQCAUTH-SAMEBLOCK-EMERGENCY-FIX-20261102.md).

Full updates retaining the active emergency mode retain its existing expiry; if
an ordinary replacement activates after that expiry, its emergency component is
NORMAL. Renewal requires `emergency_only: true`. Numeric cutoff fields have been removed. A full update with a new emergency mode still has
full-bundle semantics, including its applicable safety delay; use explicit
emergency-only scope for a fast pause that must preserve an ordinary plan.

The response's `resulting_params` is the actual stored state, showing both pending
schedules and expiry. For governance JSON, `emergency_only` is a top-level message
field, not a Params field. A request must still clear `pending`,
`pending_activation_height`, `pending_emergency` and `emergency_expires_height`
from queried state; runtime schedules/expiry cannot be supplied by callers.
The [GOV-02 fix record](../../docs/PQCAUTH-GOV02-FIXES-20261101.md) describes
compatibility and regression coverage.

During `PAUSE_PQC_TRANSACTIONS`, exactly one top-level `MsgRecoverKey` or
`MsgCancelRecovery` may carry an authorization extension. This permits a protected
independent payer to fund recovery without bypassing the owner's account signature,
recovery signature, new-key proof, payer authentication or gas charging.
It does not permit ordinary protected sends, message batches or nested lifecycle
execution. This chain-level support does not add multi-signer CLI orchestration.
See the [emergency fixes record](../../docs/PQCAUTH-EMERGENCY-FIXES-20261101.md).

Key history is compacted over the complete owner's key prefix, separately for
signing and recovery roles. Current and pending policy keys are pinned.
`last_compacted_key_id` is the maximum compacted ID, **not** a boundary below
which all records were deleted: an older active key can outlive newer cancelled
recovery keys. The accumulator follows compaction-batch order, with ascending
IDs inside each batch; a later-retired older key is appended once when deleted.
Export/import preserves this ordering and permits retained keys below that maximum.

## Application requirements and tests

The app registers the module, store, services, canonical decoder, ordered Ante
checks and default SDK proposal selection, using the native SDK Feegrant module. Existing
SDK proposal gas/byte policy is preserved. The candidate upgrade requires the
completed v1.0.0 archive state and activated v1.0.1 signing rules. It initializes
OPTIONAL parameters and assigns an upgrade-specific network domain without
scanning accounts, Authz grants or Feegrant allowances. No PQC delegation index
is built or maintained. Internal module version 4 deliberately rejects older
experimental PQC databases; it does not provide a migration from versions 1/2/3.
Completed v1.0.0 and v1.0.1 remain recognized but must not be executed with this
binary. Existing chains must complete v1.0.1 using its released binary first.

Feegrant state changes, rollback, expiry and fee charging use the SDK's own
implementation. Admission checks and the exact
message authorization marker prevent indirect lifecycle execution. Consensus
keys and IBC light-client algorithms are outside this module's scope.

```sh
GOMAXPROCS=2 go test -mod=readonly -p 2 ./x/pqcauth/... ./app ./cmd/dorad/cmd
```

App tests cover failed-message rollback with fees retained, nested authz
routing, SDK-keyring enrollment and hybrid transfer/replay, SDK gas/byte limits,
and no-scan upgrade initialization. The earlier merged runtime passed remote repository
tests, enabled simulations, a four-validator v1.0.0 -> v1.0.1 -> v1.1.0 upgrade,
restarts, and the synthetic keyring lifecycle/outage rehearsal. See
[the v1.0.1 integration record](../../docs/PQCAUTH-V101-INTEGRATION-20261030.md).
Earlier snapshot evidence in the [integration record](../../docs/PQCAUTH-INTEGRATION.md)
and [2026-10-27 follow-up](../../docs/PQCAUTH-FOLLOWUP-20261027.md) predates this
merge and does not establish final merged-candidate snapshot acceptance.
Those results predate phase-one simplification. Final-candidate snapshot rehearsal, public-testnet/IBC acceptance, independent
security review and release approval remain outstanding.

## Multisig support boundary (v1.1.0)

PQCAuth enrollment supports classical **single-key** accounts only. All
composite public keys, including threshold accounts whose members are all
ML-DSA, are currently classified as unsupported by PQCAuth. Ordinary SDK
multisig transactions can use OPTIONAL mode, subject to SDK signature-count, gas, byte and verification rules. They cannot register an additional PQCAuth factor.
Global REQUIRED is disabled in phase one. Its reserved runtime semantics would
reject these accounts, including all-ML-DSA multisigs. Re-enabling it requires a
separately reviewed multisig/wallet/relayer migration policy, not a governance
parameter change. Experimental state already using/queuing REQUIRED is not a
supported drop-in upgrade source; do not silently downgrade it to OPTIONAL.
An OPTIONAL-mode signature test is not wallet support or migration approval.

## Ledger, watch-only and offline owners

At registration, signing-key rotation, recovery-key rotation and introduction
of a replacement factor during recovery, the CLI checks local secp256k1 key
material against each new ML-DSA public key. Detected coupling is rejected;
`--acknowledge-independent-factors` cannot override it.

When the owner's private key is unavailable (Ledger, watch-only or offline),
the command now stops unless `--acknowledge-independent-factors` is supplied.
This flag only acknowledges the operator's independent-mnemonic responsibility;
it is NOT proof of independence. Generate separate, fresh, dedicated mnemonics
for the signing and recovery factors. Never export/import a Ledger seed to
create either factor. The check cannot detect reuse at another derivation path
or with another account, even for local owners. These are CLI protections,
not consensus-enforced knowledge of mnemonic history.

Existing keys remain recoverable and usable to authorize rotation away from
unsafe factors. Do not prevent restoration of an existing key because it was
previously reused; restore in a trusted environment and transfer/rotate safely.

Module review fixes and regression evidence: [2026-10-27 module fixes](../../docs/PQCAUTH-MODULE-FIXES-20261027.md).
