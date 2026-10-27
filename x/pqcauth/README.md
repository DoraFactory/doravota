# PQC Auth — candidate integration

This module adds an ML-DSA-65 authorization factor to an existing classical
account. Its address, assets and classical public key stay unchanged. Protected
transactions require both the normal SDK signature and the PQC extension.
Native SDK ML-DSA accounts already use PQC signatures and do not enroll here.

Status: development on `feature/pqcauth-sdk-keyring`, based on the v1.0.0
archive runtime and the ML-DSA mnemonic-warning CLI. This is not a published
release or a mainnet activation. The candidate upgrade plan is `v1.1.0`;
the default development binary reports `v1.1.0-dev`.

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

The output contains public key and proof in base64, never private key material.
Pass those outputs to registration, signed by the existing owner:

```sh
dorad tx pqcauth register-key 1 "$SIGNING_PUB" "$SIGNING_PROOF" \
  --recovery-public-key-base64 "$RECOVERY_PUB" --recovery-proof-base64 "$RECOVERY_PROOF" \
  --from "$OWNER_KEY" --chain-id "$CHAIN_ID" --node "$RPC" \
  --keyring-backend file --gas auto --gas-adjustment 1.5 --gas-prices "$GAS_PRICE"
```

Revoke outgoing authz and feegrant capabilities before enrollment. Registration
must be the only message. Enrollment and normal rotations activate at H+1.

Protected lifecycle commands accept `--pqc-key pqc-signing`. Recovery accepts
`--recovery-key pqc-recovery`. Generic bank/staking/etc. messages use the bundle
flow, which also supports offline factor signing:

```sh
dorad tx pqcauth prepare-bundle --help
dorad tx pqcauth sign-bundle prepared.json pqc-signing signed.json --keyring-backend file
dorad tx pqcauth broadcast-bundle signed.json --help
```

Recovery bundles use `sign-recovery-bundle prepared.json pqc-recovery signed.json`.
Review the exact transaction and hashes before signing. Bundle preparation and
broadcast perform online state checks; offline signing does not require an RPC.
Changing a message, fee, sequence, signer, policy version or domain invalidates
the bound authorization. Protocol envelopes remain byte-compatible with the
ported module; SDK keyring is only the signing backend.

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
| Signature / proof verification gas | 250,000 each |
| Maximum PQC signers / extension bytes | 8 / 65,536 |
| Maximum verifications per transaction / block | 16 / 400 |
| Retained key records per role | 16 |
| Governance safety / recovery delay | 17,280 blocks each |
| Maximum emergency duration | 17,280 blocks |

These are candidate defaults, not a statement of live chain parameters.
Restrictive changes to verification limits and history retention wait for the
safety delay; emergency pauses have their separately bounded fast path.

Key history is compacted over the complete owner's key prefix, separately for
signing and recovery roles. Current and pending policy keys are pinned.
`last_compacted_key_id` is the maximum compacted ID, **not** a boundary below
which all records were deleted: an older active key can outlive newer cancelled
recovery keys. The accumulator follows compaction-batch order, with ascending
IDs inside each batch; a later-retired older key is appended once when deleted.
Export/import preserves this ordering and permits retained keys below that maximum.

## Application requirements and tests

The app registers the module, store, services, canonical decoder, ordered Ante
checks, feegrant MsgServer wrapper, and proposal verification budgets. Existing
SDK proposal gas/byte policy is preserved. The candidate upgrade requires the
completed v1.0.0 archive state, initializes OPTIONAL parameters, assigns an
upgrade-specific network domain and rebuilds existing feegrant indexes.
Completed v1.0.0 remains recognized but must not be executed with this binary.

Feegrant predictions use an uncommitted cache; actual mutations share the
message cache with the SDK feegrant store. Admission checks and the exact
message authorization marker prevent indirect lifecycle execution. Consensus
keys and IBC light-client algorithms are outside this module's scope.

```sh
GOMAXPROCS=2 go test -mod=readonly -p 2 ./x/pqcauth/... ./app ./cmd/dorad/cmd
```

App tests cover failed-message rollback with fees retained, nested authz
routing, SDK-keyring enrollment and hybrid transfer/replay, proposal budgets,
and upgrade initialization. Local executable rehearsal has also exercised an
old v1.0.0 node, a governance-triggered store upgrade, SDK-keyring enrollment,
online protected signing, offline bundle transfer and restart. See
[the integration record](../../docs/PQCAUTH-INTEGRATION.md).
An isolated mainnet-snapshot upgrade has passed; the packaged-binary restart
and lifecycle evidence is recorded in the
[2026-10-27 follow-up](../../docs/PQCAUTH-FOLLOWUP-20261027.md).
Public-testnet acceptance, independent security review and approval of the
final release remain outstanding. Snapshot preservation is not live IBC proof.

## Multisig support boundary (v1.1.0)

PQCAuth enrollment supports classical **single-key** accounts only. All
composite public keys, including threshold accounts whose members are all
ML-DSA, are currently classified as unsupported by PQCAuth. Ordinary SDK
multisig transactions can use OPTIONAL mode, subject to SDK verification and
PQC verification budgets. They cannot register an additional PQCAuth factor.
Global REQUIRED mode rejects these accounts, including all-ML-DSA multisigs.
Do not enable REQUIRED on an existing network before a separately reviewed
multisig support/migration policy is deployed and tested. Moving a treasury to
an ML-DSA multisig is not a workaround for this REQUIRED-mode restriction.
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
