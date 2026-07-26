# PQC signing and wire specification v1

## Algorithms and contexts

The only v1 transaction algorithm is ML-DSA-65.

The FIPS 204 context is the ASCII byte string:

```text
doravota/pqcauth/tx/v1
```

Key registration, signing-key rotation, recovery-key proof of possession, and
recovery authorization use separate, fixed contexts:

```text
doravota/pqcauth/register/v1
doravota/pqcauth/rotate/v1
doravota/pqcauth/rotate-recovery/v1
doravota/pqcauth/recover-key-proof/v1
doravota/pqcauth/recovery/v1
```

Context strings are constants in the binary and cannot be supplied by
transactions or governance.

## Extension envelope

A transaction contains at most one critical
`/doravota.pqcauth.v1.ExtensionPQCAuth`. It must be the final critical extension.

Signer entries:

- are sorted by `signer_index`;
- contain no duplicate or out-of-range index;
- contain exactly the fixed-length signature for their algorithm;
- never contain a public key;
- are matched to `Tx.GetSigners()` and `AuthInfo.SignerInfos`.

The v1 implementation supports only `SIGN_MODE_DIRECT` for any transaction
carrying the PQC extension or requiring PQC authentication.

## Canonical signing document

For every protected signer, the client and verifier construct
`PQCSignDocV1` containing:

- format version;
- immutable 32-byte network ID;
- chain ID;
- canonical TxBody with the unique PQC extension removed;
- complete canonical AuthInfo;
- the current signer address and index;
- that signer's account number, sequence, key ID, algorithm, and policy version.

Each signer context binds:

- signer index and raw address bytes;
- account number and sequence;
- key ID and algorithm;
- account policy version.

The document excludes classical signatures and PQC signatures. It retains all
other critical and non-critical extension options.

`RecoverySignDocV1` applies the same transaction binding to recovery. It
contains the owner/recovery-key/replacement-key tuple plus account number,
sequence, signer address/index, canonical AuthInfo, and canonical TxBody. The
embedded `MsgRecoverKey.recovery_signature` and the PQC extension are cleared
only while constructing that canonical recovery body, preventing a circular
signature dependency without excluding any transaction intent.

The client:

1. freezes TxBody and AuthInfo and creates every signer-specific document;
2. produces every ML-DSA signature;
3. constructs the unique PQC extension;
4. attaches it to TxBody;
5. produces the existing classical signatures over the final transaction.

## Offline signing bundle

`doravota.pqcauth/sign-bundle/v1` is a client transport envelope, not a
consensus message. Its JSON byte fields use standard base64. It contains:

- the exact protobuf-encoded unsigned transaction with one empty classical
  `SIGN_MODE_DIRECT` signature slot and no PQC extension;
- the exact canonical `PQCSignDocV1`;
- SHA-256 digests of both byte strings;
- the active on-chain PQC public key used for offline key matching;
- an optional ML-DSA signature.

Before signing, the offline client decodes and canonically re-encodes the
transaction and sign document, reconstructs the sign document from the
transaction, checks both digests, validates all fixed lengths, and confirms
that the private key derives the public key carried by the bundle.

Before classical signing or broadcast, the online client repeats those checks,
queries the latest chain state, reconstructs the sign document again, and
requires an exact byte match. A sequence, account number, network, key, public
key, or policy change makes the bundle stale. The client then verifies the
offline signature locally, attaches the critical PQC extension, and finally
produces the existing classical signature.

Recovery uses the separate
`doravota.pqcauth/recovery-sign-bundle/v1` transport envelope and the fixed
`doravota/pqcauth/recovery/v1` context. A standalone signature over only the
replacement key is never accepted. The prepared recovery transaction carries a
correctly sized all-zero placeholder; offline validation requires that exact
placeholder, signs the complete recovery document, and the online finalizer
attaches the result only after re-querying the policy and recovery key.

## Encoding rules

- Consensus messages contain no protobuf maps.
- The PQC extension must round-trip to the exact canonical protobuf bytes;
  unknown fields, duplicate scalar fields, non-minimal varints, and alternate
  field order therefore fail before cryptographic verification.
- Unknown versions, algorithms, and sign modes are rejected.
- The canonicalizer is shared by the node and Go client.
- Go, TypeScript, and Rust golden vectors define interoperability.
- Any one-bit change to a bound field must invalidate the signature.

## Height semantics

Registration, signing-key rotation, recovery-key rotation, signing-key
recovery, account policy, and the complete mutable parameter bundle submitted
at height `H` become effective no earlier than `H+1`. Active or pending signing
and recovery keys cannot be revoked directly; revocation is limited to already
inactive historical keys.

This is mandatory because Cosmos SDK proposal verification runs AnteHandlers but
does not execute messages. Same-height activation would let proposal validation
and DeliverTx observe different authentication state.
