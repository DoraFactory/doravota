# PQC authentication threat model v1

## Security goal

For an account whose PQC policy is enforced, a transaction is authorized only
when both the existing Cosmos SDK signature and the account's active ML-DSA key
validate the same execution intent.

Compromise of only one of the two private keys must not be sufficient to
authorize a transaction.

## In-scope attackers

- An attacker able to forge the account's classical signature, including a
  future quantum attacker.
- An attacker possessing an ML-DSA private key but not the account's classical
  private key.
- A malicious transaction builder changing messages, fees, gas, payer,
  granter, tip, signer order, sequence, key selection, or extension options.
- A malicious proposer bypassing CheckTx and placing arbitrary transaction
  bytes in a proposal.
- A malicious or compromised online transaction-preparation host attempting to
  substitute an offline signing bundle or replay one after account state
  changes.
- An attacker sending malformed protobuf, public keys, signatures, or large
  extension payloads to exhaust CPU or memory.
- Governance or operators attempting to weaken an account from hybrid
  authentication to classical-only authentication.

## Security invariants

1. A protected signer requires both signature families.
2. Unknown versions, algorithms, sign modes, or malformed encodings fail
   closed.
3. The ML-DSA signature binds the chain, immutable network ID, account number,
   signer address and index, sequence, key ID, algorithm, policy version,
   transaction body, and complete AuthInfo.
4. A PQC extension is critical, unique, ordered, and never silently ignored.
5. Key and policy changes become effective no earlier than the next block
   height so proposal validation and delivery observe the same authentication
   state.
6. Governance cannot replace an account key, exempt an address, or downgrade a
   protected account to classical-only authentication.
7. Registration, rotation, and recovery proofs are verified during Ante
   processing, not only during message execution.
8. Every lifecycle message must be the sole top-level transaction message.
   Ante authorization is bound to the exact canonical message; `authz`, group,
   wasm, governance, and other nested execution paths cannot inherit or reuse
   it.
9. Offline signing bundles are advisory transport objects: the signed canonical
   document remains authoritative, and the online finalizer must re-query and
   match current chain state before adding the classical signature.

## Bootstrap limitation

First registration uses the existing account signature plus proof of possession
of the new ML-DSA key. This is safe only while the classical signature is still
trusted.

After a quantum attacker can forge that classical signature, the attacker can
generate a new ML-DSA key and race the owner to first registration. Therefore:

- registration must happen during a pre-quantum migration window;
- the chain must announce an irreversible registration cutoff;
- after the cutoff, unregistered legacy accounts cannot bootstrap from only a
  classical signature and a new-key proof;
- governance cannot repair this by assigning a key to an address.

## Recovery boundary

An offline recovery ML-DSA key may replace a lost active ML-DSA key with the
existing classical signature. Its recovery signature binds the complete
transaction intent using the same account, sequence, TxBody, and AuthInfo
boundaries as ordinary PQC transaction authorization. The replacement becomes
active at H+1; v1 does not claim a longer challenge-period timelock.

While the active signing key is available, the account can replace its offline
recovery key using the classical signature, the active signing-key PQC
authorization, and proof of possession of the replacement recovery key. The
old and replacement recovery keys switch atomically at H+1.

The reverse is not provided by v1. A Cosmos SDK BaseAccount address is derived
from its classical public key, so possession of only the PQC key cannot rotate a
lost classical key while preserving the address.

## Explicit non-goals

- Validator consensus signatures.
- CometBFT node/P2P identity.
- IBC client or counterparty signatures.
- Contract-internal authorization.
- Protecting a granter from actions already delegated through `x/authz`.
- Threshold ML-DSA or Legacy Amino multisig in v1.
