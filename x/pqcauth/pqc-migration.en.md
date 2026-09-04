# Dora's PQC Migration Path: Native ML-DSA and Legacy Account Protection

One of the main threats quantum computing poses to blockchains is the weakening of the security assumptions behind existing digital signature schemes. Dora Vota adopts a dual-track migration strategy: the account and consensus layers use the native ML-DSA capabilities provided by the Cosmos SDK and CometBFT, while legacy accounts that cannot change their addresses gain an additional ML-DSA authentication factor through [`x/pqcauth`](https://github.com/DoraFactory/doravota/tree/pqc-auth/x/pqcauth).

## 1. Background and Migration Constraints

Dora Vota currently uses [`secp256k1`](https://github.com/cosmos/cosmos-sdk/tree/v0.55.0/crypto/keys/secp256k1) for most user accounts and [`Ed25519`](https://github.com/cometbft/cometbft/tree/v0.40.0/crypto/ed25519) for validator consensus keys. Both schemes rely on the hardness of the elliptic-curve discrete logarithm problem and are not resistant to Shor's algorithm running on a sufficiently capable quantum computer. Once an account sends its first transaction, its classical public key is recorded on-chain; long-term exposure increases the risk of future key-recovery attacks.

For a running chain, signature algorithms cannot be migrated through direct replacement. Public keys participate in account-address derivation, so adopting a PQC (Post-Quantum Cryptography) public key normally creates a new address. Balances, staking positions, contract permissions, authz grants, feegrant allowances, and external-system mappings associated with the old address do not move automatically. Wallets, exchanges, and custody systems must also complete their own compatibility upgrades.

Account migration is therefore divided according to whether the address may change:

- Users who can change addresses migrate to native PQC accounts.
- Users whose addresses must remain unchanged retain their existing addresses and add a PQC second factor.

## 2. Native ML-DSA Support

[Cosmos SDK v0.55.0](https://github.com/cosmos/cosmos-sdk/releases/tag/v0.55.0) and [CometBFT v0.40.0](https://github.com/cometbft/cometbft/releases/tag/v0.40.0) provide ML-DSA-65 support compliant with [NIST FIPS 204](https://csrc.nist.gov/pubs/fips/204/final). The cryptographic implementation comes from [Cloudflare CIRCL](https://github.com/cloudflare/circl/tree/main/sign/mldsa/mldsa65). Cosmos SDK and CometBFT build on it with key interfaces, protobuf encoding, address derivation, and account and consensus signature-verification paths.

| Layer | Scope |
|---|---|
| [Cloudflare CIRCL](https://github.com/cloudflare/circl/tree/main/sign/mldsa/mldsa65) | ML-DSA-65 key generation, signing, and verification |
| [CometBFT v0.40 `crypto/mldsa65`](https://github.com/cometbft/cometbft/tree/v0.40.0/crypto/mldsa65) | Defines `PubKeyMlDsa65` and the consensus-signing interface, allowing ML-DSA to be used for validator consensus keys |
| [Cosmos SDK v0.55 `crypto/keys/mldsa65`](https://github.com/cosmos/cosmos-sdk/tree/v0.55.0/crypto/keys/mldsa65) | Integrates protobuf codecs, keyring support, mnemonic recovery, address derivation, and native [`x/auth` signature verification](https://github.com/cosmos/cosmos-sdk/blob/v0.55.0/x/auth/ante/sigverify.go) |

### 2.1 Account Layer: Native ML-DSA Transaction Signing

An upgraded `dorad` can create native ML-DSA accounts directly:

```bash
dorad keys add alice-pqc \
  --key-type ml_dsa_65 \
  --keyring-backend os \
  --home ~/.dora
```

The account address is derived from the ML-DSA-65 public key, transactions are signed by the corresponding private key, and Cosmos SDK `x/auth` verifies them with the account public key. ML-DSA-65 is based on the hardness of module-lattice problems rather than the elliptic-curve discrete logarithm assumption used by secp256k1 and Ed25519. FIPS 204 standardizes the algorithm, parameters, and encoding with the goal of providing digital-signature security against both classical and quantum attacks.

### 2.2 Consensus Layer: ML-DSA Validator Keys

[CometBFT v0.40's ML-DSA-65 implementation](https://github.com/cometbft/cometbft/tree/v0.40.0/crypto/mldsa65) implements the same consensus-key interface as Ed25519. Once the consensus parameters allow the `ml_dsa_65` public-key type, validators can use ML-DSA-65 private keys to sign block proposals and consensus votes. Other nodes verify those signatures against the public keys in the validator set, and block commits record the corresponding ML-DSA-65 signatures. This protects validator authentication and consensus signing for new blocks.

The upgrade does not change the CometBFT BFT process or validator operator addresses; it only replaces the keys and signature algorithm used to participate in consensus. Existing validators can bind a new public key to the same validator with the Cosmos SDK v0.55 [`MsgRotateConsPubKey`](https://github.com/cosmos/cosmos-sdk/blob/v0.55.0/docs/architecture/adr-016-validator-consensus-key-rotation.md), after which an ABCI validator update changes the CometBFT validator set. Section 4.2 describes the full procedure. Because ML-DSA public keys and signatures are substantially larger than Ed25519 values, block capacity, network bandwidth, consensus timeouts, and key-custody arrangements must be reassessed before production deployment.

## 3. PQC Auth Supplementary Authentication Module

The SDK's native ML-DSA support is suitable for new accounts, but it cannot replace an account public key while preserving an existing secp256k1 address. [`x/pqcauth`](https://github.com/DoraFactory/doravota/tree/pqc-auth/x/pqcauth) handles this compatibility case: the address and classical account model remain unchanged, while ML-DSA becomes an additional authentication factor for transaction authorization.

![PQC Auth architecture](https://hackmd.io/_uploads/r1pq68VvGl.jpg)

The module stores only [public-key records and account policies](https://github.com/DoraFactory/doravota/blob/pqc-auth/proto/doravota/pqcauth/v1/state.proto), never user private keys. Each account may register a Signing Key for routine transactions and an offline Recovery Key, together with its enforcement status, current key ID, and policy version. Registration, rotation, recovery, revocation, and policy changes are executed through [dedicated lifecycle messages](https://github.com/DoraFactory/doravota/blob/pqc-auth/proto/doravota/pqcauth/v1/tx.proto) and take effect at H+1 so that CheckTx and DeliverTx at the same height use a consistent authentication state.

Protected transactions retain the standard Cosmos signature and place a custom [`ExtensionPQCAuth`](https://github.com/DoraFactory/doravota/blob/pqc-auth/proto/doravota/pqcauth/v1/extension.proto) in the SDK-defined [`TxBody.critical_extension_options`](https://github.com/cosmos/cosmos-sdk/blob/v0.55.0/proto/cosmos/tx/v1beta1/tx.proto) field. The extension contains the ML-DSA signature corresponding to each signer:

```text
secp256k1 classical signature
          AND
ML-DSA-65 second-factor signature
```

The [Ante Handler integration](https://github.com/DoraFactory/doravota/blob/pqc-auth/app/ante.go) verifies the transaction before any business message executes:

1. Validate extension uniqueness, position, canonical encoding, size limits, and signer-count limits.
2. Verify the standard Cosmos signature.
3. Load the account's current policy and active ML-DSA key.
4. Reconstruct the deterministic [`PQCSignDocV1`](https://github.com/DoraFactory/doravota/blob/pqc-auth/x/pqcauth/types/canonical_tx.go) and verify the second signature.
5. Execute bank, staking, Wasm, and other business messages only after both signatures pass.

`PQCSignDocV1` binds the chain and network, account number, sequence, messages, fee, gas, signer order, key ID, and policy version. This prevents cross-chain replay, replay with retired keys, and transaction-field substitution. The Recovery Key is used only to recover the Signing Key and does not participate in routine transactions; clients and custodians should keep it offline or use secret-sharing backups.

PQC verification is centralized in [`VerifyPQCDecorator`](https://github.com/DoraFactory/doravota/blob/pqc-auth/x/pqcauth/ante/verify.go), so business modules such as bank, staking, and Wasm do not require separate ML-DSA integration. Lifecycle messages may only execute as direct top-level messages. Message fingerprints bind Ante authorization to the same message and prevent proof verification from being bypassed through authz, group, or contract nesting. [`PrepareProposal` and `ProcessProposal`](https://github.com/DoraFactory/doravota/blob/pqc-auth/app/proposal.go) repeat the authentication checks, preventing a proposer from bypassing the mempool and placing invalid transactions in a block proposal.

## 4. Technical Migration Path

The overall migration first upgrades the application and on-chain state, then advances account authentication and validator consensus-key migration in stages on the target version:

![PQC migration path](https://hackmd.io/_uploads/HyJktQ4vze.png)

### 4.1 Application Software and On-Chain State Upgrade

The production chain cannot upgrade directly from SDK v0.47 / IBC-Go v7 to SDK v0.55 / IBC-Go v11. SDK v0.55 has removed some migrations that depended on the legacy `x/params` module and historical Wasm migration code, while IBC-Go v11 cannot directly process the existing IBC module version. Older Dora releases also store consensus-parameter state in `upgrade/Consensus`, which must be migrated.

The upgrade is divided into two stages:

```text
Current production version
SDK v0.47 / IBC-Go v7 / CometBFT v0.37
        │
        ▼
Bridge version
SDK v0.53 / IBC-Go v10 / CometBFT v0.38
Migrate legacy params, IBC, Wasm, and consensus-parameter state
        │
        ▼
PQC target version
SDK v0.55 / IBC-Go v11 / CometBFT v0.40
Native ML-DSA + x/pqcauth
```

The target version uses [upgrade preflight checks](https://github.com/DoraFactory/doravota/blob/pqc-auth/app/upgrades/v1_0_0/migration.go) to verify the module version map. If the bridge migration has not completed, the upgrade handler terminates instead of allowing historical state migrations to be silently skipped.

### 4.2 Consensus-Key Migration

Consensus-key rotation combines the Cosmos SDK v0.55 [`MsgRotateConsPubKey`](https://github.com/cosmos/cosmos-sdk/blob/v0.55.0/docs/architecture/adr-016-validator-consensus-key-rotation.md) with replacement of the node's private key:

1. Governance submits `cosmos.consensus.v1.MsgUpdateParams` to add `ml_dsa_65` to the allowlist of validator public-key types in the consensus parameters.
2. Each validator runs `dorad init --consensus-key-algo ml_dsa_65` in an isolated directory to generate a new key, then exports the new public key with `dorad comet show-validator`.
3. The validator operator account submits `dorad tx staking rotate-cons-pub-key '<new-pubkey-json>' --from <operator>`. The SDK checks the key type, prior use, rotation history, and fee, then records the new public key in staking state. If the operator account has enabled `x/pqcauth`, the transaction must also pass both classical and ML-DSA signature verification.
4. After the transaction returns `apply_height`, the validator backs up the original `priv_validator_key.json` and installs the new private key during the planned window. The staking module removes the old consensus address and adds the new one through `ValidatorUpdate`.
5. After restarting the node, operators query the staking validator, CometBFT `/validators`, and `/block?height=...` endpoints to confirm that the new public key has entered the validator set and that the block `commit` contains an ML-DSA signature from the new address. The next validator is rotated only after these checks pass.

Production rotation should proceed one validator at a time while continuously keeping more than two-thirds of the voting power online. The [multi-node upgrade rehearsal script](https://github.com/DoraFactory/doravota/blob/pqc-auth/scripts/rehearse-multinode-pqc-upgrade.sh) rotates four validators in the following order: submit the transaction, read the activation height, stop one node and install its new private key, allow the remaining nodes to cross the activation height, then restart the node and verify block production.

### 4.3 Account Migration

Account migration is divided according to address and business-state constraints:

- New accounts use SDK-native ML-DSA keys directly.
- Legacy accounts that can change addresses move their balances and business permissions to new ML-DSA addresses.
- Accounts whose addresses cannot change enable `x/pqcauth` hybrid dual signatures.
- Applications that allow an owner, admin, or operator to change should provide an explicit address-replacement procedure.

The network policy initially runs in `OPTIONAL` mode to give wallets and users an integration window. It then switches to `REQUIRED_FOR_REGISTERED`, enforcing dual signatures for registered accounts. First-time registration may remain open so that accounts that have not yet migrated are not permanently locked out.

The following section summarizes the four-validator network simulation.

## 5. Multi-Node Upgrade Simulation and Performance Data

The test environment ran four isolated validator processes, four standard wallets, and four validator operator accounts on one high-performance server. Each node used an independent node home, database, port set, and consensus private key, and completed the two-stage SDK v0.47 → v0.53 → v0.55 upgrade. All four nodes retained identical App Hash values after both upgrades. This environment validates multi-validator state-machine and key-rotation behavior; it does not cover inter-host latency, packet loss, or failure-domain isolation.

The tests covered PQC Auth registration, hybrid-authentication transactions, and validator consensus-key rotation. Classical-only transactions from protected accounts were rejected as expected, while transactions with valid ML-DSA signatures succeeded. All four Ed25519 → ML-DSA-65 consensus-key rotations became active at H+2 after submission. After rotation, every validator-set public key was of type `cometbft/PubKeyMlDsa65`, and the network continued producing blocks after a full-node restart. The tests recorded 53 successful on-chain transactions, including four transfers signed directly by two native ML-DSA accounts.

Performance comparisons used the same SDK v0.55 binary and standard `MsgSend`, with four successful transactions in each group. Transaction size was measured from the raw protobuf bytes returned by RPC:

| Test Stage | Account Authentication | Consensus Key | Transaction Size | Gas Used |
|---|---|---|---:|---:|
| Classical baseline | secp256k1 | Ed25519 | 314 B | 75,241 |
| PQC Auth hybrid authentication | secp256k1 and ML-DSA-65 | Ed25519 | 3,730 B | 376,597 |
| PQC Auth hybrid authentication + ML-DSA consensus | secp256k1 and ML-DSA-65 | ML-DSA-65 | 3,731 B | 376,607 |
| Native ML-DSA account + ML-DSA consensus | ML-DSA-65 | ML-DSA-65 | 5,483–5,485 B | First transaction: 282,691; subsequent: 228,941 |

A PQC Auth transaction contains a 3,309 B ML-DSA-65 signature, increasing each transaction by approximately 3.4 KB. A native ML-DSA transaction must also carry a 1,952 B public key in `SignerInfo`, increasing the size further. Its subsequent transactions use less gas than hybrid-authentication transactions because the verification path contains only native ML-DSA verification, rather than both secp256k1 verification and the 250,000 gas configured for PQC Auth extension verification.

Consensus signatures are not part of the raw transaction bytes, so rotating consensus keys has almost no effect on the size or gas of equivalent hybrid-authentication transactions. The added cost appears in the block commit: an Ed25519 signature is 64 B, while an ML-DSA-65 signature is 3,309 B. In a four-validator network, total commit-signature data increases from 256 B to 13,236 B, adding approximately 13 KB of fixed overhead per block. Production deployment must continue to benchmark full-block throughput, P2P bandwidth, and consensus timeouts using the actual validator count.

The procedure is automated in the [multi-node upgrade rehearsal script](https://github.com/DoraFactory/doravota/blob/pqc-auth/scripts/rehearse-multinode-pqc-upgrade.sh), which preserves transactions, node logs, consensus-key rotation evidence, and an automatically generated comparison of transaction sizes and gas usage.

## 6. PQC-IBC Dual-Chain Compatibility Experiment

Two independent Dora chains were connected through an IBC client, connection, and ICS20 channel. Validator consensus keys on both chains were then rotated from Ed25519 to ML-DSA-65. Bidirectional transfers, client updates, `RecvPacket`, and `Acknowledgement` all completed before and after rotation without deleting or recreating the existing IBC clients.

A transition header signed by the old validator set first committed the ML-DSA validator set for the next height. Only then was the first header signed by the new set submitted. A PQC-aware relayer constructed and relayed the ML-DSA headers, while a native ML-DSA-65 relayer account signed the corresponding IBC transactions.

| Validation Item | Result |
|---|---|
| Bidirectional ICS20 relay before and after consensus-key rotation | Passed |
| ML-DSA header, validator-set, and commit verification | Passed |
| Native ML-DSA relayer account signing | Passed |
| IBC header size | 855 B → 11,794–11,796 B, an increase of approximately 10.9 KiB |

These results validate compatibility across the real CometBFT, RPC, IBC proof, and state-machine paths. They do not constitute coverage of a production-scale validator set, cross-data-center networking, or every IBC application.

## 7. Remaining Work for End-to-End Post-Quantum Security

After account and consensus signatures have migrated to PQC, classical cryptographic dependencies still remain in wallets, business state, interchain protocols, and operational infrastructure:

- Wallet and custody integration: Keplr, hardware wallets, exchanges, and custody systems must support native ML-DSA, PQC Auth extension fields, key rotation, and recovery.
- Authentication policy: global `REQUIRED` mode currently still requires a native ML-DSA signer to provide a PQC Auth extension. Ante should recognize a native ML-DSA account signature as already satisfying the PQC authentication requirement.
- Business-state migration: staking, vesting, contract administrators, authz, feegrant, DAOs, ICA, and other address-bound state require migration interfaces. Contracts that perform internal secp256k1 or Ed25519 verification must also be identified.
- Consensus-key custody: validator infrastructure must support ML-DSA HSMs, remote signers, backups, and incident recovery.
- Interchain verification: IBC light clients, relayers, counterparty chains, and interchain applications must all be verified for compatibility with ML-DSA consensus public keys. Upgrading this chain does not automatically change the security properties of an interchain path.
- Addresses and hashing: native ML-DSA addresses still use the Cosmos truncated public-key hash rule. The target quantum-security level should determine whether a longer, versioned address format is required.
- Network and release security: P2P node identities, RPC TLS, upgrade artifacts, and release signatures may still depend on classical cryptography and remain part of the end-to-end operational security boundary.
- Performance and audit: gas, block size, P2P bandwidth, and proposal timeouts must be calibrated for the production validator count, followed by independent cryptographic and upgrade audits and dependency-vulnerability remediation.

The recommended sequence is to enable native ML-DSA for new accounts first, configure PQC Auth hybrid authentication for legacy accounts that must retain their addresses, and then migrate consensus keys, business permissions, and ecosystem tooling in stages. Legacy accounts do not need to complete every migration at the same upgrade height.

For implementation details, see the [PQC Auth module documentation](https://github.com/DoraFactory/doravota/blob/pqc-auth/x/pqcauth/README.md) and the [implementation guide](https://github.com/DoraFactory/doravota/blob/pqc-auth/x/pqcauth/implementation.md).
