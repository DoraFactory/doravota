# PQC-IBC compatibility and relayer gate

This suite is the P0 compatibility gate for relaying IBC traffic while Dora
validators rotate from Ed25519 to ML-DSA-65. It exercises two independent,
in-memory **Dora applications**. It does not substitute a generic IBC SimApp
for the chain under test.

## What is verified

The deterministic two-chain scenario performs the following sequence:

1. initialize two Dora application states with independent validator sets and
   funded native ML-DSA-65 relayer accounts;
2. create 07-tendermint clients in both directions;
3. complete the IBC connection and ICS-20 channel handshakes;
4. send, receive and acknowledge an ICS-20 packet before key rotation;
5. rotate chain A from Ed25519 to ML-DSA-65 under CometBFT's H+2 validator-set
   rule;
6. submit the old-signed transition header that commits the new
   `NextValidatorsHash`, then update the existing client with an all-ML-DSA
   commit;
7. repeat the rotation for chain B without recreating either client;
8. relay ICS-20 packets and acknowledgements after both chains use ML-DSA-65.

Every client, connection, channel, receive-packet and acknowledgement message
is signed by those native ML-DSA-65 relayer accounts and passes through Dora's
real AnteHandler.

The transition header is mandatory when the old and new validator sets have no
overlap. Skipping it causes 07-tendermint to reject the next update because the
new commit has no voting power under the client's old trust root.

The relayer adapter tests separately verify:

- CometBFT 0.40 ML-DSA-65 validator public-key protobuf decoding;
- 07-tendermint `Header` construction with `TrustedHeight` and the validator
  set at `TrustedHeight + 1`;
- two-thirds commit signature verification before broadcast;
- protobuf marshal/unmarshal of ML-DSA-65 headers;
- validator count, commit signature count and encoded-header size limits;
- mnemonic-backed native ML-DSA-65 relayer keys;
- `SIGN_MODE_DIRECT` signing and local signature verification;
- rejection of a classic key when the operator requires a PQC relayer key.

## Run

```bash
tests/e2e/pqc-ibc/run.sh
```

The script retains a temporary audit directory and prints its path. It contains
the test logs and a machine-readable `result.json`.

IBC-Go v11.2's deterministic harness currently bundles a SimApp that calls SDK
constructors removed in v0.55. The script copies the locked IBC-Go source into
its temporary directory and replaces only those four test-only SimApp helpers
with `third_party/ibc-go-testing-simapp-v055-compat`. Production dependencies,
the application binary and the repository `go.mod` are not modified.

## Relayer integration

An external relayer provider should integrate `pkg/pqcibc` at these boundaries:

1. Build against CometBFT 0.40 and IBC-Go v11 types. Relayers based on a
   CometBFT 0.38 public-key protobuf cannot decode `PubKeyMlDsa65`.
2. Obtain source headers through a verified CometBFT light provider, not a raw
   RPC response, and call `BuildUpdateHeaderFromSource`.
3. Call `MarshalUpdateHeader` before constructing `MsgUpdateClient`; its local
   admission limits stop unexpectedly large validator sets before transaction
   signing.
4. Replace keyring options that hard-code only secp256k1 with
   `pqcibc.KeyringOption`, select `ml_dsa_65`, and bind the selected key through
   `pqcibc.NewKeyringSigner`.
5. Relay the transition header before the first commit signed entirely by the
   replacement validator set. Relayer monitoring must alert if this update has
   not committed before the scheduled rotation height.

The adapter accepts Ed25519 during a staged transition and ML-DSA-65 after it.
Any other validator public-key type is rejected at this boundary.

## RPC preflight

The preflight command confirms that a CometBFT 0.40 RPC response, including all
validator pages, can be decoded and that its commit, algorithms and size pass
the configured relayer limits:

```bash
go run ./tests/e2e/pqc-ibc/cmd/pqcibc-preflight \
  --rpc http://127.0.0.1:26657 \
  --require-mldsa
```

This command validates the block's own commit but does not make a raw RPC node
a trust anchor. Production relay construction must use a verified light
provider and the destination chain still performs the final 07-tendermint
verification.
