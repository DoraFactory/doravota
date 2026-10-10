# Dora Vota v1.0.0 release requirements

## Operator and integration requirements

This release supplies the upgrade software; it does not schedule or activate a live-network upgrade. Use the governance-approved height for each network. Do not switch a running 0.5.0 node early. The exact plan name and Cosmovisor directory are **v1.0.0**.

- Stage the executable at `$DAEMON_HOME/cosmovisor/upgrades/v1.0.0/bin/dorad` and check the published SHA-256 and embedded source commit. Back up the database and validator signing state. Never run the validator key twice or start 0.5.0 on migrated state.
- Wasm execution, smart queries and contract withdrawals are removed at the upgrade. Raw store data remains queryable through `wasm-archive`; this is not a replacement for contract execution. NAV writes stop. Historical-height queries require retained historical versions; pruned history cannot be reconstructed from the retained current store. Wasm IBC channels close locally without packet settlement/refunds.
- Integrations must preserve account numbers as decimal strings or unsigned 64-bit integers/bigint. All post-upgrade accounts have numbers >= 2^63. Use compatible CosmJS 0.39.0 packages together, and validate address decoding as well as signing and broadcasting.
- Older CosmJS 0.37 and earlier clients may report a transaction error even when the transaction has committed. Check the transaction hash on chain before retrying. CosmJS 0.38 does not solve the new-account-number issue.
- Although the dependency is CometBFT v0.40.0, its upstream RPC version string is `0.39.0`. This is expected and is distinct from the Dora Vota application version `v1.0.0`.
- Hermes 1.13.3 was exercised in isolated cross-chain rehearsals. Set `compat_mode = '0.38'` in the Vota chain configuration. Its SDK compatibility health warning may remain; check actual client updates, packets and acknowledgements. This release does not recover expired IBC clients. Coordinate existing Osmosis and Cosmos Hub transfer routes.
- For ML-DSA CLI transactions, use `--gas auto --gas-adjustment 1.5` with the network's configured gas price and verify simulation. The 750 gas parameter covers signature verification, not total transaction gas. It is not a guarantee that Keplr or another existing wallet can sign ML-DSA transactions.

## Parameters

| Parameter | Value initialized by the upgrade |
| --- | --- |
| ML-DSA signature verification gas | 750 |
| Consensus key rotation fee | 1,000,000 peaka |
| Mint maximum supply | 0 (no cap) |
| New consensus authority | Unset |
| Existing inflation and governance settings | Preserved |

Consensus ML-DSA activation and a custom pqcauth module are outside this release.

## Validation and distribution scope

The same source candidate has passed isolated mainnet-snapshot four-node upgrade/restart and two-chain upgrade rehearsals, including preserved Wasm store roots, archive queries, IBC sequence migration, transfers, in-flight packets and timeout refunds. These rehearsals do not substitute for acceptance on the public testnet or authorize a mainnet upgrade.

The public release distributes **Linux amd64 only**. Any ARM64 CI build is a candidate build, not a published or fully rehearsed network release. Additional wallet operations and live-network acceptance remain scheduled after the testnet upgrade.


See [validator instructions](VALIDATOR-1.0.0.md), [client integration](CLIENT-1.0.0.md), and [Wasm archive queries](WASM-RETIREMENT.md). Final source commit, download links and checksums are published with the GitHub Release.
