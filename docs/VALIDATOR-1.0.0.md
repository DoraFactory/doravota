# Dora Vota v1.0.0 upgrade guide

Target: Linux x86_64, direct upgrade from 0.5.0. Release tag and `dorad version`: `v1.0.0`. Binary asset: `dorad-v1.0.0-linux-amd64`. Governance plan and Cosmovisor directory name: `v1.0.0` (including the `v` prefix). Height, download URL, full source commit and binary SHA-256 must come from the final release announcement. Previously distributed runtime-preserving 1.0.0 binaries are obsolete. This guide does not schedule a live upgrade. The earlier unprefixed `1.0.0` plan and staging directory are superseded; do not submit or stage that name.

## Prepare

1. Verify the downloaded binary against the announced SHA-256, then run `dorad version --long` to verify version and source commit. Set executable permission with `chmod 755`.
2. Back up node configuration, current binary and a consistent database snapshot; retain validator signing state. Never run two copies of the validator key. Back up external Wasm bytecode separately if it is needed for historical research.
3. Confirm `halt-height = 0` in app.toml and no obsolete halt flag in the service. Inspect effective systemd settings and drop-ins, not only the base service file.
4. Cosmovisor: stage the verified executable at `$DAEMON_HOME/cosmovisor/upgrades/v1.0.0/bin/dorad`. Verify that exact file's SHA-256. A manual-service deployment replaces its executable only after the chain reaches the scheduled upgrade boundary.

## At the upgrade

The 0.5.0 node stops with `UPGRADE "v1.0.0" NEEDED` at the governance height. If Cosmovisor switches successfully, let the node resume. If it does not, stop the supervisor/service, confirm the on-chain plan and recorded upgrade height, point `cosmovisor/current` to `upgrades/v1.0.0`, verify the selected binary and restart. Do not delete chain data, reset signing state or roll back a validator automatically.

A manual deployment must stop the service before replacing its binary. Retain the old binary for investigation, but do not restart 0.5.0 against migrated state. The new binary is static and needs no libwasmvm shared library.

## Verify

- Node reports v1.0.0 and advances beyond the upgrade height; validators sign, peers synchronize and independently operated nodes agree on AppHash at the same height.
- Normal bank transfers, staking and ordinary IBC transfers work. Operators should coordinate a small round-trip on an existing transfer channel with an active relayer; expired clients are not repaired by this upgrade.
- All Wasm channels are CLOSED locally; ICS20/ICA channels are retained. No new Wasm channels, contract execution or smart queries are supported.
- Module version map contains wasm_archive=1 and no live wasm/group/params entries. Historical raw contract queries work at retained heights.
- New defaults are ML-DSA verification gas 750, key_rotation_fee 1000000 peaka, mint max_supply 0 (no supply cap), and unset consensus authority. Existing governance and inflation parameters are retained.
- Test outgoing transactions from a newly created post-upgrade account; integrations must support full uint64 account numbers. See CLIENT-1.0.0.md.

Reply in the validator group: `<validator name> upgraded to v1.0.0`.

## Explorer / indexer integration

Old Wasmd REST and smart-query endpoints are removed. Use `dorad query wasm-archive contract-state <address> --height <retained-height>` or the archive Get/Scan API described in WASM-RETIREMENT.md. Parse raw state using the original contract schema; smart-query responses are not reconstructed. A pruned node cannot answer discarded historical heights.

For SDK transaction search, integrations should send the supported `query` expression rather than the removed `events` parameter, for example `/cosmos/tx/v1beta1/txs?query=tx.height%3D123`. Confirm pagination and the configured transaction index with the actual RPC/REST provider. Historical Wasm/group messages retain decode support, not execution support.

Use fixed-height scans with pagination and record the height. Test raw-state, metadata, historical transaction, search and error responses before switching production indexers. Existing NAV contract writes stop; retained raw NAV records remain queryable.
