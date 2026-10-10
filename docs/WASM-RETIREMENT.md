# Wasm read-only archive candidate

This branch removes Wasm execution and the wasmd/wasmvm dependencies while retaining IBC core, ICS20 transfer and ICA. This branch is the canonical v1.0.0 candidate (release tag and binary version), with governance/Cosmovisor plan `v1.0.0`, upgrading directly from 0.5.0. It combines the SDK 0.55 migrations with Wasm execution retirement. Previously tested runtime-preserving 1.0.0 binaries and the separate `wasm-retirement` candidate are superseded and must not be distributed as this release. A production height is not selected.

## Preserved data

The original `wasm` store stays mounted under its original name, with no deletion, renaming or migration. Existing code metadata, contract metadata, raw contract state, indexes, parameters and history entries remain byte-for-byte. The store becomes immutable after activation. Historical versions remain available only if the node already retained them; this change does not recover pruned history.

`dorad query wasm-archive` provides `get KEY_HEX`, `scan PREFIX_HEX`, `contract-state ADDRESS`, `contract-info ADDRESS`, and `code-info ID`. All accept normal query flags including `--height`. Raw values are base64. Scan returns full keys and an inclusive `next_key` cursor (convert base64 to hex for `--start-key`). Use a fixed height for a consistent scan. Pages are limited to 1000 entries and 4 MiB.

The gRPC service is `doravota.wasmarchive.v1.Query` (Get and Scan). REST endpoints are `/doravota/wasmarchive/v1/get?key=HEX` and `/doravota/wasmarchive/v1/scan?prefix=HEX&limit=100`; `x-cosmos-block-height` selects retained history. Metadata CLI commands decode stable fields only and return original bytes alongside them.

Full genesis export includes `wasm_archive`, containing every raw KV entry. Import validates sorted unique keys before writing. A live `wasm` genesis section is rejected rather than silently dropped. State-sync snapshots include the retained store without a VM extension.

## Removed behavior

No upload, instantiate, execute, migrate, sudo, contract reply or Wasm IBC callbacks are registered. Generic smart queries stop working even with a pre-retirement height, because they execute code. Existing Wasmd REST/CLI endpoints are not compatibility aliases for the archive API. Indexers must adopt raw-state parsing or retain an isolated old-version query service.

Historical Wasm transaction, governance content and authorization wire types are registered by a small decode-only compatibility package. It contains no keeper or VM and registers no executable Wasm handlers. Standard queries and genesis export can decode the known historical types, including nested authorization limits/filters. Unknown custom extension types remain unsupported. Existing grants remain stored and expire normally; Wasm-specific authorization Accept and ValidateBasic reject use, and generic grants cannot execute absent handlers. Pending proposals continue through normal SDK governance processing; a passing proposal that invokes a retired handler fails as a proposal without stopping block processing. No deposits are swept or special refund policy introduced.

Wasm bytecode files and VM caches live outside the KV store. Retaining the store does not guarantee preservation of those files. Before retirement, export code binaries and verify their hashes, retain an original node backup and an independent copy of required history. The new binary cannot download bytecode from its archive API.

## Activation

The coordinated v1.0.0 upgrade deletes all legacy params/group stores. Group data, policy-account balances, grants and proposal text are not activation vetoes. Existing auth accounts and bank balances are not swept. Decode-only historical group/params types remain registered, with no executable handlers.

At activation all non-closed `wasm.*` channels are set to CLOSED locally and emit `wasm_channel_retired` with port, channel and previous state. No contract callback runs. Packet commitments, receipts and acknowledgements remain stored; there is no refund, asset migration or counterparty closure. Contract execution, NAV writes and withdrawals cease. Ordinary bank transfers into retired contract addresses are not blocked. Preserving state does not restore access to contract-controlled assets.

Ordinary ICS20 and ICA channels are retained. The guarded IBC v11 migration moves send-sequence keys exactly once, verifies each logical sequence value, and removes its old key. Wasm channel closure occurs before that migration, so retired channels do not acquire active v2 aliases. The Wasm store itself is never written, renamed or deleted.

Structural checks still verify committed store layout, source module versions, on-chain plan, halt height and local upgrade info. Per-block activation checks prevent premature use, including after state sync. Default ML-DSA verification gas (750) and consensus-key rotation fee (1000000 peaka) are unchanged.

## Release validation

Use the final committed binary for mainnet-derived and testnet snapshot rehearsals and a two-chain upgrade. Verify same-height AppHash agreement, restart, complete Wasm store digest, retained historical raw queries, logical IBC sequences, existing transfers/acknowledgements/timeouts and rejection of retired messages without halting. Group creation and Wasm channel creation before the upgrade must not prevent activation. Preserve baseline evidence before deleting test copies. See [validator and integration guide](VALIDATOR-1.0.0.md).

## Database compatibility

Keep the same LevelDB replacement as Cosmos SDK 0.55. The selected 2022
revision treats stored empty values as missing keys, which prevents loading
empty IAVL roots after restart. The pinned 2021 revision preserves this
distinction. A persistent empty-tree restart regression covers the requirement.
