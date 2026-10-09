# Wasm read-only archive candidate

This branch removes Wasm execution and the wasmd/wasmvm dependencies while retaining IBC core, ICS20 transfer and ICA. It is a separate candidate after SDK 0.55 release 1.0.0, with plan `wasm-retirement`. It cannot directly upgrade 0.5.0 or replace a running 1.0.0 node before the scheduled boundary. The release number and production height still require a coordinated release decision.

## Preserved data

The original `wasm` store stays mounted under its original name, with no deletion, renaming or migration. Existing code metadata, contract metadata, raw contract state, indexes, parameters and history entries remain byte-for-byte. The store becomes immutable after activation. Historical versions remain available only if the node already retained them; this change does not recover pruned history.

`dorad query wasm-archive` provides `get KEY_HEX`, `scan PREFIX_HEX`, `contract-state ADDRESS`, `contract-info ADDRESS`, and `code-info ID`. All accept normal query flags including `--height`. Raw values are base64. Scan returns full keys and an inclusive `next_key` cursor (convert base64 to hex for `--start-key`). Use a fixed height for a consistent scan. Pages are limited to 1000 entries and 4 MiB.

The gRPC service is `doravota.wasmarchive.v1.Query` (Get and Scan). REST endpoints are `/doravota/wasmarchive/v1/get?key=HEX` and `/doravota/wasmarchive/v1/scan?prefix=HEX&limit=100`; `x-cosmos-block-height` selects retained history. Metadata CLI commands decode stable fields only and return original bytes alongside them.

Full genesis export includes `wasm_archive`, containing every raw KV entry. Import validates sorted unique keys before writing. A live `wasm` genesis section is rejected rather than silently dropped. State-sync snapshots include the retained store without a VM extension.

## Removed behavior

No upload, instantiate, execute, migrate, sudo, contract reply or Wasm IBC callbacks are registered. Generic smart queries stop working even with a pre-retirement height, because they execute code. Existing Wasmd REST/CLI endpoints are not compatibility aliases for the archive API. Indexers must adopt raw-state parsing or retain an isolated old-version query service.

Historical Wasm transaction, governance content and authorization wire types are registered by a small decode-only compatibility package. It contains no keeper or VM and registers no executable Wasm handlers. Standard queries and genesis export can decode the known historical types, including nested authorization limits/filters. Unknown custom extension types remain unsupported. Existing grants remain stored and expire normally; Wasm-specific authorization Accept and ValidateBasic reject use, and generic grants cannot execute absent handlers. Pending proposals continue through normal SDK governance processing; a passing proposal that invokes a retired handler fails as a proposal without stopping block processing. No deposits are swept or special refund policy introduced.

Wasm bytecode files and VM caches live outside the KV store. Retaining the store does not guarantee preservation of those files. Before retirement, export code binaries and verify their hashes, retain an original node backup and an independent copy of required history. The new binary cannot download bytecode from its archive API.

## Activation and settlement

Complete operator claims and resolve contract-held bank tokens, internal CW20 balances, escrow and other obligations before activation. Preservation is not a withdrawal mechanism. The implementation does not seize or transfer assets. Ordinary bank sends to old contract addresses are not disabled; such funds can become inaccessible, so integrations must stop sending to retired addresses.

Startup and the upgrade handler verify the committed store layout, source module versions, on-chain plan, halt height and local upgrade info. It rejects non-closed Wasm IBC channels and pending packets on those channels. Governance text and authz records are user-controlled and are not activation vetoes. A per-block gate also refuses pre-retirement state restored through state sync before activation. These checks are not a proof that all business liabilities have settled.

The upgrade changes only the module-version map: `wasm` is replaced with `wasm_archive=1`. It does not rerun the SDK or IBC migrations. The same IBC dependency and default ML-DSA/rotation parameters are retained. No mainnet height is hardcoded.

## Remaining IBC activation risk — not production-ready

The channel/packet gate is still a production blocker and can be influenced by users if the live contract accepts a new handshake or send before retirement. Removing this gate or setting every channel CLOSED does not settle escrow, NFTs, acknowledgements or timeouts. This candidate does not solve that risk by silently abandoning obligations.

A separate preparation phase must first freeze new Wasm channel handshakes and outbound packets in the live-runtime binary, across direct, authz, governance and contract paths, while preserving the callbacks needed to drain existing packets and withdraw assets. Reconcile both sides and obtain approval for residual liabilities before the retirement plan is scheduled. An expired client may require coordinated recovery. Ordinary ICS20/ICA must remain available. Until this preparation and a fresh unmodified snapshot rehearsal are completed, do not schedule the retirement candidate on mainnet. Structural store/version/plan checks remain necessary regardless of who can affect state.
