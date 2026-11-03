# SDK 0.53 parameter checklist — d37fa73

Historical English summary; not current deployment instructions or a new audit. See the [documentation index](../README.md) for current guidance.

Historical target: `d37fa73ef456cfd985df3679cd87704509db9a42`, baseline 0.4.4. This inventories that migration, **not current PQCAuth settings** or live mainnet configuration.

| New governance field | Migrated value |
| --- | --- |
| min_deposit_ratio | 0 |
| proposal_cancel_ratio | 0 |
| expedited_min_deposit | 110,000 DORA (110000000000000000000000 peaka) |
| expedited_voting_period | 86,400 seconds |
| expedited_threshold | 0.667 |
| proposal_cancel_dest | Empty |

Only the first three were custom approved overrides. They applied during the upgrade handler, not new genesis. Expedited deposit/threshold had to exceed ordinary values and its voting period had to be shorter. Existing governance fields, consensus gas/bytes/evidence settings, account/bank/staking/mint/distribution/slashing policies and IBC/ICA permissions retained source values subject to upstream structural migrations.

Capability/feeibc stores were removed only after checks; params remained. The historical feeibc account and bank-send block remained. DORA precision stayed 18 decimals; Wasm upload limits stayed 3 MiB. Optional callbacks, IBC v2, unordered transactions and PQC were not enabled by this bridge.

The [configuration review](sdk-053-config-review-2026-09-12.md) and its preserved CSV/JSON contain all 37 template differences: 12 additions, two default changes and 23 removals/replacements. Key distinctions:

- Generic query-gas-limit=0 was newly connected; Wasm query gas/cache defaults were unchanged.
- Template mempool.max-txs changed, but runtime application mempool stayed NoOp.
- gRPC-Web used the API listener, not the old standalone listener.
- Removed TOML keys did not retain behavior merely by remaining in a file.
- iavl-sync-pruning was not a wired daemon flag.
- Existing configs were not to be overwritten with newly generated templates.

The historical build used SDK 0.53.6, Comet 0.38.21, IBC-Go 10.5.0, Wasmd 0.61.14, WasmVM 3.0.7 and Go 1.24.7. Candidate version/notes required reconciliation before release. This review changed no runtime code or network state; the original detailed checklist is linked below.

[Original detailed record](https://github.com/DoraFactory/doravota/blob/eb5bbec2a88a36224bd27c5b487f3d726a6bfeda/docs/security/sdk-053-parameter-checklist-d37fa73.md). Raw evidence is unchanged.
