# SDK 0.53 legacy asset and NFT check — 2026-09-11

Historical English summary. Results apply only to the recorded artifact and environment; see the [documentation index](../README.md) for current guidance.

Read-only inspection of the isolated snapshot chain; no mainnet, channel, client, contract or asset changes.

Five selected old channels retained channel records, 7,993 receipts, 7,993 acknowledgements and sequence values across exports at committed heights 17,250,459 and 17,250,510. Local send commitments were zero. Fixed-height checks at 17,252,862 confirmed unchanged escrow balances and correctly paginated responses.

| Counterparty | Local / remote channel | Client state | Escrow peaka |
| --- | --- | --- | --- |
| Cosmos Hub | 4 / 750 | Active | 221732826210837911066 |
| Osmosis | 0 / 2694 | Active | 474762777110515299264757 |
| Noble | 14 / 94 | Active | 4000024290000000001 |
| Historical Osmosis | 17 / 106136 | Expired | 1 |
| Stargaze NFT | 16 / 397 | Expired | Not transfer escrow |

Expired or tiny-balance channels were not empty/disposable. Counterparty-client expiry was pre-existing, not a migration mutation. Native escrow and inbound IBC voucher supply are distinct balances.

Channel-16 had live historical business state: Donation code 98, two NFT mappings and five owner queries succeeded (tokens 551, 619, 67, 791 and 83). Full NFT cross-chain execution was explicitly deferred, not passed. Creator/admin addresses did not establish who opened the channel.

[Verification assertions](sdk-053-rehearsal-evidence/legacy-assets-verification.json), [boundary inventory](sdk-053-rehearsal-evidence/legacy-assets-boundary.json), [current assets](sdk-053-rehearsal-evidence/legacy-assets-current.json), [NFT records](sdk-053-rehearsal-evidence/legacy-nft-current.json), [client states](sdk-053-rehearsal-evidence/legacy-client-status.json) and [store comparison](sdk-053-rehearsal-evidence/boundary-stores.summary.json).

Local zero commitments did not prove counterparties had no inbound pending packets. This was state preservation, not old-channel end-to-end acceptance. Isolated forks must not connect to mainnet relayers or alter old clients to manufacture a passing test.

[Original detailed record](https://github.com/DoraFactory/doravota/blob/eb5bbec2a88a36224bd27c5b487f3d726a6bfeda/docs/upgrades/sdk-053-legacy-assets-check-2026-09-11.md). Raw evidence is unchanged.
