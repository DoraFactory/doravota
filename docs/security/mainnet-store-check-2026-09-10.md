# Mainnet feeibc and capability store check — 2026-09-10

Historical English summary; not current deployment instructions or a new audit. See the [documentation index](../README.md) for current guidance.

Read-only RPC inspection of vota-ash at height **17,236,364** found an empty feeibc store and no module-account balances. This excludes the outstanding ICS-29 fee condition at that height only, not at a future upgrade height.

The next header (17,236,365) supplied AppHash `26BB6A6CBE50A507197B986BD01D8DCA46782F752C2C0599D806AF5F56863DBD`. ICS-23 proofs verified the feeibc/capability roots and capability entries against that header. The header came from the same RPC; validator signatures and an independently trusted light-client checkpoint were not verified. Bank balances were an additional fixed-height query, not a separately verified range proof.

Capability contained 21 ownership records and a next-index counter of 22: three ports and 18 channels. Fifteen channels were OPEN and three INIT. Fourteen OPEN transfer channels used ics20-1; channel-16 was an ICS-721 Wasm channel paired with channel-397. INIT transfer channels were 8, 9 and 11.

Removal of legacy capability state was not a balance refund and did not justify manually clearing production stores. Existing transfer/ICA/Wasm routes, acknowledgements, timeouts/refunds and incomplete handshakes still required migration regression. Empty fee state did not close the other bridge-release blockers.

[Raw responses, fixed-height proofs, inventories and verifier](mainnet-store-check-17236364/). The verifier's local evidence path must be adjusted after relocation. No transactions were broadcast.

[Original detailed record](https://github.com/DoraFactory/doravota/blob/eb5bbec2a88a36224bd27c5b487f3d726a6bfeda/docs/security/mainnet-store-check-2026-09-10.md). Raw evidence is unchanged.
