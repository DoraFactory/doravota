# 0.4.4 four-validator snapshot baseline — 2026-09-11

Historical English summary. Results apply only to the recorded artifact and environment; see the [documentation index](../README.md) for current guidance.

This record covers the **old-version baseline only**. Subsequent migration is recorded in [the SDK 0.53 rehearsal](sdk-053-snapshot-upgrade-2026-09-11.md).

Snapshot height 17,249,823 came from ITRocket. Archive SHA-256: `ace45e16775385c6483d03a884f7f3756edbc2af0bbf1b694737b90b812d2ff6`; application/Comet AppHash: `33C38FB34DF70094118170FD0640A05BF5B4600BDED0CB38DFF5AFB51EDE5499`. The checksum was locally computed, not vendor authentication.

Revision 0.4.4 `1b0774785111d8a6e693cd155053c19a5a1d8bdc` ran on copied databases, not export/import genesis. An offline test-only checkpoint at 17,249,824 installed four fresh consensus keys, a test chain ID and adjusted the validator set. Expected staking/slashing/bank roots changed; other listed module roots remained identical. Original archives/pristine copies were retained.

Nodes used loopback peers, empty seeds and disabled PEX. No mainnet keys, peers or relayers were used; public proxies were read-only.

Four nodes agreed at 17,249,853. Three progressed while node3 was down; all restarted and agreed again at 17,249,921. Read-only checks found 18 IBC channels and the historical ICS-721 contract code 98. These observations did not validate SDK migration, asset transfers, cross-chain delivery or long-term stability.

[Evidence and fork report](evidence/snapshot-20260911/). Remote root: /root/doravota-snapshot-rehearsal-20260911. Failed preparation attempts were rebuilt from the original snapshot after fixing signing timestamp, cached chain ID and port conflicts. Production data was not reset.

[Original detailed record](https://github.com/DoraFactory/doravota/blob/eb5bbec2a88a36224bd27c5b487f3d726a6bfeda/docs/upgrades/snapshot-rehearsal-2026-09-11.md). Raw evidence is unchanged.
