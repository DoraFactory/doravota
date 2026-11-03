# SDK 0.53 source-snapshot upgrade rehearsal — 2026-09-11

Historical English summary. Results apply only to the recorded artifact and environment; see the [documentation index](../README.md) for current guidance.

## Inputs and outcome

The isolated chain upgraded successfully; the report's mainnet decision remained **No-Go pending further acceptance**. No production node or formal release was changed.

Source snapshot: doravota_2026-09-11_17249823_snap.tar.lz4, SHA-256 `ace45e16775385c6483d03a884f7f3756edbc2af0bbf1b694737b90b812d2ff6`. Old revision: 0.4.4 `1b0774785111d8a6e693cd155053c19a5a1d8bdc`.

Test proposal 19 scheduled sdk-v0.53-bridge at 17,250,460. Old nodes stopped at H−1; review5 migrated H and resumed. Final Linux AMD64 static binary SHA-256: `066360c4ff46696bb41162b7ce5a505e58325311a3b73fefef07a90f5057bfe1`. The baseline commit alone did not identify its then-uncommitted fixes.

A test checkpoint added 1,000 DORA and shortened governance settings, separately from migration. Test keys, balances, chain ID and signing state must never be copied into production.

## State preservation at H−1/H

| State | Recorded result |
| --- | --- |
| Accounts | 2,854,262 entries; account records unchanged; counter encoding migrated with value 1,427,130 preserved |
| Bank | 2,273,729 existing entries unchanged; 14 metadata entries added |
| Wasm | 4,180,549 entries; identical root |
| Feegrant | 2,139,783 entries; identical root |
| Authz/group/params/evidence | Identical respective roots |
| Staking/slashing | Expected index/history/bitmap migrations; 605 true missed-block flags preserved |
| IBC/transfer | Existing protocol records preserved except localhost removal; 14 denom paths/hashes preserved under new encoding |
| Consensus | 600,000,000 gas / 22,020,096 bytes retained |
| feeibc/capability | Empty fee store removed after checks; 22 capability records removed as designed |

Normal per-block proposer/reward/history changes were distinguished from migration. Complete JSON export hit 12/16 GiB limits and did not pass; bounded raw-store comparison and cold-backup recovery were used instead.

## Execution and recovery

Transfers, staking, rewards, old/new Wasm execution and rejection cases passed. Controlled ICS-20 round trips/timeouts and both ICA directions worked; wrong signers produced error acknowledgements without balance changes. Feegrant, authz and group CLI flows also passed.

Missing upgrade-info, cold Wasm cache, one-node outage, whole-network restart and a cold-backup restore were exercised. A network-disabled zero-voting-power copy replayed the upgrade. SIGKILL during slashing migration left H−1 committed; restart reproduced the normal H AppHash. This covered that interruption point, not every disk-write failure.

Four nodes agreed at 17,251,520, 1,060 blocks after upgrade; this was not 24-hour stability. Manual switching did not validate production Cosmovisor automation.

[Evidence index](sdk-053-rehearsal-evidence/README.md). Original remote root: /root/doravota-snapshot-rehearsal-20260911. Preserve source/boundary backups and signing-state consistency; never reopen committed new state with 0.4.4 or roll back validator signing records.

Real legacy counterparties, production Wasm/Groth16, final artifact architectures, long load/stability and fresh mainnet preflight remained separate release gates.

[Original detailed record](https://github.com/DoraFactory/doravota/blob/eb5bbec2a88a36224bd27c5b487f3d726a6bfeda/docs/upgrades/sdk-053-snapshot-upgrade-2026-09-11.md). Raw evidence is unchanged.
