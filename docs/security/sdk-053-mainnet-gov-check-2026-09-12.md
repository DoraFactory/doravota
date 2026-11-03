# Mainnet governance and pending-proposal check — 2026-09-12

Historical English summary; not current deployment instructions or a new audit. See the [documentation index](../README.md) for current guidance.

Target: `d37fa73ef456cfd985df3679cd87704509db9a42`, baseline 0.4.4. Read-only vota-ash RPC collection at **17,268,224**.

| Source setting | Observed value |
| --- | --- |
| Ordinary minimum deposit | 100,000 DORA |
| Ordinary deposit/voting periods | Five days each |
| Ordinary approval threshold | 0.5 |
| Block max gas / bytes | 600,000,000 / 22,020,096 |
| Evidence maximum age | 324,000 blocks / 21 days |

Applying the proposed expedited settings (110,000 DORA, one day, 0.667) passed parameter validation and preserved existing governance fields. This was a migration-rule check using actual source parameters, not full RunMigrations or an executed upgrade.

ICS-23 proofs for gov/0x30 and upgrade/Consensus matched next-height AppHash `41E23658347BABC92F5BC84651782E24A20BDC76FDBC527B33D0FDF1D148A43E`. The header came from the same RPC; no independent light-client/signature verification was performed.

Complete pagination returned 17 retained proposals (IDs 1–16 and 18), all PASSED. No deposit/voting proposal or scheduled upgrade was reported. Missing ID 17 was not assigned an inferred status. Proposal listing was not a complete storage-proof traversal.

These findings did not justify adding legacy handlers or altering ordinary policy. Active proposals, source parameters and pending upgrade plans had to be checked again near the actual upgrade.

[Evidence, decoder, verifier and hashes](sdk-053-mainnet-gov-check-2026-09-12-evidence/). The .go.txt verifier can be copied to a temporary Go file and run against a **copy** of the evidence directory; it rewrites validated.json. It verifies two proofs and parameter constraints, not proposal pagination or current mainnet state.

[Original detailed record](https://github.com/DoraFactory/doravota/blob/eb5bbec2a88a36224bd27c5b487f3d726a6bfeda/docs/security/sdk-053-mainnet-gov-check-2026-09-12.md). Raw evidence is unchanged.
