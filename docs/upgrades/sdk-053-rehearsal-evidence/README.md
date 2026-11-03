# SDK 0.53 rehearsal evidence index

Historical public source identities, transaction responses, state summaries and test logs. No private keys or mnemonics are included. These files identify the recorded candidate, not a current release.

| Files | Contents |
| --- | --- |
| final-binary.sha256, final-version.txt | Executed artifact identity |
| candidate-source-manifest.json, source-match-verified.json | Then-uncommitted source identity and remote comparison |
| final-four-node-consistency.json | Final same-height node agreement |
| boundary-stores.summary.json, semantic-checks.json | H−1/H raw-store and semantic comparisons |
| final-migration-replay.json, migration-crash-recovery.json | Upgrade replay and interruption recovery |
| missing-plan-cold-cache-restart.json, all-four-restarted.json, recovery-archive.sha256 | Restart and backup recovery |
| bridge-*-result.json, ica-*.json, ibc-*.json | Transactions and cross-chain assertions |
| final-unit-tests.log, final-simulation-results.json, review5-final-build.log | Candidate tests and build |

Full per-key differences, cold backups and node logs were retained in the original test-server working directory; large databases are not stored in Git. See the [rehearsal report](../sdk-053-snapshot-upgrade-2026-09-11.md) for scope and limitations.
