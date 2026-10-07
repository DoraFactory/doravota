# IBC channel migration in 1.0.0

This upgrade is pinned to IBC-Go commit `7b1838a13bc442393253b3b3d995e228a3995855`.
Its core consensus version is 8, the same as the 0.5.0 source chain. The upstream
channel v11 migration is not registered with `RunMigrations`, so the upgrade
handler explicitly invokes it through a guarded wrapper.

The migration changes the send-sequence key for every existing channel and adds
alias/counterparty metadata where applicable. The upstream function is NOT
idempotent: after deleting the old keys, a second call can overwrite sequences
with zero. The wrapper rejects missing, malformed, zero or mixed source state,
checks core version before `RunMigrations`, checks again before the manual call,
and verifies every resulting sequence and old-key deletion.

Before changing IBC-Go:

1. Review the actual replacement revision, core consensus version and registered
   migrations. The version test is an intentional dependency review gate.
2. Determine whether the new dependency automatically runs this migration.
   Account for chains that already completed 1.0.0. Do not blindly increase
   `fromVM["ibc"]`: that could skip other necessary migrations in the same step.
   Design the next upgrade for the exact old/new schemas and test it separately.
3. On an isolated snapshot compare every channel's send/recv/ack sequence,
   commitments and metadata before/after; missing or extra destination entries
   must be investigated.
4. Create a channel before upgrading and exercise in-flight packets, new sends,
   returns, acknowledgements, timeout refunds and restart on the same channel.

This policy does not enable new IBC v2 application routes or change consensus keys.
