# Doravota x/group compatibility snapshot

This directory is a source snapshot of `x/group` from Cosmos SDK v0.53.6,
adapted to the SDK v0.55 Store v2 import paths.

Cosmos SDK v0.54 moved `x/group` out of the main SDK distribution. Doravota
already mounted and exposed the group module on its v0.47 production line, so
dropping that store during the v0.55/PQC upgrade would silently discard
existing group state. This compatibility package keeps the same module name,
protobuf API, consensus version (2), key layout, and lifecycle behavior while
the application moves to SDK v0.55.

Only mechanical compatibility changes are applied:

- imports point at this repository-local package instead of the removed
  `github.com/cosmos/cosmos-sdk/x/group` path;
- legacy `cosmossdk.io/store` imports point at SDK v0.55 Store v2;
- upstream tests and test-only helpers are omitted; application integration
  tests cover mounting, genesis, command registration, and state retention.

This copy remains Apache-2.0 under the upstream Cosmos SDK license. Security
fixes to the retired module must be reviewed and backported explicitly. It is
not a new group implementation and must not change the existing wire or store
format.
