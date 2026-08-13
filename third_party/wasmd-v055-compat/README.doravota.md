# Wasmd v0.70.3 compatibility snapshot

This directory is a source snapshot of `github.com/CosmWasm/wasmd` v0.70.3,
trimmed to the `x/wasm` module code used by Doravota. It exists only because
Wasmd v0.70.3 targets Cosmos SDK v0.54 while Doravota targets SDK v0.55.0.

The v0.70.3 production Wasm keeper compiles against SDK v0.55. The remaining
source conflicts are in a legacy test-helper file that imports the removed SDK
`x/params` keeper and in two public aliases of those helpers. This snapshot has
exactly these compatibility changes:

1. `x/wasm/keeper/test_common.go` is guarded by Go's explicit `ignore` build
   tag because its dependencies no longer exist in SDK v0.55.
2. `CreateTestInput` and `TestHandler` aliases are removed from
   `x/wasm/alias.go`.

Upstream Wasmd `_test.go` files and keeper test fixtures are intentionally
omitted. Doravota tests the integrated Wasm behavior in its own `app` and
module test suites; the upstream v0.70.3 release remains the source of record
for Wasmd's own test suite.

The historical `x/wasm/exported.ParamSet` dependency is satisfied by the
separate compile-only `third_party/cosmos-sdk-x-params-compat` package. The app
does not mount the removed `x/params` module and refuses to run the historical
Wasm v2-to-v3 params migration directly.

Remove this replacement and use an official Wasmd release as soon as Wasmd
publishes a version targeting Cosmos SDK v0.55. Keep the upstream version,
license, and NOTICE files intact when refreshing the snapshot.
