#!/usr/bin/env bash
# Run on a workstation with read access to the private upstream repositories.
# The cache contains source and binaries, but no GitHub credentials. Keep it private.
set -euo pipefail
cd "$(dirname "$0")/.."
export GOPRIVATE=github.com/CosmWasm/priv_wasmd_sec,github.com/CosmWasm/priv_wasmvm_sec
export GONOSUMDB="$GOPRIVATE"
go mod download github.com/CosmWasm/wasmd github.com/CosmWasm/wasmvm/v3
cache=$(go env GOMODCACHE)
mkdir -p '.modcache/github.com/!cosm!wasm'
for module in priv_wasmd_sec priv_wasmvm_sec; do
  cp -R "${cache}/cache/download/github.com/!cosm!wasm/${module}" '.modcache/github.com/!cosm!wasm/'
done
