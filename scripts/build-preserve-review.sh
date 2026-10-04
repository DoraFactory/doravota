#!/usr/bin/env bash
# Linux/CGO review build. This is NOT the static validator release build.
set -euo pipefail
cd "$(dirname "$0")/.."
evidence=docs/v1.0.0-preserve/evidence
mkdir -p "$evidence" build
: "${COMMIT_SHA:?Set the reviewed full source commit}"
[[ "$COMMIT_SHA" =~ ^[0-9a-f]{40}$ ]]
go vet -p 4 ./... > "$evidence/vet.log" 2>&1
go mod verify > "$evidence/mod-verify.log" 2>&1
python3 scripts/verify-wasmd-snapshot.py > "$evidence/wasmd-snapshot-check.log"
CGO_ENABLED=1 go build -p 4 -mod=readonly -buildvcs=false -trimpath \
  -ldflags "-X github.com/cosmos/cosmos-sdk/version.Version=1.0.0 -X github.com/cosmos/cosmos-sdk/version.Commit=$COMMIT_SHA" \
  -o build/dorad ./cmd/dorad
go version -m build/dorad > "$evidence/binary-modules.txt"
sha256sum build/dorad > "$evidence/binary-sha256.txt"
build/dorad version --long > "$evidence/version.txt"
build/dorad query wasm libwasmvm-version > "$evidence/wasmvm-version.txt"
grep -qx 3.0.8 "$evidence/wasmvm-version.txt"
python3 scripts/smoke-sdk055-native.py
