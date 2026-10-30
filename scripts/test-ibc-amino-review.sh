#!/usr/bin/env bash
# Run inside an isolated remote builder with /evidence mounted separately.
# No node, wallet, network transaction, or production directory is used.
set -uo pipefail
cd "$(dirname "$0")/.."
evidence=${IBC_REVIEW_EVIDENCE:?set the evidence directory}
mkdir -p "$evidence" build
: > "$evidence/status.tsv"
run() {
  local name=$1
  shift
  "$@" > "$evidence/$name.log" 2>&1
  local result=$?
  printf '%s\t%s\n' "$name" "$result" | tee -a "$evidence/status.tsv"
  return 0
}
go version > "$evidence/environment.txt"
go env GOOS GOARCH GOMAXPROCS >> "$evidence/environment.txt"
go list -m github.com/cosmos/ibc-go/v11 >> "$evidence/environment.txt"
sed 's|replace github.com/cosmos/ibc-go/v11 => ./third_party/ibc-go|replace github.com/cosmos/ibc-go/v11 => github.com/cosmos/ibc-go/v11 v11.0.0-20260929073332-7b1838a13bc4|' go.mod > build/unpatched.mod
cp go.sum build/unpatched.sum
run baseline-golden go test -p 2 -mod=readonly -modfile=build/unpatched.mod ./app -run '^TestIBCCompatUnchangedSignBytes$' -v -count=1
# Expected failure proves the regression tests distinguish the unmodified release.
run baseline-negative-control go test -p 2 -mod=readonly -modfile=build/unpatched.mod ./app -run '^TestIBCCompat(AminoEncoding|CheckTx)$' -v -count=1
run compatibility go test -p 2 -mod=readonly ./app -run '^TestIBCCompat' -v -count=1
run activation go test -p 2 -mod=readonly ./app/upgrades/amino ./app -run '^Test(CommittedBoundary|AminoUpgradeLifecycle|UpgradeIdentity|VersionedUpgrade)' -v -count=1
run root-tests go test -p 2 -mod=readonly ./... -count=1
run transfer-tests go test -p 2 -mod=readonly github.com/cosmos/ibc-go/v11/modules/apps/transfer/... -count=1
run vet go vet -p 2 -mod=readonly ./...
run build env CGO_ENABLED=0 go build -p 2 -mod=readonly -trimpath \
  -ldflags '-X github.com/cosmos/cosmos-sdk/version.Version=v1.0.1 -X github.com/cosmos/cosmos-sdk/version.Commit=v1.0.0-plus-uncommitted-amino-upgrade' \
  -o build/dorad-amino-review ./cmd/dorad
if [[ -f build/dorad-amino-review ]]; then
  sha256sum build/dorad-amino-review > "$evidence/binary.sha256"
  build/dorad-amino-review version --long > "$evidence/binary-version.txt"
  go version -m build/dorad-amino-review > "$evidence/binary-modules.txt"
fi
awk -F '\t' '($1 == "baseline-negative-control" && $2 != 1) || ($1 != "baseline-negative-control" && $2 != 0) {bad=1} END {exit bad}' "$evidence/status.tsv"
