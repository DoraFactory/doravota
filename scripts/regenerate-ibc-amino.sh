#!/usr/bin/env sh
# Regenerate the one changed proto using the upstream gocosmos generator.
# By default compare only. --write replaces the generated file explicitly.
set -eu
root=$(cd "$(dirname "$0")/.." && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
cd "$root/third_party/ibc-go"
buf generate proto --path proto/ibc/applications/transfer/v1/tx.proto \
  --template "{\"version\":\"v1\",\"plugins\":[{\"name\":\"gocosmos\",\"out\":\"$tmp\",\"opt\":\"plugins=grpc,Mgoogle/protobuf/any.proto=github.com/cosmos/cosmos-sdk/codec/types\"}]}"
generated="$tmp/github.com/cosmos/ibc-go/v11/modules/apps/transfer/types/tx.pb.go"
target=modules/apps/transfer/types/tx.pb.go
if [ "${1:-}" = --write ]; then
  cp "$generated" "$target"
else
  cmp "$generated" "$target"
  echo 'PASS: generated tx.pb.go is reproducible'
fi
