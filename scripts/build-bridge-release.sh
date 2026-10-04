#!/usr/bin/env bash
# Run inside a native or emulated Alpine Go container (musl, not glibc).
set -euo pipefail
: "${VERSION:?release version is required}"
# Source archives have no .git directory: callers must supply the full commit.
commit_sha=${COMMIT_SHA:-$(git rev-parse HEAD 2>/dev/null || true)}
if [[ ! "$commit_sha" =~ ^[0-9a-f]{40}$ ]]; then
  echo 'Release requires a full 40-character commit hash; set COMMIT_SHA for source archives.' >&2
  exit 1
fi
test "${VERSION#v}" = "1.0.0"
VERSION=1.0.0
case "$(go env GOARCH)" in
  amd64) asset=x86_64; suffix=amd; expected=b2299c85d49faccf3dcbb84984f30f55e8870111df98c10f017f86204d007470 ;;
  arm64) asset=aarch64; suffix=arm64; expected=c73a0d5d340e35188e138584ddd6662a160902adef1b08b209e38d16b43a4c28 ;;
  *) echo 'Unsupported release architecture' >&2; exit 1 ;;
esac
test "$(go list -m -f '{{.Version}}' github.com/CosmWasm/wasmvm/v3)" = v3.0.8
test -z "$(go list -m -f '{{with .Replace}}{{.Path}}{{end}}' github.com/CosmWasm/wasmvm/v3)"
# Official v3.0.8 release archives are outside the Go module zip. Pin the
# release-asset SHA-256 (also published in upstream checksums.txt), not just go.sum.
curl --fail --location --retry 3 \
  "https://github.com/CosmWasm/wasmvm/releases/download/v3.0.8/libwasmvm_muslc.${asset}.a" \
  -o "/usr/local/lib/libwasmvm_muslc.${asset}.a"
printf '%s  %s\n' "$expected" "/usr/local/lib/libwasmvm_muslc.${asset}.a" | sha256sum -c -
mkdir -p release
binary="dorad-${VERSION}-linux-${suffix}"
# CI checks out as runner but builds inside a root-owned container.
# Commit identity is supplied explicitly below; do not ask Git to inspect a
# bind-mounted checkout (or require .git in exported source archives).
build_tags=${BUILD_TAGS:-muslc,netgo,osusergo,static_build}
CGO_ENABLED=1 go build -buildvcs=false -trimpath -tags "$build_tags" \
  -ldflags "-linkmode external -extldflags '-static -L/usr/local/lib -lm' -X github.com/cosmos/cosmos-sdk/version.Version=${VERSION} -X github.com/cosmos/cosmos-sdk/version.Commit=${commit_sha} -X github.com/cosmos/cosmos-sdk/version.BuildTags=${build_tags}" \
  -o "release/${binary}" ./cmd/dorad
if readelf -l "release/${binary}" | grep -q INTERP; then
  echo 'Release unexpectedly requires a dynamic loader' >&2; exit 1
fi
# Execute the actual artifact on its target architecture.
test "$("release/${binary}" version)" = "$VERSION"
smoke_home=$(mktemp -d)
trap 'rm -rf "$smoke_home"' EXIT
"release/${binary}" init release-smoke --chain-id bridge-release-smoke --home "$smoke_home" >/dev/null
test "$("release/${binary}" query wasm libwasmvm-version --home "$smoke_home")" = "3.0.8"
# Regression: fresh Comet config has a top-level version, which must not leak
# into the ICA transaction's protocol metadata. No keys or RPC are needed.
smoke_sender=dora1ny4nw32wzg70qxdtyy9a6fhkl809echuwj40f4
"release/${binary}" tx ica controller register connection-0 --from "$smoke_sender" \
  --generate-only --home "$smoke_home" >"${smoke_home}/ica-default.json"
grep -Eq '"version":[[:space:]]*""' "${smoke_home}/ica-default.json"
"release/${binary}" tx ica controller register connection-0 --from "$smoke_sender" \
  --version explicit-protocol-version --generate-only --home "$smoke_home" >"${smoke_home}/ica-explicit.json"
grep -Eq '"version":[[:space:]]*"explicit-protocol-version"' "${smoke_home}/ica-explicit.json"
smoke_recipient=dora1lpp0muhc09se5sjkdcw56qmvl97jeexxxzrfy3
"release/${binary}" tx feegrant grant "$smoke_sender" "$smoke_recipient" \
  --spend-limit 1peaka --generate-only --home "$smoke_home" >"${smoke_home}/feegrant.json"
grep -q 'MsgGrantAllowance' "${smoke_home}/feegrant.json"
"release/${binary}" tx authz grant "$smoke_recipient" send --from "$smoke_sender" \
  --spend-limit 1peaka --generate-only --home "$smoke_home" >"${smoke_home}/authz.json"
grep -q 'MsgGrant' "${smoke_home}/authz.json"
# The retired group module must not expose executable CLI commands.
if "release/${binary}" tx group --help 2>&1 | grep -q 'create-group'; then
  echo 'Retired group transaction commands are still registered' >&2; exit 1
fi
# Exercise the generated SDK genesis through the real startup path. Supplying
# --chain-id here would hide failures in the application's genesis fallback.
set +e
timeout 8 "release/${binary}" start --with-comet=false --home "$smoke_home" >"${smoke_home}/startup.log" 2>&1
startup_status=$?
set -e
# BusyBox timeout propagates a graceful child's zero exit; GNU returns 124.
if { test "$startup_status" -ne 124 && test "$startup_status" -ne 0; } || \
  ! grep -q 'Waiting for new connection' "${smoke_home}/startup.log"; then
  cat "${smoke_home}/startup.log" >&2
  echo "Release startup smoke exited unexpectedly: ${startup_status}" >&2
  exit 1
fi
tar -czf "release/${binary}.tar.gz" -C release "$binary"
