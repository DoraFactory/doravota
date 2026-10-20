#!/usr/bin/env bash
# No Wasm VM or native library is needed. Run builds and smoke tests on Linux.
set -euo pipefail
: "${VERSION:?candidate version is required}"
commit_sha=${COMMIT_SHA:-$(git rev-parse HEAD 2>/dev/null || true)}
[[ "$commit_sha" =~ ^[0-9a-f]{40}$ ]] || { echo 'Full source commit required' >&2; exit 1; }
expected_version=$(cat VERSION)
version_pattern='^v[0-9]+\.[0-9]+\.[0-9]+$'
if [[ "${ALLOW_PRERELEASE:-false}" = true ]]; then
 version_pattern='^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z]+([.-][0-9A-Za-z]+)*)?$'
fi
[[ "$VERSION" =~ $version_pattern && "$VERSION" = "$expected_version" ]] || {
 echo "Release version must match VERSION (${expected_version}), including the v prefix" >&2; exit 1
}
[[ "$(go env GOOS)" = linux ]] || exit 1
case "$(go env GOARCH)" in amd64) suffix=amd64 ;; arm64) suffix=arm64 ;; *) exit 1 ;; esac
modules=$(go list -m all)
if grep -Ei 'github.com/(CosmWasm|DoraFactory)/(wasmd|wasmvm)' <<< "$modules"; then
 echo 'Unexpected Wasm runtime dependency' >&2; exit 1
fi
mkdir -p release
binary="dorad-${VERSION}-linux-${suffix}"
build_tags=netgo,osusergo
CGO_ENABLED=0 go build -buildvcs=false -trimpath -tags "$build_tags" \
 -ldflags "-s -w -X github.com/cosmos/cosmos-sdk/version.Version=${VERSION} -X github.com/cosmos/cosmos-sdk/version.Commit=${commit_sha} -X github.com/cosmos/cosmos-sdk/version.BuildTags=${build_tags}" \
 -o "release/${binary}" ./cmd/dorad
if readelf -l "release/${binary}" | grep -q INTERP; then exit 1; fi
if readelf -d "release/${binary}" | grep -q NEEDED; then exit 1; fi
test "$("release/${binary}" version)" = "$VERSION"
smoke_home=$(mktemp -d)
trap 'rm -rf "$smoke_home"' EXIT
"release/${binary}" init release-smoke --chain-id archive-release-smoke --home "$smoke_home" >/dev/null
"release/${binary}" query wasm-archive --help >/dev/null
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
