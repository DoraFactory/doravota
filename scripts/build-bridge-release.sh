#!/usr/bin/env bash
# Run inside a native or emulated Alpine Go container (musl, not glibc).
set -euo pipefail
: "${VERSION:?release version is required}"
case "$(go env GOARCH)" in
  amd64) asset=x86_64; suffix=amd; expected=ab1a878ed3beecc5f3821b1fb1f73a5254443e3ba9bca53964a50a122ee77497 ;;
  arm64) asset=aarch64; suffix=arm64; expected=cc9175235d1e0051002c33a94027a63a008b14dcc13ae483685e511d59754235 ;;
  *) echo 'Unsupported release architecture' >&2; exit 1 ;;
esac
# Verify the replacement, then use its bundled native library. A public release
# download would silently link the old engine despite the patched Go dependency.
test "$(go list -m -f '{{with .Replace}}{{.Path}}@{{.Version}}{{end}}' github.com/CosmWasm/wasmvm/v3)" = \
  github.com/CosmWasm/priv_wasmvm_sec/v3@v3.0.8-rc.3
test "$(go list -m -f '{{with .Replace}}{{.Path}}@{{.Version}}{{end}}' github.com/CosmWasm/wasmd)" = \
  github.com/CosmWasm/priv_wasmd_sec@v0.61.15-rc.3
wasmvm_dir=$(go list -m -f '{{.Dir}}' github.com/CosmWasm/wasmvm/v3)
xz -dc "${wasmvm_dir}/internal/api/libwasmvm_muslc.${asset}.a.xz" \
  >"/usr/local/lib/libwasmvm_muslc.${asset}.a"
printf '%s  %s\n' "$expected" "/usr/local/lib/libwasmvm_muslc.${asset}.a" | sha256sum -c -
commit_sha=${COMMIT_SHA:-$(git rev-parse HEAD 2>/dev/null || printf unknown)}
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
test "$("release/${binary}" query wasm libwasmvm-version --home "$smoke_home")" = "3.0.8-rc.3"
"release/${binary}" init release-smoke --chain-id bridge-release-smoke --home "$smoke_home" >/dev/null
# Regression: fresh Comet config has a top-level version, which must not leak
# into the ICA transaction's protocol metadata. No keys or RPC are needed.
smoke_sender=dora1ny4nw32wzg70qxdtyy9a6fhkl809echuwj40f4
"release/${binary}" tx ica controller register connection-0 --from "$smoke_sender" \
  --generate-only --chain-id bridge-release-smoke --home "$smoke_home" >"${smoke_home}/ica-default.json"
grep -Eq '"version":[[:space:]]*""' "${smoke_home}/ica-default.json"
"release/${binary}" tx ica controller register connection-0 --from "$smoke_sender" \
  --version explicit-protocol-version --generate-only --chain-id bridge-release-smoke --home "$smoke_home" >"${smoke_home}/ica-explicit.json"
grep -Eq '"version":[[:space:]]*"explicit-protocol-version"' "${smoke_home}/ica-explicit.json"
smoke_recipient=dora1lpp0muhc09se5sjkdcw56qmvl97jeexxxzrfy3
"release/${binary}" tx feegrant grant "$smoke_sender" "$smoke_recipient" \
  --spend-limit 1peaka --generate-only --chain-id bridge-release-smoke --home "$smoke_home" >"${smoke_home}/feegrant.json"
grep -q 'MsgGrantAllowance' "${smoke_home}/feegrant.json"
"release/${binary}" tx authz grant "$smoke_recipient" send --from "$smoke_sender" \
  --spend-limit 1peaka --generate-only --chain-id bridge-release-smoke --home "$smoke_home" >"${smoke_home}/authz.json"
grep -q 'MsgGrant' "${smoke_home}/authz.json"
printf '{"members":[{"address":"%s","weight":"1","metadata":""}]}' "$smoke_sender" >"${smoke_home}/members.json"
"release/${binary}" tx group create-group "$smoke_sender" smoke "${smoke_home}/members.json" \
  --generate-only --chain-id bridge-release-smoke --home "$smoke_home" >"${smoke_home}/group.json"
grep -q 'MsgCreateGroup' "${smoke_home}/group.json"
# Exercise the generated SDK genesis through the real startup path. Supplying
# --chain-id here would hide failures in the application's genesis fallback.
set +e
timeout 8 "release/${binary}" start --with-tendermint=false --home "$smoke_home" >"${smoke_home}/startup.log" 2>&1
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
