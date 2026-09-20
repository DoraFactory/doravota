#!/usr/bin/env bash
# Run inside a native or emulated Alpine Go container (musl, not glibc).
set -euo pipefail
: "${VERSION:?release version is required}"
case "$(go env GOARCH)" in
  amd64) asset=x86_64; suffix=amd; expected=49ecd70da281b6ee08b31770a54bb529d1de96b3e54013e025df9f0c39fff7f4 ;;
  arm64) asset=aarch64; suffix=arm64; expected=ef3e3125e1ce588a9bc698f695a1a4793432b9903a0928018c0d7872e874cc97 ;;
  *) echo 'Unsupported release architecture' >&2; exit 1 ;;
esac
wasmvm_version=$(go list -m -f '{{.Version}}' github.com/CosmWasm/wasmvm/v3)
# Update these reviewed upstream asset checksums when changing the dependency.
test "$wasmvm_version" = v3.0.7
curl --fail --show-error --location --retry 3 \
  "https://github.com/CosmWasm/wasmvm/releases/download/${wasmvm_version}/libwasmvm_muslc.${asset}.a" \
  -o "/usr/local/lib/libwasmvm_muslc.${asset}.a"
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
"release/${binary}" init release-smoke --chain-id bridge-release-smoke --home "$smoke_home" >/dev/null
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
