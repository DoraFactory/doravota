#!/usr/bin/env bash
# Run in a native Linux musl build environment (see Dockerfile.emergency).
# No application execution, chain initialization or tests are run here.
set -euo pipefail
export LC_ALL=C
cd "$(dirname "$0")/.."

die() { echo "ERROR: $*" >&2; exit 1; }
[[ $(uname -s) == Linux ]] || die 'Use a Linux musl builder.'
[[ ${EMERGENCY_HEIGHT:-} =~ ^[1-9][0-9]*$ ]] || die 'Set the agreed EMERGENCY_HEIGHT explicitly.'
[[ ${#EMERGENCY_HEIGHT} -le 18 ]] || die 'EMERGENCY_HEIGHT is out of range.'
[[ ${EMERGENCY_CHAIN_ID:-} =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ ]] || die 'Set EMERGENCY_CHAIN_ID explicitly.'
if [[ $EMERGENCY_CHAIN_ID == vota-ash ]] && (( EMERGENCY_HEIGHT >= 17520000 )); then
  die 'Emergency activation must precede the scheduled mainnet 0.5.0 upgrade.'
fi
if [[ -z ${COMMIT_SHA:-} ]]; then
  COMMIT_SHA=$(git rev-parse HEAD)
fi
[[ $COMMIT_SHA =~ ^[0-9a-f]{40}$ ]] || die 'COMMIT_SHA must be the full source commit.'
for command in go curl sha256sum readelf ar cc; do
  command -v "$command" >/dev/null || die "Missing $command"
done

# Avoid accidentally building a different architecture using an incompatible C
# compiler. Build each target in its native Linux container.
case $(uname -m) in
  x86_64)
    target_arch=amd64
    archive_arch=x86_64
    archive_sha=c0f4614d0835be78ac8f3d647a70ccd7ed9f48632bc1374db04e4df2245cb467
    ;;
  aarch64|arm64)
    target_arch=arm64
    archive_arch=aarch64
    archive_sha=b89c242ffe2c867267621a6469f07ab70fc204091809d9c6f482c3fdf9293830
    ;;
  *) die 'Supported architectures: x86_64 and arm64.' ;;
esac
[[ -z ${GOARCH:-} || $GOARCH == "$target_arch" ]] || die 'Use a native target-architecture builder.'
[[ -z ${GOOS:-} || $GOOS == linux ]] || die 'GOOS must be linux.'
export GOOS=linux GOARCH="$target_arch" CGO_ENABLED=1 GOWORK=off GOTOOLCHAIN=local
# The shipped recipe uses the system musl compiler. Do not silently fall back to
# a dynamic/glibc build if static PIE fails for the old Rust archive.
[[ -f /etc/alpine-release ]] || die 'Use the Alpine musl builder in Dockerfile.emergency.'
export CC=cc
unset CGO_LDFLAGS CGO_CFLAGS CGO_CPPFLAGS CGO_CXXFLAGS GOFLAGS

sdk_version=$(go list -mod=readonly -m -f '{{.Version}}' github.com/cosmos/cosmos-sdk)
wasmd_version=$(go list -mod=readonly -m -f '{{.Version}}' github.com/CosmWasm/wasmd)
wasmvm_version=$(go list -mod=readonly -m -f '{{.Version}}' github.com/CosmWasm/wasmvm)
[[ $sdk_version == v0.47.17 && $wasmd_version == v0.43.0 && $wasmvm_version == v1.5.1 ]] || die 'Unexpected dependency versions.'
go mod download github.com/CosmWasm/wasmvm

build_tmp=$(mktemp -d /tmp/vota-emergency-build.XXXXXX)
trap 'rm -rf "$build_tmp"' EXIT
curl --fail --location --retry 3 \
  "https://github.com/CosmWasm/wasmvm/releases/download/v1.5.1/libwasmvm_muslc.${archive_arch}.a" \
  --output "$build_tmp/libwasmvm_muslc.a"
# Pinned to the official v1.5.1 checksums.txt, not a mutable user-supplied hash.
printf '%s  %s\n' "$archive_sha" "$build_tmp/libwasmvm_muslc.a" | sha256sum --check -
ar t "$build_tmp/libwasmvm_muslc.a" >/dev/null
export CGO_LDFLAGS="-L${build_tmp}"

output=${OUTPUT:-build/dorad}
mkdir -p "$(dirname "$output")"
module=github.com/DoraFactory/doravota
build_tags=muslc,netgo,osusergo,static_build,ledger
go build -mod=readonly -trimpath -buildmode=pie -tags "$build_tags" \
  -ldflags "-X ${module}/app.EmergencyWasmHeight=${EMERGENCY_HEIGHT} -X ${module}/app.EmergencyWasmChainID=${EMERGENCY_CHAIN_ID} -X github.com/cosmos/cosmos-sdk/version.Commit=${COMMIT_SHA} -X github.com/cosmos/cosmos-sdk/version.BuildTags=${build_tags} -w -s -linkmode=external -extldflags '-Wl,-z,muldefs -static-pie -z noexecstack -lm'" \
  -o "$build_tmp/dorad" ./cmd/dorad

# Inspect without running the binary. Static PIE is ELF DYN with no interpreter
# or dynamic-library dependencies; it must also carry the PIE dynamic flag.
readelf -hW "$build_tmp/dorad" > "$build_tmp/elf-header"
readelf -lW "$build_tmp/dorad" > "$build_tmp/elf-programs"
readelf -dW "$build_tmp/dorad" > "$build_tmp/elf-dynamic"
grep -Eq 'Type:[[:space:]]+DYN' "$build_tmp/elf-header" || die 'ELF is not position independent.'
grep -Eq 'FLAGS_1.*PIE' "$build_tmp/elf-dynamic" || die 'ELF lacks the PIE flag.'
if grep -q 'INTERP' "$build_tmp/elf-programs" || grep -q '(NEEDED)' "$build_tmp/elf-dynamic"; then
  die 'Binary is not statically linked; refusing to publish an artifact.'
fi
install -m 0755 "$build_tmp/dorad" "$output"
sha256sum "$output" > "${output}.sha256"
{
  printf 'version=0.4.4-wasm-emergency.1\ncommit=%s\nchain_id=%s\nactivation_height=%s\n' "$COMMIT_SHA" "$EMERGENCY_CHAIN_ID" "$EMERGENCY_HEIGHT"
  printf 'arch=%s\nwasmvm_archive_sha256=%s\n' "$target_arch" "$archive_sha"
  go version
  go version -m "$output"
} > "${output}.build-info.txt"
echo "Candidate built: $output. Node ASLR and application compatibility still require validation."
