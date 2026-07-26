#!/usr/bin/env bash

set -euo pipefail

minimum_coverage="${PQCAUTH_COVERAGE_MIN:-80.0}"
coverage_dir="$(mktemp -d "${TMPDIR:-/tmp}/pqcauth-coverage.XXXXXX")"
trap 'rm -rf "$coverage_dir"' EXIT

go test \
  -count=1 \
  -covermode=atomic \
  -coverpkg=./x/pqcauth/... \
  -coverprofile="$coverage_dir/all.out" \
  ./x/pqcauth/...

# Generated protobuf and gRPC gateway implementations are machine-produced
# compatibility code. The gate measures the handwritten consensus, keeper,
# client, and cryptographic logic instead.
awk \
  'NR == 1 || $0 !~ /\.pb(\.gw)?\.go:/ { print }' \
  "$coverage_dir/all.out" \
  >"$coverage_dir/handwritten.out"

actual_coverage="$(
  go tool cover -func="$coverage_dir/handwritten.out" |
    awk '/^total:/ { gsub(/%/, "", $3); print $3 }'
)"

if [[ -z "$actual_coverage" ]]; then
  echo "unable to determine pqcauth coverage" >&2
  exit 1
fi

if ! awk \
  -v actual="$actual_coverage" \
  -v minimum="$minimum_coverage" \
  'BEGIN { exit !((actual + 0) >= (minimum + 0)) }'
then
  printf \
    'pqcauth handwritten coverage %s%% is below the required %s%%\n' \
    "$actual_coverage" \
    "$minimum_coverage" \
    >&2
  exit 1
fi

printf \
  'pqcauth handwritten coverage: %s%% (minimum: %s%%)\n' \
  "$actual_coverage" \
  "$minimum_coverage"
