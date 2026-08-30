#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
WORK_DIR="${PQC_IBC_WORK_DIR:-$(mktemp -d /tmp/doravota-pqc-ibc.XXXXXX)}"
IBC_ROOT="$(cd "$REPO_ROOT" && go list -m -f '{{.Dir}}' github.com/cosmos/ibc-go/v11)"
IBC_COPY="$WORK_DIR/ibc-go"
MOD_FILE="$WORK_DIR/pqcibc.mod"
REPORT_FILE="$WORK_DIR/result.json"

mkdir -p "$WORK_DIR/disabled-simapp" "$WORK_DIR/logs"
cp -R "$IBC_ROOT" "$IBC_COPY"
chmod -R u+w "$IBC_COPY"

# IBC-Go v11.2's harness is valid, but its bundled SimApp still calls SDK
# constructors removed in v0.55. Keep an audit copy of those helpers and use
# the narrow Dora-backed compatibility implementation for this isolated test.
mv "$IBC_COPY/testing/simapp/ante.go" "$WORK_DIR/disabled-simapp/ante.go"
mv "$IBC_COPY/testing/simapp/genesis.go" "$WORK_DIR/disabled-simapp/genesis.go"
mv "$IBC_COPY/testing/simapp/test_helpers.go" "$WORK_DIR/disabled-simapp/test_helpers.go"
cp "$REPO_ROOT/third_party/ibc-go-testing-simapp-v055-compat/simapp.go" \
  "$IBC_COPY/testing/simapp/app.go"

cp "$REPO_ROOT/go.mod" "$MOD_FILE"
cp "$REPO_ROOT/go.sum" "$WORK_DIR/pqcibc.sum"
(
  cd "$REPO_ROOT"
  go mod edit -modfile="$MOD_FILE" -replace="github.com/cosmos/ibc-go/v11=$IBC_COPY"

  go test ./pkg/pqcibc -count=1 -v \
    | tee "$WORK_DIR/logs/relayer-adapter.log"
  go test ./tests/e2e/pqc-ibc/cmd/pqcibc-preflight -count=1 \
    | tee "$WORK_DIR/logs/preflight-build.log"
  go test -modfile="$MOD_FILE" -tags pqcibc_e2e ./app \
    -run '^TestPQCIBCTwoChainCompatibility$' -count=1 -v \
    | tee "$WORK_DIR/logs/two-chain.log"
)

jq -n \
  --arg result PASS \
  --arg work_dir "$WORK_DIR" \
  --arg ibc_version "$(cd "$REPO_ROOT" && go list -m -f '{{.Version}}' github.com/cosmos/ibc-go/v11)" \
  --arg sdk_version "$(cd "$REPO_ROOT" && go list -m -f '{{.Version}}' github.com/cosmos/cosmos-sdk)" \
  --arg comet_version "$(cd "$REPO_ROOT" && go list -m -f '{{.Version}}' github.com/cometbft/cometbft)" \
  '{
    result:$result,
    work_dir:$work_dir,
    versions:{ibc_go:$ibc_version,cosmos_sdk:$sdk_version,cometbft:$comet_version},
    checks:[
      "Dora App pair initialized with independent state",
      "07-tendermint clients, connection and ICS-20 channel opened",
      "ICS-20 packet relayed before consensus-key rotation",
      "old-signed transition header relayed before all-ML-DSA commit",
      "existing clients updated across Ed25519 to ML-DSA-65 rotation on both chains",
      "ICS-20 packets and acknowledgements relayed after both rotations",
      "ML-DSA-65 header protobuf round trip and admission limits",
      "native ML-DSA-65 relayer key creation and SIGN_MODE_DIRECT signing"
    ]
  }' >"$REPORT_FILE"

printf 'PQC-IBC compatibility suite: PASS\n'
printf 'Artifacts retained at: %s\n' "$WORK_DIR"
printf 'Machine-readable result: %s\n' "$REPORT_FILE"
