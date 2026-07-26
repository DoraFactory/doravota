#!/usr/bin/env bash

# End-to-end, single-validator rehearsal for the v1.0.0 Sponsor-module upgrade.
#
# This script is intentionally not run by CI. It builds two committed revisions,
# starts an isolated chain with the old binary, schedules the real on-chain
# software upgrade, reuses the same node home with the new binary, and verifies
# the migration plus Sponsor smoke tests.
#
# It never targets an existing node home and never deletes its work directory.

set -Eeuo pipefail

umask 077

readonly UPGRADE_NAME="v1.0.0"
readonly SPONSOR_MODULE_NAME="sponsor"
readonly WASM_MODULE_NAME="wasm"
readonly EXPECTED_SPONSOR_VERSION="1"
readonly EXPECTED_WASM_VERSION="4"

OLD_REF=""
NEW_REF="HEAD"
WASM_FILE=""
UPGRADE_ONLY="false"
WORK_DIR=""
CHAIN_ID="doravota-v1-upgrade-rehearsal"
RPC_PORT="28657"
P2P_PORT="28656"
ABCI_PORT="28658"
UPGRADE_OFFSET="40"
TIMEOUT_SECONDS="300"
VOTING_PERIOD="10s"
MIN_GAS_PRICE="0.001peaka"
TX_GAS="500000"
TX_FEE="1000peaka"
WASM_GAS="5000000"
WASM_FEE="10000peaka"
REHEARSAL_CGO_ENABLED="${REHEARSAL_CGO_ENABLED:-1}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
REPO_ROOT="$(git -C "$SCRIPT_DIR/.." rev-parse --show-toplevel 2>/dev/null || true)"

NODE_PID=""
ACTIVE_BIN=""
OLD_SOURCE=""
NEW_SOURCE=""
OLD_WORKTREE_ADDED="false"
NEW_WORKTREE_ADDED="false"
REPORT_DIR=""
NODE_HOME=""
RPC_URL=""

usage() {
  cat <<'EOF'
Usage:
  scripts/rehearse-v1.0.0-upgrade.sh \
    --old-ref <pre-sponsor git ref> \
    [--new-ref <git ref>] \
    [--wasm <counter.wasm> | --upgrade-only] \
    [options]

Required:
  --old-ref REF         Exact deployed/pre-Sponsor revision. For example: 0.4.4

Full Sponsor rehearsal:
  --wasm FILE           Prebuilt counter contract used before and after upgrade

Upgrade-only rehearsal:
  --upgrade-only        Skip CosmWasm deployment and Sponsor lifecycle smoke tests

Options:
  --new-ref REF         Revision containing v1.0.0 upgrade code (default: HEAD)
  --work-dir DIR        New directory for binaries, node data and reports
                        (default: .rehearsal/v1_0_0_<UTC timestamp>)
  --chain-id ID         Isolated chain ID
  --rpc-port PORT       Local RPC port (default: 28657)
  --p2p-port PORT       Local P2P port (default: 28656)
  --abci-port PORT      Local ABCI port (default: 28658)
  --upgrade-offset N    Upgrade height = current height + N (default: 40)
  --timeout N           Per-phase timeout in seconds (default: 300)
  --help                Show this help

Environment:
  REHEARSAL_CGO_ENABLED Build setting passed to both go builds (default: 1)

Safety:
  - The work directory must not already exist.
  - The old revision must not contain x/sponsor-contract-tx.
  - The RPC endpoint must not already be serving a node.
  - The generated key files and node home are test-only secrets.
  - The work directory is preserved after both success and failure.
EOF
}

log() {
  printf '[rehearsal] %s\n' "$*" >&2
}

warn() {
  printf '[rehearsal] WARNING: %s\n' "$*" >&2
}

die() {
  printf '[rehearsal] ERROR: %s\n' "$*" >&2
  exit 1
}

need_command() {
  command -v "$1" >/dev/null 2>&1 || die "required command not found: $1"
}

is_uint() {
  case "$1" in
    ''|*[!0-9]*) return 1 ;;
    *) return 0 ;;
  esac
}

sha256_file() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$1" | awk '{print $1}'
  else
    die "sha256sum or shasum is required"
  fi
}

stop_node() {
  if [[ -n "$NODE_PID" ]] && kill -0 "$NODE_PID" >/dev/null 2>&1; then
    log "stopping rehearsal node (pid $NODE_PID)"
    kill "$NODE_PID" >/dev/null 2>&1 || true
    wait "$NODE_PID" >/dev/null 2>&1 || true
  fi
  NODE_PID=""
}

remove_source_worktrees() {
  if [[ "$OLD_WORKTREE_ADDED" == "true" ]]; then
    git -C "$REPO_ROOT" worktree remove --force "$OLD_SOURCE" >/dev/null 2>&1 || true
    OLD_WORKTREE_ADDED="false"
  fi
  if [[ "$NEW_WORKTREE_ADDED" == "true" ]]; then
    git -C "$REPO_ROOT" worktree remove --force "$NEW_SOURCE" >/dev/null 2>&1 || true
    NEW_WORKTREE_ADDED="false"
  fi
  git -C "$REPO_ROOT" worktree prune >/dev/null 2>&1 || true
}

cleanup() {
  local exit_code=$?
  stop_node
  remove_source_worktrees
  if [[ -n "$WORK_DIR" && -d "$WORK_DIR" ]]; then
    if [[ "$exit_code" -eq 0 ]]; then
      log "artifacts preserved at: $WORK_DIR"
    else
      warn "rehearsal failed; diagnostics preserved at: $WORK_DIR"
    fi
  fi
  return "$exit_code"
}

trap cleanup EXIT
trap 'exit 130' INT TERM

while [[ $# -gt 0 ]]; do
  case "$1" in
    --old-ref)
      [[ $# -ge 2 ]] || die "--old-ref requires a value"
      OLD_REF="$2"
      shift 2
      ;;
    --new-ref)
      [[ $# -ge 2 ]] || die "--new-ref requires a value"
      NEW_REF="$2"
      shift 2
      ;;
    --wasm)
      [[ $# -ge 2 ]] || die "--wasm requires a value"
      WASM_FILE="$2"
      shift 2
      ;;
    --upgrade-only)
      UPGRADE_ONLY="true"
      shift
      ;;
    --work-dir)
      [[ $# -ge 2 ]] || die "--work-dir requires a value"
      WORK_DIR="$2"
      shift 2
      ;;
    --chain-id)
      [[ $# -ge 2 ]] || die "--chain-id requires a value"
      CHAIN_ID="$2"
      shift 2
      ;;
    --rpc-port)
      [[ $# -ge 2 ]] || die "--rpc-port requires a value"
      RPC_PORT="$2"
      shift 2
      ;;
    --p2p-port)
      [[ $# -ge 2 ]] || die "--p2p-port requires a value"
      P2P_PORT="$2"
      shift 2
      ;;
    --abci-port)
      [[ $# -ge 2 ]] || die "--abci-port requires a value"
      ABCI_PORT="$2"
      shift 2
      ;;
    --upgrade-offset)
      [[ $# -ge 2 ]] || die "--upgrade-offset requires a value"
      UPGRADE_OFFSET="$2"
      shift 2
      ;;
    --timeout)
      [[ $# -ge 2 ]] || die "--timeout requires a value"
      TIMEOUT_SECONDS="$2"
      shift 2
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    *)
      die "unknown argument: $1"
      ;;
  esac
done

[[ -n "$REPO_ROOT" ]] || die "script must run from a doravota git checkout"
[[ -n "$OLD_REF" ]] || die "--old-ref is required"
[[ "$UPGRADE_ONLY" == "false" || -z "$WASM_FILE" ]] ||
  die "--wasm and --upgrade-only are mutually exclusive"
if [[ "$UPGRADE_ONLY" == "false" && -z "$WASM_FILE" ]]; then
  die "--wasm is required unless --upgrade-only is selected"
fi

for number in "$RPC_PORT" "$P2P_PORT" "$ABCI_PORT" "$UPGRADE_OFFSET" "$TIMEOUT_SECONDS"; do
  is_uint "$number" || die "numeric option contains a non-integer value: $number"
done
((RPC_PORT > 0 && RPC_PORT <= 65535)) || die "invalid RPC port: $RPC_PORT"
((P2P_PORT > 0 && P2P_PORT <= 65535)) || die "invalid P2P port: $P2P_PORT"
((ABCI_PORT > 0 && ABCI_PORT <= 65535)) || die "invalid ABCI port: $ABCI_PORT"
((UPGRADE_OFFSET >= 15)) || die "--upgrade-offset must be at least 15 blocks"
((TIMEOUT_SECONDS >= 30)) || die "--timeout must be at least 30 seconds"

need_command git
need_command go
need_command jq
need_command curl
need_command awk
need_command cp

if [[ -n "$WASM_FILE" ]]; then
  [[ -f "$WASM_FILE" ]] || die "Wasm file not found: $WASM_FILE"
  WASM_FILE="$(cd "$(dirname "$WASM_FILE")" && printf '%s/%s\n' "$(pwd -P)" "$(basename "$WASM_FILE")")"
fi

if [[ -z "$WORK_DIR" ]]; then
  WORK_DIR="$REPO_ROOT/.rehearsal/v1_0_0_$(date -u +%Y%m%dT%H%M%SZ)"
elif [[ "$WORK_DIR" != /* ]]; then
  WORK_DIR="$(pwd -P)/$WORK_DIR"
fi

[[ "$WORK_DIR" != "/" ]] || die "refusing to use / as work directory"
[[ "$WORK_DIR" != "$REPO_ROOT" ]] || die "refusing to use repository root as work directory"
[[ "$WORK_DIR" != "${HOME:-__unset__}" ]] || die "refusing to use the user home as work directory"
[[ ! -e "$WORK_DIR" ]] || die "work directory already exists: $WORK_DIR"

RPC_URL="http://127.0.0.1:$RPC_PORT"
if curl --silent --fail --max-time 2 "$RPC_URL/status" >/dev/null 2>&1; then
  die "RPC endpoint is already serving a node: $RPC_URL"
fi

OLD_SHA="$(git -C "$REPO_ROOT" rev-parse --verify "$OLD_REF^{commit}" 2>/dev/null || true)"
NEW_SHA="$(git -C "$REPO_ROOT" rev-parse --verify "$NEW_REF^{commit}" 2>/dev/null || true)"
[[ -n "$OLD_SHA" ]] || die "cannot resolve old ref: $OLD_REF"
[[ -n "$NEW_SHA" ]] || die "cannot resolve new ref: $NEW_REF"
[[ "$OLD_SHA" != "$NEW_SHA" ]] || die "old and new refs resolve to the same commit"

if git -C "$REPO_ROOT" cat-file -e "$OLD_SHA:x/sponsor-contract-tx/module.go" 2>/dev/null; then
  die "old ref already contains the Sponsor module; use the exact pre-Sponsor production revision"
fi
git -C "$REPO_ROOT" cat-file -e "$NEW_SHA:x/sponsor-contract-tx/module.go" 2>/dev/null ||
  die "new ref does not contain the Sponsor module"
git -C "$REPO_ROOT" grep -q 'UpgradeName = "v1.0.0"' "$NEW_SHA" -- app/upgrades/v1_0_0/constants.go ||
  die "new ref does not declare the exact v1.0.0 upgrade name"
git -C "$REPO_ROOT" grep -q 'Added:.*sponsortypes.StoreKey' "$NEW_SHA" -- app/upgrades/v1_0_0/store.go ||
  die "new ref does not declare the Sponsor store addition"

mkdir -p "$WORK_DIR/bin" "$WORK_DIR/logs" "$WORK_DIR/reports" "$WORK_DIR/secrets"
chmod 700 "$WORK_DIR" "$WORK_DIR/secrets"

REPORT_DIR="$WORK_DIR/reports"
NODE_HOME="$WORK_DIR/node-home"
OLD_SOURCE="$WORK_DIR/source-old"
NEW_SOURCE="$WORK_DIR/source-new"
readonly OLD_BIN="$WORK_DIR/bin/dorad-old"
readonly NEW_BIN="$WORK_DIR/bin/dorad-new"

log "old ref: $OLD_REF ($OLD_SHA)"
log "new ref: $NEW_REF ($NEW_SHA)"
log "work directory: $WORK_DIR"

git -C "$REPO_ROOT" worktree add --detach "$OLD_SOURCE" "$OLD_SHA" >/dev/null
OLD_WORKTREE_ADDED="true"
git -C "$REPO_ROOT" worktree add --detach "$NEW_SOURCE" "$NEW_SHA" >/dev/null
NEW_WORKTREE_ADDED="true"

log "building old binary"
(
  cd "$OLD_SOURCE"
  CGO_ENABLED="$REHEARSAL_CGO_ENABLED" go build -mod=readonly -o "$OLD_BIN" ./cmd/dorad
)

log "building new binary"
(
  cd "$NEW_SOURCE"
  CGO_ENABLED="$REHEARSAL_CGO_ENABLED" go build -mod=readonly -o "$NEW_BIN" ./cmd/dorad
)

"$OLD_BIN" version --long >"$REPORT_DIR/old-version.txt"
"$NEW_BIN" version --long >"$REPORT_DIR/new-version.txt"

jq -n \
  --arg upgrade_name "$UPGRADE_NAME" \
  --arg old_ref "$OLD_REF" \
  --arg old_sha "$OLD_SHA" \
  --arg old_binary_sha256 "$(sha256_file "$OLD_BIN")" \
  --arg new_ref "$NEW_REF" \
  --arg new_sha "$NEW_SHA" \
  --arg new_binary_sha256 "$(sha256_file "$NEW_BIN")" \
  --arg chain_id "$CHAIN_ID" \
  --arg rpc_url "$RPC_URL" \
  --arg wasm_sha256 "$([[ -n "$WASM_FILE" ]] && sha256_file "$WASM_FILE" || printf '')" \
  '{
    upgrade_name: $upgrade_name,
    old: {ref: $old_ref, commit: $old_sha, binary_sha256: $old_binary_sha256},
    new: {ref: $new_ref, commit: $new_sha, binary_sha256: $new_binary_sha256},
    chain_id: $chain_id,
    rpc_url: $rpc_url,
    wasm_sha256: (if $wasm_sha256 == "" then null else $wasm_sha256 end)
  }' >"$REPORT_DIR/manifest.json"

log "initializing isolated old-version chain"
"$OLD_BIN" init rehearsal-validator --chain-id "$CHAIN_ID" --home "$NODE_HOME" >/dev/null

"$OLD_BIN" keys add validator --keyring-backend test --home "$NODE_HOME" --output json \
  >"$WORK_DIR/secrets/validator.json"
"$OLD_BIN" keys add admin --keyring-backend test --home "$NODE_HOME" --output json \
  >"$WORK_DIR/secrets/admin.json"
"$OLD_BIN" keys add user --keyring-backend test --home "$NODE_HOME" --output json \
  >"$WORK_DIR/secrets/user.json"

VALIDATOR_ADDRESS="$("$OLD_BIN" keys show validator -a --keyring-backend test --home "$NODE_HOME")"
ADMIN_ADDRESS="$("$OLD_BIN" keys show admin -a --keyring-backend test --home "$NODE_HOME")"
USER_ADDRESS="$("$OLD_BIN" keys show user -a --keyring-backend test --home "$NODE_HOME")"
readonly VALIDATOR_ADDRESS ADMIN_ADDRESS USER_ADDRESS

"$OLD_BIN" add-genesis-account "$VALIDATOR_ADDRESS" \
  1000000000000000000000000peaka --home "$NODE_HOME"
"$OLD_BIN" add-genesis-account "$ADMIN_ADDRESS" \
  1000000000000000000000000peaka --home "$NODE_HOME"
# The user account must exist for signing but remain unable to self-pay a 1000peaka fee.
"$OLD_BIN" add-genesis-account "$USER_ADDRESS" 1peaka --home "$NODE_HOME"
"$OLD_BIN" gentx validator 1000000000000000000000peaka \
  --chain-id "$CHAIN_ID" --keyring-backend test --home "$NODE_HOME" >/dev/null
"$OLD_BIN" collect-gentxs --home "$NODE_HOME" >/dev/null

GENESIS_FILE="$NODE_HOME/config/genesis.json"
GENESIS_TMP="$NODE_HOME/config/genesis.rehearsal.json"
jq \
  --arg voting_period "$VOTING_PERIOD" \
  '.app_state.gov.params.min_deposit = [{"denom":"peaka","amount":"1000000"}]
   | .app_state.gov.params.max_deposit_period = $voting_period
   | .app_state.gov.params.voting_period = $voting_period' \
  "$GENESIS_FILE" >"$GENESIS_TMP"
mv "$GENESIS_TMP" "$GENESIS_FILE"
"$OLD_BIN" validate-genesis --home "$NODE_HOME" >"$REPORT_DIR/validate-genesis.txt"

start_node() {
  local binary="$1"
  local log_file="$2"

  ACTIVE_BIN="$binary"
  "$binary" start \
    --home "$NODE_HOME" \
    --minimum-gas-prices "$MIN_GAS_PRICE" \
    --rpc.laddr "tcp://127.0.0.1:$RPC_PORT" \
    --p2p.laddr "tcp://127.0.0.1:$P2P_PORT" \
    --address "tcp://127.0.0.1:$ABCI_PORT" \
    --grpc.enable=false \
    --grpc-web.enable=false \
    --pruning nothing \
    >"$log_file" 2>&1 &
  NODE_PID=$!
}

rpc_status() {
  curl --silent --show-error --fail --max-time 3 "$RPC_URL/status"
}

rpc_height() {
  rpc_status | jq -r '.result.sync_info.latest_block_height | tonumber'
}

wait_for_rpc() {
  local deadline=$(( $(date +%s) + TIMEOUT_SECONDS ))
  while (( $(date +%s) < deadline )); do
    if [[ -n "$NODE_PID" ]] && ! kill -0 "$NODE_PID" >/dev/null 2>&1; then
      die "node exited before RPC became ready; inspect the active node log"
    fi
    if rpc_status >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  die "timed out waiting for RPC readiness"
}

wait_for_height() {
  local target="$1"
  local deadline=$(( $(date +%s) + TIMEOUT_SECONDS ))
  local current=0
  while (( $(date +%s) < deadline )); do
    current="$(rpc_height 2>/dev/null || printf '0')"
    if is_uint "$current" && ((current >= target)); then
      return 0
    fi
    if [[ -n "$NODE_PID" ]] && ! kill -0 "$NODE_PID" >/dev/null 2>&1; then
      die "node exited while waiting for height $target"
    fi
    sleep 1
  done
  die "timed out waiting for height $target; last observed height: $current"
}

query_json() {
  "$ACTIVE_BIN" query "$@" \
    --home "$NODE_HOME" \
    --node "$RPC_URL" \
    --output json
}

broadcast_sync() {
  local label="$1"
  shift
  local response
  local stderr_file="$REPORT_DIR/${label}.broadcast.stderr"

  if ! response="$("$@" \
    --chain-id "$CHAIN_ID" \
    --home "$NODE_HOME" \
    --node "$RPC_URL" \
    --keyring-backend test \
    --yes \
    --output json \
    --broadcast-mode sync \
    2>"$stderr_file")"; then
    die "$label broadcast command failed; inspect $stderr_file"
  fi
  printf '%s\n' "$response" >"$REPORT_DIR/${label}.checktx.json"
  if ! jq -e '((.code // 0) | tonumber) == 0' >/dev/null 2>&1 \
    <"$REPORT_DIR/${label}.checktx.json"; then
    die "$label failed CheckTx: $(jq -r '.raw_log // .log // "unknown error"' "$REPORT_DIR/${label}.checktx.json")"
  fi
  printf '%s\n' "$response"
}

wait_for_tx() {
  local label="$1"
  local txhash="$2"
  local deadline=$(( $(date +%s) + TIMEOUT_SECONDS ))
  local result=""

  while (( $(date +%s) < deadline )); do
    if result="$("$ACTIVE_BIN" query tx "$txhash" \
      --home "$NODE_HOME" \
      --node "$RPC_URL" \
      --output json 2>/dev/null)"; then
      printf '%s\n' "$result" >"$REPORT_DIR/${label}.deliver.json"
      if ! jq -e '((.code // 0) | tonumber) == 0' >/dev/null 2>&1 \
        <"$REPORT_DIR/${label}.deliver.json"; then
        die "$label failed DeliverTx: $(jq -r '.raw_log // "unknown error"' "$REPORT_DIR/${label}.deliver.json")"
      fi
      printf '%s\n' "$result"
      return 0
    fi
    sleep 1
  done
  die "timed out waiting for transaction $label ($txhash)"
}

wait_for_failed_tx() {
  local label="$1"
  local txhash="$2"
  local deadline=$(( $(date +%s) + TIMEOUT_SECONDS ))
  local result=""

  while (( $(date +%s) < deadline )); do
    if result="$("$ACTIVE_BIN" query tx "$txhash" \
      --home "$NODE_HOME" \
      --node "$RPC_URL" \
      --output json 2>/dev/null)"; then
      printf '%s\n' "$result" >"$REPORT_DIR/${label}.expected-deliver-rejection.json"
      if jq -e '((.code // 0) | tonumber) != 0' >/dev/null 2>&1 \
        <"$REPORT_DIR/${label}.expected-deliver-rejection.json"; then
        return 0
      fi
      die "$label unexpectedly succeeded in DeliverTx"
    fi
    sleep 1
  done
  die "timed out waiting for expected failed transaction $label ($txhash)"
}

broadcast_and_wait() {
  local label="$1"
  shift
  local checktx
  local txhash

  checktx="$(broadcast_sync "$label" "$@")"
  txhash="$(printf '%s\n' "$checktx" | jq -r '.txhash // empty')"
  [[ -n "$txhash" ]] || die "$label response has no txhash"
  wait_for_tx "$label" "$txhash"
}

expect_deliver_rejection() {
  local label="$1"
  shift
  local checktx
  local txhash

  checktx="$(broadcast_sync "$label" "$@")"
  txhash="$(printf '%s\n' "$checktx" | jq -r '.txhash // empty')"
  [[ -n "$txhash" ]] || die "$label response has no txhash"
  wait_for_failed_tx "$label" "$txhash"
}

expect_sync_rejection() {
  local label="$1"
  shift
  local response=""
  local exit_code=0
  local stderr_file="$REPORT_DIR/${label}.expected-rejection.stderr"

  set +e
  response="$("$@" \
    --chain-id "$CHAIN_ID" \
    --home "$NODE_HOME" \
    --node "$RPC_URL" \
    --keyring-backend test \
    --yes \
    --output json \
    --broadcast-mode sync \
    2>"$stderr_file")"
  exit_code=$?
  set -e

  printf '%s\n' "$response" >"$REPORT_DIR/${label}.expected-rejection.json"
  if [[ "$exit_code" -ne 0 ]]; then
    return 0
  fi
  if jq -e '((.code // 0) | tonumber) != 0' >/dev/null 2>&1 \
    <"$REPORT_DIR/${label}.expected-rejection.json"; then
    return 0
  fi
  die "$label unexpectedly passed CheckTx"
}

event_attribute() {
  local tx_json="$1"
  local event_type="$2"
  local attribute_key="$3"
  printf '%s\n' "$tx_json" | jq -r \
    --arg event_type "$event_type" \
    --arg attribute_key "$attribute_key" \
    '[
      .logs[]?.events[]?
      | select(.type == $event_type)
      | .attributes[]?
      | select(.key == $attribute_key)
      | .value
    ][0] // empty'
}

wait_for_proposal_passed() {
  local proposal_id="$1"
  local deadline=$(( $(date +%s) + TIMEOUT_SECONDS ))
  local proposal=""
  local status=""

  while (( $(date +%s) < deadline )); do
    proposal="$(query_json gov proposal "$proposal_id" 2>/dev/null || true)"
    status="$(printf '%s\n' "$proposal" | jq -r '.status // empty' 2>/dev/null || true)"
    if [[ "$status" == "PROPOSAL_STATUS_PASSED" || "$status" == "3" ]]; then
      printf '%s\n' "$proposal" >"$REPORT_DIR/upgrade-proposal-passed.json"
      return 0
    fi
    if [[ "$status" == "PROPOSAL_STATUS_REJECTED" ||
          "$status" == "PROPOSAL_STATUS_FAILED" ||
          "$status" == "4" || "$status" == "5" ]]; then
      die "upgrade proposal entered terminal non-passed status: $status"
    fi
    sleep 1
  done
  die "timed out waiting for proposal $proposal_id to pass; last status: $status"
}

wait_for_old_binary_halt() {
  local expected_height="$1"
  local deadline=$(( $(date +%s) + TIMEOUT_SECONDS ))
  local last_status=""

  while (( $(date +%s) < deadline )); do
    if ! kill -0 "$NODE_PID" >/dev/null 2>&1; then
      set +e
      wait "$NODE_PID"
      local node_exit_code=$?
      set -e
      printf '%s\n' "$node_exit_code" >"$REPORT_DIR/old-node-exit-code.txt"
      NODE_PID=""
      return 0
    fi
    last_status="$(rpc_status 2>/dev/null || true)"
    if [[ -n "$last_status" ]]; then
      printf '%s\n' "$last_status" >"$REPORT_DIR/old-last-rpc-status.json"
    fi
    sleep 1
  done
  die "old binary did not halt for upgrade height $expected_height"
}

assert_json_equal() {
  local label="$1"
  local before_file="$2"
  local after_file="$3"
  local before
  local after
  before="$(jq -S -c . "$before_file")"
  after="$(jq -S -c . "$after_file")"
  [[ "$before" == "$after" ]] ||
    die "$label changed across upgrade; compare $before_file and $after_file"
}

log "starting old binary"
start_node "$OLD_BIN" "$WORK_DIR/logs/old-node.log"
wait_for_rpc
wait_for_height 2

CONTRACT_ADDRESS=""
INITIAL_COUNT="41"

if [[ "$UPGRADE_ONLY" == "false" ]]; then
  log "deploying pre-upgrade counter contract"
  STORE_TX="$(broadcast_and_wait wasm-store \
    "$OLD_BIN" tx wasm store "$WASM_FILE" \
    --from admin --gas "$WASM_GAS" --fees "$WASM_FEE")"
  CODE_ID="$(event_attribute "$STORE_TX" store_code code_id)"
  [[ -n "$CODE_ID" ]] || die "could not extract code_id from wasm store transaction"

  INSTANTIATE_TX="$(broadcast_and_wait wasm-instantiate \
    "$OLD_BIN" tx wasm instantiate "$CODE_ID" "{\"initial_count\":$INITIAL_COUNT}" \
    --from admin \
    --admin "$ADMIN_ADDRESS" \
    --label v1-upgrade-rehearsal-counter \
    --gas "$WASM_GAS" \
    --fees "$WASM_FEE")"
  CONTRACT_ADDRESS="$(event_attribute "$INSTANTIATE_TX" instantiate _contract_address)"
  [[ -n "$CONTRACT_ADDRESS" ]] ||
    die "could not extract contract address from instantiate transaction"

  query_json wasm contract "$CONTRACT_ADDRESS" >"$REPORT_DIR/contract-before-upgrade.json"
  query_json wasm contract-state smart "$CONTRACT_ADDRESS" '{"get_count":{}}' \
    >"$REPORT_DIR/contract-state-before-upgrade.json"
  jq -e --argjson expected "$INITIAL_COUNT" '.data.count == $expected' \
    "$REPORT_DIR/contract-state-before-upgrade.json" >/dev/null ||
    die "unexpected pre-upgrade counter value"
fi

CURRENT_HEIGHT="$(rpc_height)"
UPGRADE_HEIGHT=$((CURRENT_HEIGHT + UPGRADE_OFFSET))
log "scheduling $UPGRADE_NAME for height $UPGRADE_HEIGHT"

PROPOSAL_TX="$(broadcast_and_wait submit-upgrade-proposal \
  "$OLD_BIN" tx gov submit-legacy-proposal software-upgrade "$UPGRADE_NAME" \
  --title "Doravota v1.0.0 rehearsal" \
  --description "Isolated rehearsal for the Sponsor module store upgrade" \
  --upgrade-height "$UPGRADE_HEIGHT" \
  --deposit 1000000peaka \
  --from validator \
  --gas "$TX_GAS" \
  --fees "$TX_FEE")"
PROPOSAL_ID="$(event_attribute "$PROPOSAL_TX" submit_proposal proposal_id)"
[[ -n "$PROPOSAL_ID" ]] || die "could not extract governance proposal ID"

broadcast_and_wait vote-upgrade-proposal \
  "$OLD_BIN" tx gov vote "$PROPOSAL_ID" yes \
  --from validator \
  --gas "$TX_GAS" \
  --fees "$TX_FEE" >/dev/null

wait_for_proposal_passed "$PROPOSAL_ID"
query_json upgrade plan >"$REPORT_DIR/upgrade-plan.json"
jq -e \
  --arg expected_name "$UPGRADE_NAME" \
  --argjson expected_height "$UPGRADE_HEIGHT" \
  '(.name // .plan.name) == $expected_name
   and (((.height // .plan.height) | tonumber) == $expected_height)' \
  "$REPORT_DIR/upgrade-plan.json" >/dev/null ||
  die "scheduled upgrade plan does not match expected name and height"

query_json bank balances "$ADMIN_ADDRESS" >"$REPORT_DIR/admin-balances-before-upgrade.json"
query_json bank balances "$USER_ADDRESS" >"$REPORT_DIR/user-balances-before-upgrade.json"
rpc_status >"$REPORT_DIR/rpc-status-before-upgrade.json"

log "waiting for old binary to halt at upgrade height"
wait_for_old_binary_halt "$UPGRADE_HEIGHT"

UPGRADE_INFO_FILE="$NODE_HOME/data/upgrade-info.json"
[[ -f "$UPGRADE_INFO_FILE" ]] || die "old binary did not write data/upgrade-info.json"
jq -e \
  --arg expected_name "$UPGRADE_NAME" \
  --argjson expected_height "$UPGRADE_HEIGHT" \
  '.name == $expected_name and ((.height | tonumber) == $expected_height)' \
  "$UPGRADE_INFO_FILE" >/dev/null ||
  die "upgrade-info.json does not match the scheduled upgrade"
cp "$UPGRADE_INFO_FILE" "$REPORT_DIR/upgrade-info.json"

log "creating rollback copy of the halted old node home"
cp -a "$NODE_HOME" "$WORK_DIR/node-home-before-upgrade"

log "starting new binary against the same node home"
start_node "$NEW_BIN" "$WORK_DIR/logs/new-node.log"
wait_for_rpc
wait_for_height $((UPGRADE_HEIGHT + 2))

query_json upgrade applied "$UPGRADE_NAME" >"$REPORT_DIR/upgrade-applied.json"
query_json upgrade module_versions "$SPONSOR_MODULE_NAME" \
  >"$REPORT_DIR/sponsor-module-version.json"
query_json upgrade module_versions "$WASM_MODULE_NAME" \
  >"$REPORT_DIR/wasm-module-version.json"
query_json sponsor params >"$REPORT_DIR/sponsor-params.json"

jq -e \
  --arg name "$SPONSOR_MODULE_NAME" \
  --argjson version "$EXPECTED_SPONSOR_VERSION" \
  '.module_versions
   | any(.name == $name and ((.version | tonumber) == $version))' \
  "$REPORT_DIR/sponsor-module-version.json" >/dev/null ||
  die "Sponsor module version is not $EXPECTED_SPONSOR_VERSION"
jq -e \
  --arg name "$WASM_MODULE_NAME" \
  --argjson version "$EXPECTED_WASM_VERSION" \
  '.module_versions
   | any(.name == $name and ((.version | tonumber) == $version))' \
  "$REPORT_DIR/wasm-module-version.json" >/dev/null ||
  die "Wasm module version is not $EXPECTED_WASM_VERSION"
jq -e '.params.sponsorship_enabled == true
       and ((.params.policy_ticket_ttl_blocks | tonumber) == 30)
       and ((.params.ticket_gc_per_block | tonumber) == 200)' \
  "$REPORT_DIR/sponsor-params.json" >/dev/null ||
  die "Sponsor default parameters were not initialized correctly"

query_json bank balances "$ADMIN_ADDRESS" >"$REPORT_DIR/admin-balances-after-upgrade.json"
query_json bank balances "$USER_ADDRESS" >"$REPORT_DIR/user-balances-after-upgrade.json"
assert_json_equal "admin balance" \
  "$REPORT_DIR/admin-balances-before-upgrade.json" \
  "$REPORT_DIR/admin-balances-after-upgrade.json"
assert_json_equal "user balance" \
  "$REPORT_DIR/user-balances-before-upgrade.json" \
  "$REPORT_DIR/user-balances-after-upgrade.json"

GENERATION_ONE=""
GENERATION_TWO=""
CHECK_STATE_RESERVATION_SAME_HEIGHT="null"

if [[ "$UPGRADE_ONLY" == "false" ]]; then
  log "verifying pre-upgrade contract state and admin survived"
  query_json wasm contract "$CONTRACT_ADDRESS" >"$REPORT_DIR/contract-after-upgrade.json"
  query_json wasm contract-state smart "$CONTRACT_ADDRESS" '{"get_count":{}}' \
    >"$REPORT_DIR/contract-state-after-upgrade.json"

  BEFORE_ADMIN="$(jq -r '.admin // empty' "$REPORT_DIR/contract-before-upgrade.json")"
  AFTER_ADMIN="$(jq -r '.admin // empty' "$REPORT_DIR/contract-after-upgrade.json")"
  [[ "$BEFORE_ADMIN" == "$ADMIN_ADDRESS" && "$AFTER_ADMIN" == "$ADMIN_ADDRESS" ]] ||
    die "contract admin did not survive the upgrade"
  jq -e --argjson expected "$INITIAL_COUNT" '.data.count == $expected' \
    "$REPORT_DIR/contract-state-after-upgrade.json" >/dev/null ||
    die "contract state did not survive the upgrade"

  log "running Sponsor ticket, CheckTx reservation and lifecycle smoke tests"
  broadcast_and_wait whitelist-user \
    "$NEW_BIN" tx wasm execute "$CONTRACT_ADDRESS" \
    "{\"add_to_whitelist\":{\"address\":\"$USER_ADDRESS\"}}" \
    --from admin --gas "$TX_GAS" --fees "$TX_FEE" >/dev/null

  broadcast_and_wait set-sponsor-generation-one \
    "$NEW_BIN" tx sponsor set-sponsor "$CONTRACT_ADDRESS" true 1000000peaka \
    --from admin --gas "$TX_GAS" --fees "$TX_FEE" >/dev/null
  query_json sponsor sponsor-info "$CONTRACT_ADDRESS" \
    >"$REPORT_DIR/sponsor-generation-one.json"
  GENERATION_ONE="$(jq -r '.sponsor.generation | tonumber' \
    "$REPORT_DIR/sponsor-generation-one.json")"
  SPONSOR_ADDRESS="$(jq -r '.sponsor.sponsor_address // empty' \
    "$REPORT_DIR/sponsor-generation-one.json")"
  [[ -n "$SPONSOR_ADDRESS" ]] || die "Sponsor address was not created"

  broadcast_and_wait fund-sponsor-generation-one \
    "$NEW_BIN" tx bank send admin "$SPONSOR_ADDRESS" 500000peaka \
    --from admin --gas "$TX_GAS" --fees "$TX_FEE" >/dev/null

  broadcast_and_wait issue-increment-ticket \
    "$NEW_BIN" tx sponsor issue-ticket "$CONTRACT_ADDRESS" "$USER_ADDRESS" \
    --method increment --uses 1 \
    --from admin --gas "$TX_GAS" --fees "$TX_FEE" >/dev/null
  broadcast_and_wait issue-decrement-ticket \
    "$NEW_BIN" tx sponsor issue-ticket "$CONTRACT_ADDRESS" "$USER_ADDRESS" \
    --method decrement --uses 1 \
    --from admin --gas "$TX_GAS" --fees "$TX_FEE" >/dev/null

  USER_ACCOUNT="$(query_json auth account "$USER_ADDRESS")"
  USER_ACCOUNT_NUMBER="$(printf '%s\n' "$USER_ACCOUNT" |
    jq -r 'first(.. | objects | .account_number? // empty)')"
  USER_SEQUENCE="$(printf '%s\n' "$USER_ACCOUNT" |
    jq -r 'first(.. | objects | .sequence? // empty)')"
  is_uint "$USER_ACCOUNT_NUMBER" || die "could not read user account number"
  is_uint "$USER_SEQUENCE" || die "could not read user account sequence"

  RESERVATION_HEIGHT_BEFORE="$(rpc_height)"
  SPONSORED_CHECKTX="$(broadcast_sync sponsored-increment \
    "$NEW_BIN" tx wasm execute "$CONTRACT_ADDRESS" '{"increment":{"amount":1}}' \
    --from user --gas "$TX_GAS" --fees "$TX_FEE")"
  SPONSORED_TXHASH="$(printf '%s\n' "$SPONSORED_CHECKTX" | jq -r '.txhash // empty')"
  [[ -n "$SPONSORED_TXHASH" ]] || die "sponsored transaction has no txhash"

  expect_sync_rejection duplicate-one-use-ticket \
    "$NEW_BIN" tx wasm execute "$CONTRACT_ADDRESS" '{"increment":{"amount":1}}' \
    --from user \
    --account-number "$USER_ACCOUNT_NUMBER" \
    --sequence "$((USER_SEQUENCE + 1))" \
    --gas "$TX_GAS" \
    --fees "$TX_FEE"
  RESERVATION_HEIGHT_AFTER="$(rpc_height)"
  if [[ "$RESERVATION_HEIGHT_BEFORE" == "$RESERVATION_HEIGHT_AFTER" ]]; then
    CHECK_STATE_RESERVATION_SAME_HEIGHT="true"
  else
    CHECK_STATE_RESERVATION_SAME_HEIGHT="false"
    warn "duplicate rejection crossed a block boundary; ticket safety passed, but rerun to observe same-height CheckTx reservation"
  fi
  wait_for_tx sponsored-increment "$SPONSORED_TXHASH" >/dev/null

  query_json sponsor ticket-by-method "$CONTRACT_ADDRESS" "$USER_ADDRESS" increment \
    >"$REPORT_DIR/increment-ticket-after-use.json"
  jq -e '.ticket.consumed == true
         and ((.ticket.uses_remaining | tonumber) == 0)' \
    "$REPORT_DIR/increment-ticket-after-use.json" >/dev/null ||
    die "one-use increment ticket was not consumed"

  query_json sponsor grant-usage "$USER_ADDRESS" "$CONTRACT_ADDRESS" \
    >"$REPORT_DIR/grant-usage-generation-one.json"
  jq -e '[.usage.total_grant_used[]?
          | select(.denom == "peaka")
          | (.amount | tonumber)]
         | add == 1000' \
    "$REPORT_DIR/grant-usage-generation-one.json" >/dev/null ||
    die "sponsored fee was not recorded as exactly 1000peaka"

  query_json wasm contract-state smart "$CONTRACT_ADDRESS" '{"get_count":{}}' \
    >"$REPORT_DIR/contract-state-after-sponsored-tx.json"
  jq -e --argjson expected "$((INITIAL_COUNT + 1))" '.data.count == $expected' \
    "$REPORT_DIR/contract-state-after-sponsored-tx.json" >/dev/null ||
    die "sponsored contract execution did not update state"

  expect_deliver_rejection clear-admin-with-sponsor \
    "$NEW_BIN" tx wasm clear-contract-admin "$CONTRACT_ADDRESS" \
    --from admin --gas "$TX_GAS" --fees "$TX_FEE"

  broadcast_and_wait withdraw-generation-one \
    "$NEW_BIN" tx sponsor withdraw-sponsor-funds "$CONTRACT_ADDRESS" "$ADMIN_ADDRESS" \
    --from admin --gas "$TX_GAS" --fees "$TX_FEE" >/dev/null
  broadcast_and_wait delete-generation-one \
    "$NEW_BIN" tx sponsor delete-sponsor "$CONTRACT_ADDRESS" \
    --from admin --gas "$TX_GAS" --fees "$TX_FEE" >/dev/null

  broadcast_and_wait set-sponsor-generation-two \
    "$NEW_BIN" tx sponsor set-sponsor "$CONTRACT_ADDRESS" true 1000000peaka \
    --from admin --gas "$TX_GAS" --fees "$TX_FEE" >/dev/null
  query_json sponsor sponsor-info "$CONTRACT_ADDRESS" \
    >"$REPORT_DIR/sponsor-generation-two.json"
  GENERATION_TWO="$(jq -r '.sponsor.generation | tonumber' \
    "$REPORT_DIR/sponsor-generation-two.json")"
  ((GENERATION_TWO > GENERATION_ONE)) ||
    die "Sponsor generation did not increase after delete and recreate"

  broadcast_and_wait fund-sponsor-generation-two \
    "$NEW_BIN" tx bank send admin "$SPONSOR_ADDRESS" 500000peaka \
    --from admin --gas "$TX_GAS" --fees "$TX_FEE" >/dev/null

  query_json sponsor ticket-by-method "$CONTRACT_ADDRESS" "$USER_ADDRESS" decrement \
    >"$REPORT_DIR/old-decrement-ticket-after-recreate.json"
  jq -e '.ticket == null' \
    "$REPORT_DIR/old-decrement-ticket-after-recreate.json" >/dev/null ||
    die "old-generation decrement ticket became visible after Sponsor recreation"

  query_json sponsor grant-usage "$USER_ADDRESS" "$CONTRACT_ADDRESS" \
    >"$REPORT_DIR/grant-usage-generation-two.json"
  jq -e '(.usage.total_grant_used // []) | length == 0' \
    "$REPORT_DIR/grant-usage-generation-two.json" >/dev/null ||
    die "new Sponsor generation inherited old user grant usage"

  expect_sync_rejection old-ticket-cannot-authorize \
    "$NEW_BIN" tx wasm execute "$CONTRACT_ADDRESS" '{"decrement":{}}' \
    --from user --gas "$TX_GAS" --fees "$TX_FEE"

  broadcast_and_wait withdraw-generation-two \
    "$NEW_BIN" tx sponsor withdraw-sponsor-funds "$CONTRACT_ADDRESS" "$ADMIN_ADDRESS" \
    --from admin --gas "$TX_GAS" --fees "$TX_FEE" >/dev/null
  broadcast_and_wait delete-generation-two \
    "$NEW_BIN" tx sponsor delete-sponsor "$CONTRACT_ADDRESS" \
    --from admin --gas "$TX_GAS" --fees "$TX_FEE" >/dev/null
  broadcast_and_wait clear-admin-after-sponsor-delete \
    "$NEW_BIN" tx wasm clear-contract-admin "$CONTRACT_ADDRESS" \
    --from admin --gas "$TX_GAS" --fees "$TX_FEE" >/dev/null

  query_json wasm contract "$CONTRACT_ADDRESS" >"$REPORT_DIR/contract-after-clear-admin.json"
  jq -e '(.admin // "") == ""' "$REPORT_DIR/contract-after-clear-admin.json" >/dev/null ||
    die "contract admin was not cleared after Sponsor deletion"
fi

FINAL_STATUS="$(rpc_status)"
printf '%s\n' "$FINAL_STATUS" >"$REPORT_DIR/final-rpc-status.json"
FINAL_HEIGHT="$(printf '%s\n' "$FINAL_STATUS" |
  jq -r '.result.sync_info.latest_block_height | tonumber')"
FINAL_APP_HASH="$(printf '%s\n' "$FINAL_STATUS" |
  jq -r '.result.sync_info.latest_app_hash')"

jq -n \
  --arg status "passed" \
  --arg upgrade_name "$UPGRADE_NAME" \
  --argjson upgrade_height "$UPGRADE_HEIGHT" \
  --argjson final_height "$FINAL_HEIGHT" \
  --arg final_app_hash "$FINAL_APP_HASH" \
  --arg old_commit "$OLD_SHA" \
  --arg new_commit "$NEW_SHA" \
  --argjson sponsor_module_version "$EXPECTED_SPONSOR_VERSION" \
  --argjson wasm_module_version "$EXPECTED_WASM_VERSION" \
  --argjson full_sponsor_rehearsal "$([[ "$UPGRADE_ONLY" == "false" ]] && printf true || printf false)" \
  --argjson check_state_reservation_same_height "$CHECK_STATE_RESERVATION_SAME_HEIGHT" \
  --arg generation_one "$GENERATION_ONE" \
  --arg generation_two "$GENERATION_TWO" \
  '{
    status: $status,
    upgrade_name: $upgrade_name,
    upgrade_height: $upgrade_height,
    final_height: $final_height,
    final_app_hash: $final_app_hash,
    old_commit: $old_commit,
    new_commit: $new_commit,
    sponsor_module_version: $sponsor_module_version,
    wasm_module_version: $wasm_module_version,
    full_sponsor_rehearsal: $full_sponsor_rehearsal,
    check_state_reservation_same_height: $check_state_reservation_same_height,
    sponsor_generation_one:
      (if $generation_one == "" then null else ($generation_one | tonumber) end),
    sponsor_generation_two:
      (if $generation_two == "" then null else ($generation_two | tonumber) end)
  }' >"$REPORT_DIR/summary.json"

touch "$WORK_DIR/PASSED"
log "v1.0.0 upgrade rehearsal passed"
log "summary: $REPORT_DIR/summary.json"
