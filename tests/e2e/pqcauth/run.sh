#!/usr/bin/env bash

# Real-node end-to-end test for x/pqcauth.
#
# The harness creates a brand-new, isolated network home, starts real dorad
# processes, sends real transactions through CometBFT, and preserves all
# diagnostics. It never targets or deletes an existing node home.

set -Eeuo pipefail

umask 077

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
REPO_ROOT="$(git -C "$SCRIPT_DIR" rev-parse --show-toplevel 2>/dev/null || true)"

NODES="${E2E_NODES:-4}"
PORT_BASE="${E2E_PORT_BASE:-31650}"
TIMEOUT_SECONDS="${E2E_TIMEOUT_SECONDS:-180}"
CHAIN_ID="${E2E_CHAIN_ID:-pqcauth-e2e-$(date -u +%Y%m%d%H%M%S)-$$}"
WORK_DIR="${E2E_WORK_DIR:-}"
DORAD_BIN="${DORAD_BIN:-}"
PQCTX_BIN="${PQCTX_BIN:-}"
KEEP_RUNNING="${E2E_KEEP_RUNNING:-false}"

DENOM="peaka"
GENESIS_BALANCE="1000000000000000000000000${DENOM}"
STAKE_AMOUNT="1000000000000000000000${DENOM}"
TX_GAS="5000000"
TX_FEE="100000${DENOM}"
MIN_GAS_PRICE="0.001${DENOM}"

NODE_PIDS=()
NODE_START_COUNTS=()
PASS_COUNT=0
FAIL_COUNT=0
LAST_TX_HASH=""
LAST_TX_HEIGHT="0"
FINAL_HEIGHT="0"
FINAL_APP_HASH=""
RUN_STARTED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
RUN_STARTED_EPOCH="$(date +%s)"

usage() {
  printf '%s\n' \
    "Usage: tests/e2e/pqcauth/run.sh [options]" \
    "" \
    "Options:" \
    "  --binary FILE       Use an already-built dorad binary" \
    "  --pqctx-binary FILE Use an already-built adversarial tx helper" \
    "  --work-dir DIR      New directory for node data and reports" \
    "  --nodes N           Number of validators (default: 4)" \
    "  --port-base N       First node P2P port (default: 31650)" \
    "  --timeout N         Per-operation timeout in seconds" \
    "  --chain-id ID       Isolated chain ID" \
    "  --keep-running      Leave test nodes running after success" \
    "  --help              Show this help" \
    "" \
    "Environment equivalents:" \
    "  DORAD_BIN, PQCTX_BIN, E2E_WORK_DIR, E2E_NODES, E2E_PORT_BASE," \
    "  E2E_TIMEOUT_SECONDS, E2E_CHAIN_ID, E2E_KEEP_RUNNING" \
    "" \
    "Safety:" \
    "  The work directory must not already exist and is never deleted."
}

log() {
  printf '[pqcauth-e2e] %s\n' "$*" >&2
}

warn() {
  printf '[pqcauth-e2e] WARNING: %s\n' "$*" >&2
}

record_result() {
  local status="$1"
  local name="$2"
  local detail="${3:-}"
  jq -cn \
    --arg status "$status" \
    --arg name "$name" \
    --arg detail "$detail" \
    '{status:$status,name:$name,detail:$detail}' >>"$RESULTS_JSONL"
}

pass() {
  local name="$1"
  local detail="${2:-}"
  PASS_COUNT=$((PASS_COUNT + 1))
  record_result pass "$name" "$detail"
  log "PASS: $name${detail:+ ($detail)}"
}

die() {
  local message="$1"
  FAIL_COUNT=$((FAIL_COUNT + 1))
  if [[ -n "${RESULTS_JSONL:-}" && -f "${RESULTS_JSONL:-}" ]]; then
    record_result fail "fatal" "$message"
  fi
  printf '[pqcauth-e2e] ERROR: %s\n' "$message" >&2
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

artifact_name() {
  printf '%s' "$1" | tr -cs 'A-Za-z0-9._-' '_'
}

node_home() {
  printf '%s/nodes/node%s' "$WORK_DIR" "$1"
}

node_p2p_port() {
  printf '%d' $((PORT_BASE + ($1 * 10)))
}

node_rpc_port() {
  printf '%d' $((PORT_BASE + ($1 * 10) + 1))
}

node_abci_port() {
  printf '%d' $((PORT_BASE + ($1 * 10) + 2))
}

node_grpc_port() {
  printf '%d' $((PORT_BASE + ($1 * 10) + 3))
}

node_rpc_url() {
  printf 'http://127.0.0.1:%s' "$(node_rpc_port "$1")"
}

port_open() {
  local port="$1"
  timeout 1 bash -c "exec 3<>/dev/tcp/127.0.0.1/$port" >/dev/null 2>&1
}

stop_one_node() {
  local index="$1"
  local pid="${NODE_PIDS[$index]:-}"
  if [[ -z "$pid" ]] || ! kill -0 "$pid" >/dev/null 2>&1; then
    NODE_PIDS[$index]=""
    return 0
  fi
  log "stopping node$index (pid $pid)"
  kill "$pid" >/dev/null 2>&1 || true
  local deadline=$(( $(date +%s) + 10 ))
  while kill -0 "$pid" >/dev/null 2>&1 && (( $(date +%s) < deadline )); do
    sleep 1
  done
  if kill -0 "$pid" >/dev/null 2>&1; then
    warn "node$index did not stop after SIGTERM; sending SIGKILL to test pid $pid"
    kill -KILL "$pid" >/dev/null 2>&1 || true
  fi
  wait "$pid" >/dev/null 2>&1 || true
  NODE_PIDS[$index]=""
}

stop_network() {
  local index
  for ((index = 0; index < NODES; index++)); do
    stop_one_node "$index"
  done
}

write_report() {
  local exit_code="$1"
  local status="passed"
  if (( exit_code != 0 )); then
    status="failed"
  fi
  local finished_at duration_seconds
  finished_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  duration_seconds=$(( $(date +%s) - RUN_STARTED_EPOCH ))
  if [[ -f "$RESULTS_JSONL" && -f "$METRICS_JSONL" ]]; then
    jq -s \
      --slurpfile metrics "$METRICS_JSONL" \
      --arg status "$status" \
      --arg chain_id "$CHAIN_ID" \
      --arg work_dir "$WORK_DIR" \
      --arg binary "$DORAD_BIN" \
      --arg git_commit "$GIT_COMMIT" \
      --arg started_at "$RUN_STARTED_AT" \
      --arg finished_at "$finished_at" \
      --arg final_app_hash "$FINAL_APP_HASH" \
      --argjson nodes "$NODES" \
      --argjson passed "$PASS_COUNT" \
      --argjson failed "$FAIL_COUNT" \
      --argjson duration_seconds "$duration_seconds" \
      --argjson final_height "$FINAL_HEIGHT" \
      '{status:$status,chain_id:$chain_id,nodes:$nodes,git_commit:$git_commit,binary:$binary,work_dir:$work_dir,started_at:$started_at,finished_at:$finished_at,duration_seconds:$duration_seconds,final_height:$final_height,final_app_hash:$final_app_hash,passed:$passed,failed:$failed,transaction_metrics:$metrics,results:.}' \
      "$RESULTS_JSONL" >"$REPORT_DIR/report.json" || true
  fi
}

on_exit() {
  local exit_code="$1"
  trap - EXIT
  if [[ "$KEEP_RUNNING" == "true" && "$exit_code" -eq 0 ]]; then
    warn "test nodes left running by request; pid file: $REPORT_DIR/node-pids.txt"
  else
    stop_network
  fi
  write_report "$exit_code"
  if (( exit_code == 0 )); then
    log "completed successfully; artifacts: $WORK_DIR"
  else
    warn "failed; diagnostics preserved at: $WORK_DIR"
  fi
  exit "$exit_code"
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --binary)
      [[ $# -ge 2 ]] || { usage; exit 2; }
      DORAD_BIN="$2"
      shift 2
      ;;
    --pqctx-binary)
      [[ $# -ge 2 ]] || { usage; exit 2; }
      PQCTX_BIN="$2"
      shift 2
      ;;
    --work-dir)
      [[ $# -ge 2 ]] || { usage; exit 2; }
      WORK_DIR="$2"
      shift 2
      ;;
    --nodes)
      [[ $# -ge 2 ]] || { usage; exit 2; }
      NODES="$2"
      shift 2
      ;;
    --port-base)
      [[ $# -ge 2 ]] || { usage; exit 2; }
      PORT_BASE="$2"
      shift 2
      ;;
    --timeout)
      [[ $# -ge 2 ]] || { usage; exit 2; }
      TIMEOUT_SECONDS="$2"
      shift 2
      ;;
    --chain-id)
      [[ $# -ge 2 ]] || { usage; exit 2; }
      CHAIN_ID="$2"
      shift 2
      ;;
    --keep-running)
      KEEP_RUNNING="true"
      shift
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    *)
      printf 'unknown argument: %s\n' "$1" >&2
      usage
      exit 2
      ;;
  esac
done

[[ -n "$REPO_ROOT" ]] || { printf 'run this script from a doravota git checkout\n' >&2; exit 1; }
is_uint "$NODES" || { printf 'nodes must be a positive integer\n' >&2; exit 2; }
is_uint "$PORT_BASE" || { printf 'port base must be a positive integer\n' >&2; exit 2; }
is_uint "$TIMEOUT_SECONDS" || { printf 'timeout must be a positive integer\n' >&2; exit 2; }
(( NODES >= 1 && NODES <= 4 )) || { printf 'nodes must be between 1 and 4\n' >&2; exit 2; }
(( PORT_BASE >= 1024 && PORT_BASE + (NODES * 10) + 3 <= 65535 )) || {
  printf 'port range is outside 1024..65535\n' >&2
  exit 2
}

need_command jq
need_command curl
need_command timeout
need_command openssl

if [[ -z "$WORK_DIR" ]]; then
  WORK_DIR="$REPO_ROOT/.e2e/pqcauth/$(date -u +%Y%m%dT%H%M%SZ)-$$"
elif [[ "$WORK_DIR" != /* ]]; then
  WORK_DIR="$PWD/$WORK_DIR"
fi
[[ ! -e "$WORK_DIR" ]] || { printf 'work directory already exists: %s\n' "$WORK_DIR" >&2; exit 1; }

mkdir -p "$WORK_DIR/bin" "$WORK_DIR/nodes" "$WORK_DIR/client" \
  "$WORK_DIR/secrets" "$WORK_DIR/pqc" "$WORK_DIR/tx" \
  "$WORK_DIR/logs" "$WORK_DIR/reports"
printf 'doravota pqcauth e2e work directory\n' >"$WORK_DIR/.pqcauth-e2e-marker"

REPORT_DIR="$WORK_DIR/reports"
RESULTS_JSONL="$REPORT_DIR/results.jsonl"
METRICS_JSONL="$REPORT_DIR/transaction-metrics.jsonl"
: >"$RESULTS_JSONL"
: >"$METRICS_JSONL"
GIT_COMMIT="$(git -C "$REPO_ROOT" rev-parse HEAD 2>/dev/null || printf unknown)"

trap 'on_exit "$?"' EXIT
trap 'exit 130' INT TERM

if [[ -z "$DORAD_BIN" ]]; then
  need_command go
  log "building dorad from current checkout"
  DORAD_BIN="$WORK_DIR/bin/dorad"
  (cd "$REPO_ROOT" && go build -mod=readonly -o "$DORAD_BIN" ./cmd/dorad)
elif [[ "$DORAD_BIN" != /* ]]; then
  DORAD_BIN="$PWD/$DORAD_BIN"
fi
[[ -x "$DORAD_BIN" ]] || die "dorad binary is not executable: $DORAD_BIN"
"$DORAD_BIN" tx pqcauth --help >/dev/null 2>&1 || die "dorad binary does not expose tx pqcauth"

if [[ -z "$PQCTX_BIN" ]]; then
  need_command go
  log "building test-only adversarial transaction helper"
  PQCTX_BIN="$WORK_DIR/bin/pqctx"
  (cd "$REPO_ROOT" && go build -mod=readonly -o "$PQCTX_BIN" ./tests/e2e/pqcauth/cmd/pqctx)
elif [[ "$PQCTX_BIN" != /* ]]; then
  PQCTX_BIN="$PWD/$PQCTX_BIN"
fi
[[ -x "$PQCTX_BIN" ]] || die "pqctx helper is not executable: $PQCTX_BIN"

CLIENT_HOME="$WORK_DIR/client"
RPC_URL="$(node_rpc_url 0)"

rpc_status() {
  local index="${1:-0}"
  curl --silent --show-error --fail --max-time 3 "$(node_rpc_url "$index")/status"
}

rpc_height() {
  rpc_status "${1:-0}" | jq -r '.result.sync_info.latest_block_height | tonumber'
}

wait_for_rpc() {
  local index="$1"
  local deadline=$(( $(date +%s) + TIMEOUT_SECONDS ))
  while (( $(date +%s) < deadline )); do
    local pid="${NODE_PIDS[$index]:-}"
    if [[ -n "$pid" ]] && ! kill -0 "$pid" >/dev/null 2>&1; then
      die "node$index exited before RPC became ready; inspect its log"
    fi
    if rpc_status "$index" >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  die "timed out waiting for node$index RPC"
}

wait_for_height() {
  local target="$1"
  local index="${2:-0}"
  local deadline=$(( $(date +%s) + TIMEOUT_SECONDS ))
  local current=0
  while (( $(date +%s) < deadline )); do
    current="$(rpc_height "$index" 2>/dev/null || printf '0')"
    if (( current >= target )); then
      return 0
    fi
    sleep 1
  done
  die "node$index timed out at height $current waiting for $target"
}

wait_for_node_synced() {
  local index="$1"
  local deadline=$(( $(date +%s) + TIMEOUT_SECONDS ))
  local status=""
  local height=0
  while (( $(date +%s) < deadline )); do
    if status="$(rpc_status "$index" 2>/dev/null)"; then
      height="$(jq -r '.result.sync_info.latest_block_height | tonumber' <<<"$status")"
      if [[ "$(jq -r '.result.sync_info.catching_up' <<<"$status")" == "false" ]]; then
        printf '%s' "$status"
        return 0
      fi
    fi
    sleep 1
  done
  die "node$index remained in catching_up state at height $height"
}

query_tx_to_file() {
  local tx_hash="$1"
  local output_file="$2"
  "$DORAD_BIN" query tx "$tx_hash" \
    --node "$RPC_URL" --output json >"$output_file" 2>"$output_file.stderr"
}

wait_for_tx() {
  local tx_hash="$1"
  local output_file="$2"
  local deadline=$(( $(date +%s) + TIMEOUT_SECONDS ))
  while (( $(date +%s) < deadline )); do
    if query_tx_to_file "$tx_hash" "$output_file"; then
      return 0
    fi
    sleep 1
  done
  die "timed out waiting for transaction $tx_hash"
}

response_code() {
  jq -r 'if has("code") then (.code|tostring) elif has("tx_response") then (.tx_response.code|tostring) else "0" end' "$1"
}

response_hash() {
  jq -r 'if has("txhash") then .txhash elif has("tx_response") then .tx_response.txhash else "" end' "$1"
}

response_height() {
  jq -r 'if has("height") then (.height|tonumber) elif has("tx_response") then (.tx_response.height|tonumber) else 0 end' "$1"
}

broadcast_ok() {
  local label="$1"
  shift
  local name
  name="$(artifact_name "$label")"
  local broadcast_file="$WORK_DIR/tx/${name}.broadcast.json"
  local stderr_file="$WORK_DIR/tx/${name}.broadcast.stderr"
  if ! "$@" >"$broadcast_file" 2>"$stderr_file"; then
    die "$label command failed: $(tail -20 "$stderr_file" | tr '\n' ' ')"
  fi
  jq -e . "$broadcast_file" >/dev/null 2>&1 || die "$label did not return JSON"
  local code
  code="$(response_code "$broadcast_file")"
  [[ "$code" == "0" ]] || die "$label CheckTx failed with code $code: $(jq -r '.raw_log // .tx_response.raw_log // ""' "$broadcast_file")"
  local tx_hash
  tx_hash="$(response_hash "$broadcast_file")"
  [[ -n "$tx_hash" && "$tx_hash" != "null" ]] || die "$label returned no transaction hash"
  local committed_file="$WORK_DIR/tx/${name}.committed.json"
  wait_for_tx "$tx_hash" "$committed_file"
  code="$(response_code "$committed_file")"
  [[ "$code" == "0" ]] || die "$label DeliverTx failed with code $code: $(jq -r '.raw_log // .tx_response.raw_log // ""' "$committed_file")"
  LAST_TX_HASH="$tx_hash"
  LAST_TX_HEIGHT="$(response_height "$committed_file")"
  local rpc_tx_file="$WORK_DIR/tx/${name}.rpc.json"
  local tx_bytes=0
  if curl --silent --show-error --fail --max-time 5 \
    "$RPC_URL/tx?hash=0x$tx_hash&prove=false" >"$rpc_tx_file" 2>"$rpc_tx_file.stderr"; then
    local encoded_tx
    encoded_tx="$(jq -r '.result.tx // empty' "$rpc_tx_file")"
    if [[ -n "$encoded_tx" ]]; then
      tx_bytes="$(printf '%s' "$encoded_tx" | openssl base64 -d -A 2>/dev/null | wc -c | tr -d ' ')"
    fi
  fi
  jq -cn \
    --arg scenario "$label" \
    --arg tx_hash "$tx_hash" \
    --argjson height "$LAST_TX_HEIGHT" \
    --argjson gas_wanted "$(jq -r '(.gas_wanted // .tx_response.gas_wanted // "0") | tonumber' "$committed_file")" \
    --argjson gas_used "$(jq -r '(.gas_used // .tx_response.gas_used // "0") | tonumber' "$committed_file")" \
    --argjson tx_bytes "$tx_bytes" \
    --argjson message_types "$(jq -c '[.tx.body.messages[]?["@type"]]' "$committed_file")" \
    '{label:$scenario,tx_hash:$tx_hash,height:$height,gas_wanted:$gas_wanted,gas_used:$gas_used,tx_bytes:$tx_bytes,message_types:$message_types}' \
    >>"$METRICS_JSONL"
  pass "$label" "height=$LAST_TX_HEIGHT tx=$tx_hash"
}

command_fails() {
  local label="$1"
  local expected="$2"
  shift 2
  local name
  name="$(artifact_name "$label")"
  local stdout_file="$WORK_DIR/tx/${name}.stdout"
  local stderr_file="$WORK_DIR/tx/${name}.stderr"
  local exit_code=0
  set +e
  "$@" >"$stdout_file" 2>"$stderr_file"
  exit_code=$?
  set -e
  local response=""
  local code=""
  if jq -e . "$stdout_file" >/dev/null 2>&1; then
    code="$(response_code "$stdout_file")"
    response="$(jq -r '.raw_log // .tx_response.raw_log // ""' "$stdout_file")"
  fi
  if (( exit_code == 0 )) && [[ -z "$code" || "$code" == "0" ]]; then
    die "$label unexpectedly succeeded"
  fi
  local combined
  combined="$(cat "$stdout_file" "$stderr_file"; printf '%s' "$response")"
  if [[ -n "$expected" ]] && ! printf '%s' "$combined" | grep -Fqi -- "$expected"; then
    die "$label failed for an unexpected reason; wanted '$expected', got: $(printf '%s' "$combined" | tail -c 1200)"
  fi
  pass "$label" "rejected as expected"
}

# Accept either a mempool rejection or a committed execution rejection. Stateful
# failures such as history compaction, registration cutoff, and nested authz cannot
# be decided safely by CheckTx alone.
broadcast_rejected() {
  local label="$1"
  local expected="$2"
  shift 2
  local name
  name="$(artifact_name "$label")"
  local broadcast_file="$WORK_DIR/tx/${name}.broadcast.json"
  local stderr_file="$WORK_DIR/tx/${name}.broadcast.stderr"
  local exit_code=0
  set +e
  "$@" >"$broadcast_file" 2>"$stderr_file"
  exit_code=$?
  set -e

  local rejection=""
  local code=""
  if jq -e . "$broadcast_file" >/dev/null 2>&1; then
    code="$(response_code "$broadcast_file")"
    rejection="$(jq -r '.raw_log // .tx_response.raw_log // ""' "$broadcast_file")"
    if [[ "$code" == "0" ]]; then
      local tx_hash
      tx_hash="$(response_hash "$broadcast_file")"
      [[ -n "$tx_hash" && "$tx_hash" != "null" ]] || die "$label returned no transaction hash"
      local committed_file="$WORK_DIR/tx/${name}.committed.json"
      wait_for_tx "$tx_hash" "$committed_file"
      code="$(response_code "$committed_file")"
      rejection="$(jq -r '.raw_log // .tx_response.raw_log // ""' "$committed_file")"
    fi
  fi
  if (( exit_code == 0 )) && [[ -z "$code" || "$code" == "0" ]]; then
    die "$label unexpectedly succeeded"
  fi
  local combined
  combined="$(cat "$broadcast_file" "$stderr_file" 2>/dev/null; printf '%s' "$rejection")"
  if [[ -n "$expected" ]] && ! printf '%s' "$combined" | grep -Fqi -- "$expected"; then
    die "$label failed for an unexpected reason; wanted '$expected', got: $(printf '%s' "$combined" | tail -c 1200)"
  fi
  pass "$label" "rejected as expected code=${code:-command}"
}

query_account_to_file() {
  local owner="$1"
  local output_file="$2"
  local rpc="${3:-$RPC_URL}"
  "$DORAD_BIN" query pqcauth account "$owner" \
    --node "$rpc" --output json >"$output_file" 2>"$output_file.stderr"
}

wait_for_policy() {
  local owner="$1"
  local signing_key="$2"
  local recovery_key="$3"
  local policy_version="$4"
  local label="$5"
  local output_file="$WORK_DIR/tx/$(artifact_name "$label").account.json"
  local deadline=$(( $(date +%s) + TIMEOUT_SECONDS ))
  while (( $(date +%s) < deadline )); do
    if query_account_to_file "$owner" "$output_file"; then
      if jq -e \
        --arg signing "$signing_key" \
        --arg recovery "$recovery_key" \
        --arg version "$policy_version" \
        '.policy.current_signing_key_id == $signing and .policy.recovery_key_id == $recovery and .policy.policy_version == $version' \
        "$output_file" >/dev/null; then
        pass "$label" "signing=$signing_key recovery=$recovery_key policy=$policy_version"
        return 0
      fi
    fi
    sleep 1
  done
  die "$label did not become effective; last response: $(cat "$output_file" 2>/dev/null || true)"
}

account_address() {
  jq -r '.address' "$WORK_DIR/secrets/account-$1.json"
}

key_private_file() {
  printf '%s/%s-%s.mldsa65' "$WORK_DIR/pqc" "$1" "$2"
}

key_json_file() {
  printf '%s/%s-%s-key.json' "$WORK_DIR/pqc" "$1" "$2"
}

proof_json_file() {
  printf '%s/%s-%s-%s-proof.json' "$WORK_DIR/pqc" "$1" "$2" "$3"
}

create_pqc_key() {
  local account="$1"
  local label="$2"
  local private_file
  private_file="$(key_private_file "$account" "$label")"
  "$DORAD_BIN" tx pqcauth keygen "$private_file" >"$(key_json_file "$account" "$label")"
  [[ "$(stat -c '%a' "$private_file" 2>/dev/null || stat -f '%Lp' "$private_file")" == "600" ]] || die "PQC private key permissions are not 0600: $private_file"
}

create_key_proof() {
  local account="$1"
  local label="$2"
  local key_id="$3"
  local role="$4"
  local purpose="$5"
  local policy_version="$6"
  local owner
  owner="$(account_address "$account")"
  "$DORAD_BIN" tx pqcauth create-key-proof \
    "$(key_private_file "$account" "$label")" "$owner" "$key_id" "$role" "$purpose" \
    --network-id-base64 "$NETWORK_ID" \
    --policy-version "$policy_version" \
    --chain-id "$CHAIN_ID" >"$(proof_json_file "$account" "$label" "$purpose")"
}

common_tx_flags() {
  local from="$1"
  printf '%s\0' \
    --from "$from" \
    --keyring-backend test \
    --home "$CLIENT_HOME" \
    --chain-id "$CHAIN_ID" \
    --node "$RPC_URL" \
    --gas "$TX_GAS" \
    --fees "$TX_FEE" \
    --broadcast-mode sync \
    --output json \
    --yes
}

register_pqc_account() {
  local account="$1"
  local owner
  owner="$(account_address "$account")"
  create_pqc_key "$account" signing1
  create_pqc_key "$account" recovery2
  create_key_proof "$account" signing1 1 signing register-signing 0
  create_key_proof "$account" recovery2 2 recovery register-recovery 0
  local signing_public recovery_public signing_proof recovery_proof
  signing_public="$(jq -r '.public_key_base64' "$(key_json_file "$account" signing1)")"
  recovery_public="$(jq -r '.public_key_base64' "$(key_json_file "$account" recovery2)")"
  signing_proof="$(jq -r '.proof_base64' "$(proof_json_file "$account" signing1 register-signing)")"
  recovery_proof="$(jq -r '.proof_base64' "$(proof_json_file "$account" recovery2 register-recovery)")"
  local flags=()
  while IFS= read -r -d '' item; do flags+=("$item"); done < <(common_tx_flags "$account")
  broadcast_ok "register $account signing and recovery keys" \
    "$DORAD_BIN" tx pqcauth register-key 1 "$signing_public" "$signing_proof" \
      --recovery-public-key-base64 "$recovery_public" \
      --recovery-proof-base64 "$recovery_proof" \
      --self-enforce=true \
      "${flags[@]}"
  wait_for_height $((LAST_TX_HEIGHT + 1))
  wait_for_policy "$owner" 1 2 1 "$account registration activates at H+1"
}

generate_unsigned_bank_send() {
  local from="$1"
  local recipient="$2"
  local amount="$3"
  local output_file="$4"
  "$DORAD_BIN" tx bank send "$(account_address "$from")" "$recipient" "$amount" \
    --from "$from" \
    --keyring-backend test \
    --home "$CLIENT_HOME" \
    --chain-id "$CHAIN_ID" \
    --node "$RPC_URL" \
    --gas "$TX_GAS" \
    --fees "$TX_FEE" \
    --generate-only \
    --output json >"$output_file"
}

prepare_and_sign_bank_bundle() {
  local account="$1"
  local key_label="$2"
  local recipient="$3"
  local amount="$4"
  local bundle_label="$5"
  local unsigned="$WORK_DIR/tx/${bundle_label}.unsigned.json"
  generate_unsigned_bank_send "$account" "$recipient" "$amount" "$unsigned"
  prepare_and_sign_unsigned_bundle "$account" "$key_label" "$unsigned" "$bundle_label"
}

prepare_and_sign_unsigned_bundle() {
  local account="$1"
  local key_label="$2"
  local unsigned="$3"
  local bundle_label="$4"
  local prepared="$WORK_DIR/tx/${bundle_label}.prepared.json"
  local signed="$WORK_DIR/tx/${bundle_label}.signed.json"
  "$DORAD_BIN" tx pqcauth prepare-bundle "$unsigned" "$prepared" \
    --from "$account" \
    --keyring-backend test \
    --home "$CLIENT_HOME" \
    --chain-id "$CHAIN_ID" \
    --node "$RPC_URL" \
    --output json --yes >"$WORK_DIR/tx/${bundle_label}.prepare-result.json"
  "$DORAD_BIN" tx pqcauth sign-bundle \
    "$prepared" "$(key_private_file "$account" "$key_label")" "$signed" \
    --home "$CLIENT_HOME" --yes >"$WORK_DIR/tx/${bundle_label}.sign-result.json"
}

broadcast_signed_bundle() {
  local label="$1"
  local account="$2"
  local signed_file="$3"
  broadcast_ok "$label" \
    "$DORAD_BIN" tx pqcauth broadcast-bundle "$signed_file" \
      --from "$account" \
      --keyring-backend test \
      --home "$CLIENT_HOME" \
      --chain-id "$CHAIN_ID" \
      --node "$RPC_URL" \
      --broadcast-mode sync \
      --output json --yes
}

forge_and_reject() {
  local variant="$1"
  local expected="$2"
  local bundle="$3"
  local output="$WORK_DIR/tx/adversarial-${variant}.base64"
  "$PQCTX_BIN" \
    --bundle "$bundle" \
    --variant "$variant" \
    --from alice \
    --keyring-home "$CLIENT_HOME" \
    --output "$output"
  local response="$WORK_DIR/tx/adversarial-${variant}.response.json"
  local payload="$WORK_DIR/tx/adversarial-${variant}.request.json"
  jq -cn --arg tx "$(tr -d '\n' <"$output")" \
    '{jsonrpc:"2.0",id:1,method:"broadcast_tx_sync",params:{tx:$tx}}' >"$payload"
  curl --silent --show-error --fail --max-time 15 \
    -H 'Content-Type: application/json' \
    --data-binary "@$payload" "$RPC_URL" >"$response"
  local code
  code="$(jq -r '.result.code // 0' "$response")"
  [[ "$code" != "0" ]] || die "Ante unexpectedly accepted adversarial $variant extension"
  local rejection
  rejection="$(jq -r '.result.log // .error.message // ""' "$response")"
  if [[ -n "$expected" ]] && ! printf '%s' "$rejection" | grep -Fqi -- "$expected"; then
    die "adversarial $variant failed unexpectedly; wanted '$expected', got '$rejection'"
  fi
  if [[ "$variant" == "valid" ]]; then
    pass "Ante fail-closes a cryptographically valid extension during emergency pause" "code=$code"
  else
    pass "Ante rejects adversarial $variant extension" "code=$code"
  fi
}

wait_for_param_state() {
  local mode="$1"
  local emergency="$2"
  local label="$3"
  local output="$WORK_DIR/tx/$(artifact_name "$label").params.json"
  local deadline=$(( $(date +%s) + TIMEOUT_SECONDS ))
  while (( $(date +%s) < deadline )); do
    if "$DORAD_BIN" query pqcauth params --node "$RPC_URL" --output json >"$output" 2>"$output.stderr"; then
      if jq -e --arg mode "$mode" --arg emergency "$emergency" \
        '.effective_enforcement_mode == $mode and .effective_emergency_mode == $emergency' \
        "$output" >/dev/null; then
        pass "$label" "mode=$mode emergency=$emergency height=$(rpc_height 0)"
        return 0
      fi
    fi
    sleep 1
  done
  die "$label did not activate: $(cat "$output" 2>/dev/null || true)"
}

submit_params_update() {
  local label="$1"
  local mode="$2"
  local emergency="$3"
  local cutoff="$4"
  local name
  name="$(artifact_name "$label")"
  local current="$WORK_DIR/tx/${name}.current-params.json"
  local desired="$WORK_DIR/tx/${name}.desired-params.json"
  local proposal="$WORK_DIR/tx/${name}.proposal.json"
  "$DORAD_BIN" query pqcauth params --node "$RPC_URL" --output json >"$current"
  jq --arg mode "$mode" --arg emergency "$emergency" --arg cutoff "$cutoff" \
    '.params
     | .enforcement_mode = $mode
     | .emergency_mode = $emergency
     | .registration_cutoff_height = $cutoff
     | .emergency_expires_height = "0"
     | .pending = null
     | .pending_activation_height = "0"' \
    "$current" >"$desired"

  local authority_json="$WORK_DIR/tx/${name}.gov-authority.json"
  "$DORAD_BIN" query auth module-account gov --node "$RPC_URL" --output json >"$authority_json"
  local authority
  authority="$(jq -r '.account.base_account.address // .account.baseAccount.address // .account.value.address // empty' "$authority_json")"
  [[ -n "$authority" ]] || die "cannot resolve governance module authority"
  jq -n \
    --arg authority "$authority" \
    --arg title "$label" \
    --slurpfile params "$desired" \
    '{messages:[{"@type":"/doravota.pqcauth.v1.MsgUpdateParams",authority:$authority,params:$params[0]}],metadata:"",deposit:"1000000peaka",title:$title,summary:$title}' \
    >"$proposal"

  local bob_flags=()
  while IFS= read -r -d '' item; do bob_flags+=("$item"); done < <(common_tx_flags bob)
  broadcast_ok "submit governance proposal: $label" \
    "$DORAD_BIN" tx gov submit-proposal "$proposal" "${bob_flags[@]}"

  local proposals="$WORK_DIR/tx/${name}.proposals.json"
  "$DORAD_BIN" query gov proposals --node "$RPC_URL" --output json >"$proposals"
  local proposal_id
  proposal_id="$(jq -r '[.proposals[].id | tonumber] | max // empty' "$proposals")"
  [[ -n "$proposal_id" ]] || die "cannot resolve proposal id for $label"

  local index
  for ((index = 0; index < NODES; index++)); do
    broadcast_ok "validator$index votes yes on proposal $proposal_id" \
      "$DORAD_BIN" tx gov vote "$proposal_id" yes \
        --from "validator-$index" --keyring-backend test --home "$(node_home "$index")" \
        --chain-id "$CHAIN_ID" --node "$RPC_URL" \
        --gas "$TX_GAS" --fees "$TX_FEE" --broadcast-mode sync --output json --yes
  done

  local final="$WORK_DIR/tx/${name}.proposal-final.json"
  local deadline=$(( $(date +%s) + TIMEOUT_SECONDS ))
  local status=""
  while (( $(date +%s) < deadline )); do
    if "$DORAD_BIN" query gov proposal "$proposal_id" --node "$RPC_URL" --output json >"$final" 2>"$final.stderr"; then
      status="$(jq -r '.proposal.status // .status // empty' "$final")"
      case "$status" in
        PROPOSAL_STATUS_PASSED) break ;;
        PROPOSAL_STATUS_REJECTED|PROPOSAL_STATUS_FAILED)
          die "governance proposal $proposal_id ended as $status"
          ;;
      esac
    fi
    sleep 1
  done
  [[ "$status" == "PROPOSAL_STATUS_PASSED" ]] || die "governance proposal $proposal_id did not pass before timeout"
  pass "governance executes proposal $proposal_id" "$label"
  wait_for_param_state "$mode" "$emergency" "$label activates at its consensus-scheduled height"
}

initialize_network() {
  log "initializing $NODES-validator network in $WORK_DIR"
  local index
  for ((index = 0; index < NODES; index++)); do
    local home
    home="$(node_home "$index")"
    "$DORAD_BIN" init "pqcauth-validator-$index" \
      --chain-id "$CHAIN_ID" --home "$home" \
      >"$WORK_DIR/logs/node${index}-init.stdout" \
      2>"$WORK_DIR/logs/node${index}-init.stderr"
    "$DORAD_BIN" keys add "validator-$index" \
      --keyring-backend test --home "$home" --output json \
      >"$WORK_DIR/secrets/validator-$index.json"
    sed -i.e2e 's/^timeout_propose = .*/timeout_propose = "1s"/' "$home/config/config.toml"
    sed -i.e2e 's/^timeout_commit = .*/timeout_commit = "1s"/' "$home/config/config.toml"
    # Every validator is intentionally bound to loopback in this single-host
    # test. CometBFT's production-safe defaults reject non-routable peers and
    # duplicate IPs, so relax them only inside the disposable E2E homes.
    sed -i.e2e 's/^addr_book_strict = .*/addr_book_strict = false/' "$home/config/config.toml"
    sed -i.e2e 's/^allow_duplicate_ip = .*/allow_duplicate_ip = true/' "$home/config/config.toml"
    # Multiple processes cannot share the default localhost:6060 profiler.
    sed -i.e2e 's/^pprof_laddr = .*/pprof_laddr = ""/' "$home/config/config.toml"
  done

  local classic_accounts=(alice bob carol dave eve grantee quota receiver feeowner feepayer)
  local account
  for account in "${classic_accounts[@]}"; do
    "$DORAD_BIN" keys add "$account" \
      --keyring-backend test --home "$CLIENT_HOME" --output json \
      >"$WORK_DIR/secrets/account-$account.json"
  done
  "$DORAD_BIN" keys add native --key-type ml_dsa_65 \
    --keyring-backend test --home "$CLIENT_HOME" --output json \
    >"$WORK_DIR/secrets/account-native.json"
  "$DORAD_BIN" keys show native --pubkey \
    --keyring-backend test --home "$CLIENT_HOME" \
    >"$REPORT_DIR/native-mldsa-pubkey.json"
  jq -e '.. | strings | ascii_downcase | select(contains("mldsa65") or contains("ml_dsa_65"))' \
    "$REPORT_DIR/native-mldsa-pubkey.json" >/dev/null \
    || die "native account does not use an ML-DSA-65 public key"

  local coordinator
  coordinator="$(node_home 0)"
  local genesis="$coordinator/config/genesis.json"
  local genesis_tmp="$coordinator/config/genesis.e2e.json"
  jq '
    walk(if type == "string" and . == "stake" then "peaka" else . end)
    | .app_state.gov.params.min_deposit = [{"denom":"peaka","amount":"1000000"}]
    | .app_state.gov.params.max_deposit_period = "10s"
    | .app_state.gov.params.voting_period = "10s"
    | .app_state.gov.params.expedited_voting_period = "5s"
    | .app_state.pqcauth.params.governance_safety_delay_blocks = "4"
    | .app_state.pqcauth.params.max_emergency_duration_blocks = "20"
    | .app_state.pqcauth.params.recovery_delay_blocks = "12"
    | .app_state.pqcauth.params.emergency_expires_height = "0"
  ' "$genesis" >"$genesis_tmp"
  mv "$genesis_tmp" "$genesis"

  for ((index = 0; index < NODES; index++)); do
    local validator_address
    validator_address="$(jq -r '.address' "$WORK_DIR/secrets/validator-$index.json")"
    "$DORAD_BIN" add-genesis-account "$validator_address" "$GENESIS_BALANCE" --home "$coordinator"
  done
  for account in "${classic_accounts[@]}" native; do
    "$DORAD_BIN" add-genesis-account "$(account_address "$account")" "$GENESIS_BALANCE" --home "$coordinator"
  done

  for ((index = 1; index < NODES; index++)); do
    cp "$genesis" "$(node_home "$index")/config/genesis.json"
  done
  for ((index = 0; index < NODES; index++)); do
    "$DORAD_BIN" gentx "validator-$index" "$STAKE_AMOUNT" \
      --chain-id "$CHAIN_ID" \
      --keyring-backend test \
      --home "$(node_home "$index")" \
      --moniker "pqcauth-validator-$index" \
      >"$WORK_DIR/logs/node${index}-gentx.stdout" \
      2>"$WORK_DIR/logs/node${index}-gentx.stderr"
    if (( index > 0 )); then
      find "$(node_home "$index")/config/gentx" -type f -name '*.json' \
        -exec cp '{}' "$coordinator/config/gentx/" ';'
    fi
  done
  "$DORAD_BIN" collect-gentxs --home "$coordinator" \
    >"$WORK_DIR/logs/collect-gentxs.stdout" \
    2>"$WORK_DIR/logs/collect-gentxs.stderr"
  # collect-gentxs rewrites the GenesisDoc using legacy numeric encodings.
  # Normalize the final document only after it has inserted every gentx so the
  # CometBFT v0.40 JSON decoder sees strings for all 64-bit consensus fields.
  jq '
    .initial_height = ((.initial_height // 1) | tostring)
    | .consensus_params = {
        block:{max_bytes:"22020096",max_gas:"100000000"},
        evidence:{max_age_num_blocks:"100000",max_age_duration:"172800000000000",max_bytes:"1048576"},
        validator:{pub_key_types:["ed25519","ml_dsa_65"]},
        version:{app:"0"},
        abci:{vote_extensions_enable_height:"0"},
        authority:{authority:""}
      }
  ' "$genesis" >"$genesis_tmp"
  mv "$genesis_tmp" "$genesis"
  "$DORAD_BIN" validate-genesis --home "$coordinator" \
    >"$REPORT_DIR/validate-genesis.txt" \
    2>"$REPORT_DIR/validate-genesis.stderr"
  for ((index = 1; index < NODES; index++)); do
    cp "$genesis" "$(node_home "$index")/config/genesis.json"
  done

  for ((index = 0; index < NODES; index++)); do
    "$DORAD_BIN" tendermint show-node-id --home "$(node_home "$index")" \
      >"$WORK_DIR/nodes/node${index}.id"
  done
  pass "initialize and validate genesis" "validators=$NODES"
}

persistent_peers_for() {
  local own_index="$1"
  local peers=""
  local index
  for ((index = 0; index < NODES; index++)); do
    if (( index == own_index )); then
      continue
    fi
    local peer
    peer="$(cat "$WORK_DIR/nodes/node${index}.id")@127.0.0.1:$(node_p2p_port "$index")"
    if [[ -n "$peers" ]]; then peers+=","; fi
    peers+="$peer"
  done
  printf '%s' "$peers"
}

start_one_node() {
  local index="$1"
  local count="${NODE_START_COUNTS[$index]:-0}"
  count=$((count + 1))
  NODE_START_COUNTS[$index]="$count"
  local log_file="$WORK_DIR/logs/node${index}-start${count}.log"
  "$DORAD_BIN" start \
    --home "$(node_home "$index")" \
    --minimum-gas-prices "$MIN_GAS_PRICE" \
    --rpc.laddr "tcp://127.0.0.1:$(node_rpc_port "$index")" \
    --p2p.laddr "tcp://127.0.0.1:$(node_p2p_port "$index")" \
    --address "tcp://127.0.0.1:$(node_abci_port "$index")" \
    --grpc.address "127.0.0.1:$(node_grpc_port "$index")" \
    --grpc-web.enable=false \
    --api.enable=false \
    --p2p.persistent_peers "$(persistent_peers_for "$index")" \
    --p2p.pex=false \
    --pruning nothing \
    >"$log_file" 2>&1 &
  NODE_PIDS[$index]=$!
  printf '%s %s\n' "$index" "${NODE_PIDS[$index]}" >>"$REPORT_DIR/node-pids.txt"
}

start_network() {
  local index
  for ((index = 0; index < NODES; index++)); do
    local port
    for port in "$(node_p2p_port "$index")" "$(node_rpc_port "$index")" \
      "$(node_abci_port "$index")" "$(node_grpc_port "$index")"; do
      port_open "$port" && die "required test port is already in use: $port"
    done
  done
  for ((index = 0; index < NODES; index++)); do
    start_one_node "$index"
  done
  for ((index = 0; index < NODES; index++)); do
    wait_for_rpc "$index"
  done
  wait_for_height 2
  local validators_file="$REPORT_DIR/bonded-validators.json"
  "$DORAD_BIN" query staking validators \
    --node "$RPC_URL" --output json >"$validators_file"
  local validator_count
  validator_count="$(jq '[.validators[] | select(.status == "BOND_STATUS_BONDED")] | length' "$validators_file")"
  [[ "$validator_count" == "$NODES" ]] || die "expected $NODES bonded validators, got $validator_count"
  pass "start real CometBFT network" "bonded_validators=$validator_count"
}

assert_same_app_hash() {
  local label="$1"
  local target
  target="$(rpc_height 0)"
  local index
  for ((index = 0; index < NODES; index++)); do
    wait_for_height "$target" "$index"
  done
  local expected=""
  for ((index = 0; index < NODES; index++)); do
    local current
    current="$(curl --silent --show-error --fail --max-time 5 "$(node_rpc_url "$index")/block?height=$target" | jq -r '.result.block.header.app_hash')"
    if [[ -z "$expected" ]]; then expected="$current"; fi
    [[ "$current" == "$expected" ]] || die "$label app hash mismatch at height $target on node$index"
  done
  FINAL_HEIGHT="$target"
  FINAL_APP_HASH="$expected"
  pass "$label" "height=$target app_hash=$expected"
}

prepare_protected_authz_grant() {
  local granter="$1"
  local grantee="$2"
  local message_type="$3"
  local label="$4"
  local unsigned="$WORK_DIR/tx/${label}.unsigned.json"
  "$DORAD_BIN" tx authz grant "$(account_address "$grantee")" generic \
    --msg-type "$message_type" \
    --from "$granter" --keyring-backend test --home "$CLIENT_HOME" \
    --chain-id "$CHAIN_ID" --node "$RPC_URL" --gas "$TX_GAS" --fees "$TX_FEE" \
    --note "$label" --generate-only --output json >"$unsigned"
  prepare_and_sign_unsigned_bundle "$granter" signing1 "$unsigned" "$label"
}

run_authz_security_scenarios() {
  local bob_flags=()
  while IFS= read -r -d '' item; do bob_flags+=("$item"); done < <(common_tx_flags bob)
  broadcast_ok "unprotected account creates a pre-existing authz grant" \
    "$DORAD_BIN" tx authz grant "$(account_address grantee)" generic \
      --msg-type /cosmos.bank.v1beta1.MsgSend "${bob_flags[@]}"

  create_pqc_key bob signing1
  create_pqc_key bob recovery2
  create_key_proof bob signing1 1 signing register-signing 0
  create_key_proof bob recovery2 2 recovery register-recovery 0
  broadcast_rejected "pre-existing authz grant blocks pqcauth registration" \
    "must revoke all existing authz grants" \
    "$DORAD_BIN" tx pqcauth register-key 1 \
      "$(jq -r '.public_key_base64' "$(key_json_file bob signing1)")" \
      "$(jq -r '.proof_base64' "$(proof_json_file bob signing1 register-signing)")" \
      --recovery-public-key-base64 "$(jq -r '.public_key_base64' "$(key_json_file bob recovery2)")" \
      --recovery-proof-base64 "$(jq -r '.proof_base64' "$(proof_json_file bob recovery2 register-recovery)")" \
      --self-enforce=true "${bob_flags[@]}"

  prepare_protected_authz_grant carol grantee /cosmos.bank.v1beta1.MsgSend carol-unsafe-grantee
  broadcast_rejected "protected granter rejects a non-PQC grantee" \
    "cannot delegate to non-PQC grantee" \
    "$DORAD_BIN" tx pqcauth broadcast-bundle "$WORK_DIR/tx/carol-unsafe-grantee.signed.json" \
      --from carol --keyring-backend test --home "$CLIENT_HOME" \
      --chain-id "$CHAIN_ID" --node "$RPC_URL" --broadcast-mode sync --output json --yes

  register_pqc_account grantee
  prepare_protected_authz_grant carol grantee /cosmos.bank.v1beta1.MsgSend carol-safe-grantee
  broadcast_signed_bundle "protected granter delegates to a PQC-enforced grantee" carol \
    "$WORK_DIR/tx/carol-safe-grantee.signed.json"

  local inner="$WORK_DIR/tx/authz-inner-protected-bank-send.json"
  jq -n \
    --arg from "$(account_address carol)" \
    --arg to "$(account_address receiver)" \
    --arg amount "301" \
    '{body:{messages:[{"@type":"/cosmos.bank.v1beta1.MsgSend",from_address:$from,to_address:$to,amount:[{denom:"peaka",amount:$amount}]}],memo:"",timeout_height:"0",extension_options:[],non_critical_extension_options:[]},auth_info:{signer_infos:[],fee:{amount:[],gas_limit:"0",payer:"",granter:""}},signatures:[]}' \
    >"$inner"
  local exec_unsigned="$WORK_DIR/tx/grantee-protected-exec.unsigned.json"
  "$DORAD_BIN" tx authz exec "$inner" \
    --from grantee --keyring-backend test --home "$CLIENT_HOME" \
    --chain-id "$CHAIN_ID" --node "$RPC_URL" --gas "$TX_GAS" --fees "$TX_FEE" \
    --generate-only --output json >"$exec_unsigned"
  prepare_and_sign_unsigned_bundle grantee signing1 "$exec_unsigned" grantee-protected-exec
  broadcast_signed_bundle "PQC-enforced grantee executes for a protected granter" grantee \
    "$WORK_DIR/tx/grantee-protected-exec.signed.json"

  local grantee_flags=()
  while IFS= read -r -d '' item; do grantee_flags+=("$item"); done < <(common_tx_flags grantee)
  broadcast_ok "grantee disables its own PQC enforcement" \
    "$DORAD_BIN" tx pqcauth set-protection false \
      --pqc-private-key-file "$(key_private_file grantee signing1)" \
      "${grantee_flags[@]}"
  wait_for_height $((LAST_TX_HEIGHT + 1))
  wait_for_policy "$(account_address grantee)" 1 2 2 "grantee protection disable activates at H+1"

  local downgraded_inner="$WORK_DIR/tx/authz-inner-after-grantee-downgrade.json"
  jq --arg amount "302" \
    '.body.messages[0].amount[0].amount = $amount' "$inner" >"$downgraded_inner"
  broadcast_rejected "old grant stops after the grantee drops PQC enforcement" \
    "cannot be executed by non-PQC grantee" \
    "$DORAD_BIN" tx authz exec "$downgraded_inner" "${grantee_flags[@]}"
}

run_feegrant_security_scenarios() {
  local feeowner_flags=()
  local feepayer_flags=()
  while IFS= read -r -d '' item; do feeowner_flags+=("$item"); done < <(common_tx_flags feeowner)
  while IFS= read -r -d '' item; do feepayer_flags+=("$item"); done < <(common_tx_flags feepayer)

  broadcast_ok "unprotected account creates a pre-existing fee grant" \
    "$DORAD_BIN" tx feegrant grant feeowner "$(account_address feepayer)" \
      --spend-limit "1000000${DENOM}" "${feeowner_flags[@]}"

  register_pqc_account feeowner

  broadcast_rejected "legacy fee grant cannot be used by a non-PQC payer" \
    "fee granter" \
    "$DORAD_BIN" tx bank send "$(account_address feepayer)" "$(account_address receiver)" \
      "401${DENOM}" --fee-granter "$(account_address feeowner)" "${feepayer_flags[@]}"

  local unsafe_grant_unsigned="$WORK_DIR/tx/feeowner-unsafe-feegrant.unsigned.json"
  "$DORAD_BIN" tx feegrant grant feeowner "$(account_address receiver)" \
    --spend-limit "1000000${DENOM}" \
    --keyring-backend test --home "$CLIENT_HOME" \
    --chain-id "$CHAIN_ID" --node "$RPC_URL" --gas "$TX_GAS" --fees "$TX_FEE" \
    --generate-only --output json >"$unsafe_grant_unsigned"
  prepare_and_sign_unsigned_bundle feeowner signing1 "$unsafe_grant_unsigned" feeowner-unsafe-feegrant
  broadcast_rejected "protected fee granter rejects a non-PQC grantee" \
    "cannot delegate to non-PQC grantee" \
    "$DORAD_BIN" tx pqcauth broadcast-bundle "$WORK_DIR/tx/feeowner-unsafe-feegrant.signed.json" \
      --from feeowner --keyring-backend test --home "$CLIENT_HOME" \
      --chain-id "$CHAIN_ID" --node "$RPC_URL" --broadcast-mode sync --output json --yes

  local native_grant_unsigned="$WORK_DIR/tx/feeowner-native-feegrant.unsigned.json"
  "$DORAD_BIN" tx feegrant grant feeowner "$(account_address native)" \
    --spend-limit "1000000${DENOM}" \
    --keyring-backend test --home "$CLIENT_HOME" \
    --chain-id "$CHAIN_ID" --node "$RPC_URL" --gas "$TX_GAS" --fees "$TX_FEE" \
    --generate-only --output json >"$native_grant_unsigned"
  prepare_and_sign_unsigned_bundle feeowner signing1 "$native_grant_unsigned" feeowner-native-feegrant
  broadcast_signed_bundle "protected fee granter delegates to native ML-DSA account" feeowner \
    "$WORK_DIR/tx/feeowner-native-feegrant.signed.json"

  register_pqc_account feepayer
  local safe_use_unsigned="$WORK_DIR/tx/feepayer-safe-feegrant-use.unsigned.json"
  "$DORAD_BIN" tx bank send "$(account_address feepayer)" "$(account_address receiver)" \
    "402${DENOM}" \
    --from feepayer --keyring-backend test --home "$CLIENT_HOME" \
    --chain-id "$CHAIN_ID" --node "$RPC_URL" --gas "$TX_GAS" --fees "$TX_FEE" \
    --fee-granter "$(account_address feeowner)" \
    --generate-only --output json >"$safe_use_unsigned"
  prepare_and_sign_unsigned_bundle feepayer signing1 "$safe_use_unsigned" feepayer-safe-feegrant-use
  broadcast_signed_bundle "PQC-enforced payer uses protected account fee grant" feepayer \
    "$WORK_DIR/tx/feepayer-safe-feegrant-use.signed.json"
}

run_nested_authz_scenario() {
  local grant_unsigned="$WORK_DIR/tx/carol-authz-grant.unsigned.json"
  "$DORAD_BIN" tx authz grant "$(account_address native)" generic \
    --msg-type /doravota.pqcauth.v1.MsgSetProtection \
    --from carol --keyring-backend test --home "$CLIENT_HOME" \
    --chain-id "$CHAIN_ID" --node "$RPC_URL" --gas "$TX_GAS" --fees "$TX_FEE" \
    --generate-only --output json >"$grant_unsigned"
  "$DORAD_BIN" tx pqcauth prepare-bundle "$grant_unsigned" "$WORK_DIR/tx/carol-authz-grant.prepared.json" \
    --from carol --keyring-backend test --home "$CLIENT_HOME" \
    --chain-id "$CHAIN_ID" --node "$RPC_URL" --output json --yes \
    >"$WORK_DIR/tx/carol-authz-grant.prepare-result.json"
  "$DORAD_BIN" tx pqcauth sign-bundle \
    "$WORK_DIR/tx/carol-authz-grant.prepared.json" \
    "$(key_private_file carol signing1)" \
    "$WORK_DIR/tx/carol-authz-grant.signed.json" \
    --home "$CLIENT_HOME" --yes >"$WORK_DIR/tx/carol-authz-grant.sign-result.json"
  broadcast_signed_bundle "grant authz for pqcauth lifecycle message" carol \
    "$WORK_DIR/tx/carol-authz-grant.signed.json"

  local inner="$WORK_DIR/tx/authz-inner-pqcauth-lifecycle.json"
  jq -n --arg owner "$(account_address carol)" \
    '{body:{messages:[{"@type":"/doravota.pqcauth.v1.MsgSetProtection",owner:$owner,enabled:true}],memo:"",timeout_height:"0",extension_options:[],non_critical_extension_options:[]},auth_info:{signer_infos:[],fee:{amount:[],gas_limit:"0",payer:"",granter:""}},signatures:[]}' \
    >"$inner"
  local native_flags=()
  while IFS= read -r -d '' item; do native_flags+=("$item"); done < <(common_tx_flags native)
  broadcast_rejected "authz cannot nest a pqcauth lifecycle message" "executed directly" \
    "$DORAD_BIN" tx authz exec "$inner" "${native_flags[@]}"

  local account="$WORK_DIR/tx/carol-after-authz-rejection.account.json"
  query_account_to_file "$(account_address carol)" "$account"
  [[ "$(jq -r '.policy.self_enforced' "$account")" == "true" ]] || die "nested authz changed Carol's protection policy"
  pass "nested authz rejection leaves pqcauth state unchanged"
}

run_history_compaction_scenario() {
  register_pqc_account quota
  local quota_flags=()
  while IFS= read -r -d '' item; do quota_flags+=("$item"); done < <(common_tx_flags quota)
  local current_key_id=1
  local current_label=signing1
  local policy_version=1
  local next
  for ((next = 3; next <= 22; next++)); do
    create_pqc_key quota "signing$next"
    create_key_proof quota "signing$next" "$next" signing rotate-signing "$policy_version"
    local public proof
    public="$(jq -r '.public_key_base64' "$(key_json_file quota "signing$next")")"
    proof="$(jq -r '.proof_base64' "$(proof_json_file quota "signing$next" rotate-signing)")"
    broadcast_ok "history account rotates signing key to id $next" \
      "$DORAD_BIN" tx pqcauth rotate-key "$next" "$public" "$proof" \
        --pqc-private-key-file "$(key_private_file quota "$current_label")" \
        "${quota_flags[@]}"
    wait_for_height $((LAST_TX_HEIGHT + 1))
    policy_version=$((policy_version + 1))
    wait_for_policy "$(account_address quota)" "$next" 2 "$policy_version" "signing key $next activates at H+1"
    current_key_id="$next"
    current_label="signing$next"
  done

  [[ "$current_key_id" == "22" ]] || die "history rotation loop ended on an unexpected key id"
  local keys="$REPORT_DIR/history-account-keys.json"
  "$DORAD_BIN" query pqcauth keys "$(account_address quota)" \
    --node "$RPC_URL" --output json >"$keys"
  [[ "$(jq '.keys | length' "$keys")" == "18" ]] || die "history account did not retain 16 terminal signing records plus two active keys"
  jq -e '.keys | any(.key_id == "22" and .role == "KEY_ROLE_SIGNING")' "$keys" >/dev/null || die "current signing key was removed by history compaction"
  jq -e '.keys | any(.key_id == "2" and .role == "KEY_ROLE_RECOVERY")' "$keys" >/dev/null || die "current recovery key was removed by signing history compaction"

  local account="$REPORT_DIR/history-account-policy.json"
  query_account_to_file "$(account_address quota)" "$account"
  [[ "$(jq -r '[.key_histories[] | select(.role == "KEY_ROLE_SIGNING")][0].compacted_count' "$account")" == "4" ]] || die "unexpected compacted signing-key count"
  [[ "$(jq -r '[.key_histories[] | select(.role == "KEY_ROLE_RECOVERY")] | length' "$account")" == "0" ]] || die "signing churn unexpectedly compacted recovery history"
  pass "unbounded key IDs compact old signing history without deleting active signing or recovery keys"
}

run_governance_scenarios() {
  local optional="ENFORCEMENT_MODE_OPTIONAL"
  local normal="EMERGENCY_MODE_NORMAL"
  local registered="ENFORCEMENT_MODE_REQUIRED_FOR_REGISTERED"
  local disabled="ENFORCEMENT_MODE_DISABLED"
  local required="ENFORCEMENT_MODE_REQUIRED"
  local pause_keys="EMERGENCY_MODE_PAUSE_NEW_KEYS"
  local pause_pqc="EMERGENCY_MODE_PAUSE_PQC_TRANSACTIONS"

  local carol_flags=()
  while IFS= read -r -d '' item; do carol_flags+=("$item"); done < <(common_tx_flags carol)
  local alice_flags=()
  while IFS= read -r -d '' item; do alice_flags+=("$item"); done < <(common_tx_flags alice)
  local bob_flags=()
  while IFS= read -r -d '' item; do bob_flags+=("$item"); done < <(common_tx_flags bob)

  submit_params_update "require PQC for every registered account" "$registered" "$normal" 0
  command_fails "registered account remains protected in registered-required mode" "PQC authorization" \
    "$DORAD_BIN" tx bank send "$(account_address carol)" "$(account_address receiver)" "201${DENOM}" \
      "${carol_flags[@]}"
  prepare_and_sign_bank_bundle carol signing1 "$(account_address receiver)" "202${DENOM}" carol-required-registered
  broadcast_signed_bundle "registered account succeeds with hybrid authorization" carol "$WORK_DIR/tx/carol-required-registered.signed.json"

  submit_params_update "restore optional enforcement" "$optional" "$normal" 0
  command_fails "registered self-enforced account stays protected in optional mode" "PQC authorization" \
    "$DORAD_BIN" tx bank send "$(account_address carol)" "$(account_address receiver)" "203${DENOM}" \
      "${carol_flags[@]}"

  submit_params_update "disable governance-wide enforcement only" "$disabled" "$normal" 0
  command_fails "disabled mode does not override account self-enforcement" "PQC authorization" \
    "$DORAD_BIN" tx bank send "$(account_address alice)" "$(account_address receiver)" "204${DENOM}" \
      "${alice_flags[@]}"
  command_fails "disabled mode cannot override another account's self-enforcement" "PQC authorization" \
    "$DORAD_BIN" tx bank send "$(account_address carol)" "$(account_address receiver)" "205${DENOM}" \
      "${carol_flags[@]}"
  submit_params_update "restore optional mode after disabled test" "$optional" "$normal" 0

  create_pqc_key alice signing5
  create_key_proof alice signing5 5 signing rotate-signing 5
  local signing5_public signing5_proof
  signing5_public="$(jq -r '.public_key_base64' "$(key_json_file alice signing5)")"
  signing5_proof="$(jq -r '.proof_base64' "$(proof_json_file alice signing5 rotate-signing)")"
  submit_params_update "pause creation and rotation of PQC keys" "$optional" "$pause_keys" 0
  prepare_and_sign_bank_bundle dave signing4 "$(account_address receiver)" "206${DENOM}" dave-existing-during-key-pause
  broadcast_signed_bundle "existing PQC authorization works while new keys are paused" dave "$WORK_DIR/tx/dave-existing-during-key-pause.signed.json"
  broadcast_rejected "key rotation is blocked by emergency pause" "paused" \
    "$DORAD_BIN" tx pqcauth rotate-key 5 "$signing5_public" "$signing5_proof" \
      --pqc-private-key-file "$(key_private_file alice signing3)" \
      "${alice_flags[@]}"
  submit_params_update "resume normal PQC key lifecycle" "$optional" "$normal" 0

  prepare_and_sign_bank_bundle alice signing3 "$(account_address receiver)" "207${DENOM}" alice-before-pqc-pause
  submit_params_update "pause every PQC-authorized transaction" "$optional" "$pause_pqc" 0
  forge_and_reject valid "paused" "$WORK_DIR/tx/alice-before-pqc-pause.signed.json"
  broadcast_rejected "valid hybrid transaction is fail-closed during PQC pause" "paused" \
    "$DORAD_BIN" tx pqcauth broadcast-bundle "$WORK_DIR/tx/alice-before-pqc-pause.signed.json" \
      --from alice --keyring-backend test --home "$CLIENT_HOME" \
      --chain-id "$CHAIN_ID" --node "$RPC_URL" --broadcast-mode sync --output json --yes
  broadcast_ok "unregistered classic transaction remains available during PQC pause" \
    "$DORAD_BIN" tx bank send "$(account_address bob)" "$(account_address receiver)" "208${DENOM}" \
      "${bob_flags[@]}"

  create_pqc_key dave signing5
  create_key_proof dave signing5 5 signing recover-signing 2
  local dave_signing5_public dave_signing5_proof
  dave_signing5_public="$(jq -r '.public_key_base64' "$(key_json_file dave signing5)")"
  dave_signing5_proof="$(jq -r '.proof_base64' "$(proof_json_file dave signing5 recover-signing)")"
  local paused_recovery_prepared="$WORK_DIR/tx/dave-paused-recovery.prepared.json"
  local paused_recovery_signed="$WORK_DIR/tx/dave-paused-recovery.signed.json"
  "$DORAD_BIN" tx pqcauth recover-key 2 5 "$dave_signing5_public" "$dave_signing5_proof" \
    --recovery-sign-bundle-output "$paused_recovery_prepared" \
    --from dave --keyring-backend test --home "$CLIENT_HOME" \
    --chain-id "$CHAIN_ID" --node "$RPC_URL" --gas "$TX_GAS" --fees "$TX_FEE" \
    --output json --yes \
    >"$WORK_DIR/tx/dave-paused-recovery.prepare-result.json"
  "$DORAD_BIN" tx pqcauth sign-recovery-bundle \
    "$paused_recovery_prepared" "$(key_private_file dave recovery2)" "$paused_recovery_signed" \
    --home "$CLIENT_HOME" --yes >"$WORK_DIR/tx/dave-paused-recovery.sign-result.json"
  broadcast_ok "recovery-only transaction remains available during full PQC pause" \
    "$DORAD_BIN" tx pqcauth broadcast-recovery-bundle "$paused_recovery_signed" \
      --from dave --keyring-backend test --home "$CLIENT_HOME" \
      --chain-id "$CHAIN_ID" --node "$RPC_URL" --broadcast-mode sync --output json --yes
  wait_for_height $((LAST_TX_HEIGHT + 12))
  wait_for_policy "$(account_address dave)" 5 2 3 "paused recovery signing key activates after challenge delay"

  wait_for_param_state "$optional" "$normal" "full PQC pause expires automatically"
  broadcast_signed_bundle "protected transaction succeeds again after automatic pause expiry" alice \
    "$WORK_DIR/tx/alice-before-pqc-pause.signed.json"

  create_pqc_key eve signing1
  create_key_proof eve signing1 1 signing register-signing 0
  local cutoff
  cutoff=$(( $(rpc_height 0) + 25 ))
  submit_params_update "schedule irreversible registration cutoff" "$optional" "$normal" "$cutoff"
  wait_for_height "$cutoff"
  local eve_public eve_proof eve_flags=()
  eve_public="$(jq -r '.public_key_base64' "$(key_json_file eve signing1)")"
  eve_proof="$(jq -r '.proof_base64' "$(proof_json_file eve signing1 register-signing)")"
  while IFS= read -r -d '' item; do eve_flags+=("$item"); done < <(common_tx_flags eve)
  broadcast_rejected "new registration is rejected at irreversible cutoff" "registration is closed" \
    "$DORAD_BIN" tx pqcauth register-key 1 "$eve_public" "$eve_proof" \
      --recovery-public-key-base64 "$(jq -r '.public_key_base64' "$(key_json_file eve recovery2)")" \
      --recovery-proof-base64 "$(jq -r '.proof_base64' "$(proof_json_file eve recovery2 register-recovery)")" \
      --self-enforce=true "${eve_flags[@]}"

  submit_params_update "final network-wide PQC requirement" "$required" "$normal" "$cutoff"
  command_fails "unregistered account is rejected in required mode" "PQC authorization" \
    "$DORAD_BIN" tx bank send "$(account_address bob)" "$(account_address receiver)" "209${DENOM}" \
      "${bob_flags[@]}"
  local native_flags=()
  while IFS= read -r -d '' item; do native_flags+=("$item"); done < <(common_tx_flags native)
  broadcast_ok "native ML-DSA account remains usable in required mode" \
    "$DORAD_BIN" tx bank send "$(account_address native)" "$(account_address receiver)" "210${DENOM}" \
      "${native_flags[@]}"
  prepare_and_sign_bank_bundle carol signing1 "$(account_address receiver)" "211${DENOM}" carol-final-required
  broadcast_signed_bundle "registered classic account remains usable with hybrid authorization in required mode" \
    carol "$WORK_DIR/tx/carol-final-required.signed.json"
}

run_scenarios() {
  log "running pqcauth transaction scenarios"
  local params_file="$REPORT_DIR/pqcauth-params.json"
  "$DORAD_BIN" query pqcauth params --node "$RPC_URL" --output json >"$params_file"
  NETWORK_ID="$(jq -r '.params.network_id' "$params_file")"
  [[ -n "$NETWORK_ID" && "$NETWORK_ID" != "null" ]] || die "pqcauth network_id is missing"
  [[ "$(jq -r '.effective_enforcement_mode' "$params_file")" == "ENFORCEMENT_MODE_OPTIONAL" ]] || die "unexpected initial enforcement mode"
  pass "query chain-derived pqcauth network identity" "$NETWORK_ID"

  local gas_estimate="$REPORT_DIR/verification-gas-estimate.json"
  "$DORAD_BIN" query pqcauth estimate-verification-gas \
    --signatures 8 --proofs 2 --node "$RPC_URL" --output json >"$gas_estimate"
  jq -e '.signature_verifications == 8 and .proof_verifications == 2 and .signature_gas == 2000000 and .proof_gas == 500000 and .total == 2500000' \
    "$gas_estimate" >/dev/null || die "deterministic PQC verification gas estimate is incorrect"
  pass "deterministic gas estimator matches on-chain verification parameters" "total=2500000"

  local bob_flags=()
  while IFS= read -r -d '' item; do bob_flags+=("$item"); done < <(common_tx_flags bob)
  broadcast_ok "classic unregistered account remains compatible" \
    "$DORAD_BIN" tx bank send "$(account_address bob)" "$(account_address receiver)" "101${DENOM}" \
      "${bob_flags[@]}"

  local native_flags=()
  while IFS= read -r -d '' item; do native_flags+=("$item"); done < <(common_tx_flags native)
  broadcast_ok "native ML-DSA account signs directly without pqcauth" \
    "$DORAD_BIN" tx bank send "$(account_address native)" "$(account_address receiver)" "100${DENOM}" \
      "${native_flags[@]}"
  create_pqc_key native secondary1
  create_pqc_key native recovery2
  create_key_proof native secondary1 1 signing register-signing 0
  create_key_proof native recovery2 2 recovery register-recovery 0
  broadcast_rejected "native ML-DSA account cannot register a pqcauth second factor" \
    "cannot register pqcauth" \
    "$DORAD_BIN" tx pqcauth register-key 1 \
      "$(jq -r '.public_key_base64' "$(key_json_file native secondary1)")" \
      "$(jq -r '.proof_base64' "$(proof_json_file native secondary1 register-signing)")" \
      --recovery-public-key-base64 "$(jq -r '.public_key_base64' "$(key_json_file native recovery2)")" \
      --recovery-proof-base64 "$(jq -r '.proof_base64' "$(proof_json_file native recovery2 register-recovery)")" \
      --self-enforce=true "${native_flags[@]}"

  create_pqc_key eve invalid1
  create_key_proof eve invalid1 2 signing register-signing 0
  create_pqc_key eve recovery2
  create_key_proof eve recovery2 2 recovery register-recovery 0
  local invalid_public invalid_proof eve_recovery_public eve_recovery_proof eve_flags=()
  invalid_public="$(jq -r '.public_key_base64' "$(key_json_file eve invalid1)")"
  invalid_proof="$(jq -r '.proof_base64' "$(proof_json_file eve invalid1 register-signing)")"
  eve_recovery_public="$(jq -r '.public_key_base64' "$(key_json_file eve recovery2)")"
  eve_recovery_proof="$(jq -r '.proof_base64' "$(proof_json_file eve recovery2 register-recovery)")"
  while IFS= read -r -d '' item; do eve_flags+=("$item"); done < <(common_tx_flags eve)
  command_fails "registration proof bound to wrong key id" "invalid" \
    "$DORAD_BIN" tx pqcauth register-key 1 "$invalid_public" "$invalid_proof" \
      --recovery-public-key-base64 "$eve_recovery_public" \
      --recovery-proof-base64 "$eve_recovery_proof" \
      --self-enforce=true "${eve_flags[@]}"

  register_pqc_account alice
  register_pqc_account dave
  register_pqc_account carol

  local alice_flags=()
  while IFS= read -r -d '' item; do alice_flags+=("$item"); done < <(common_tx_flags alice)
  command_fails "self-enforced account rejects classic-only transaction" "PQC authorization" \
    "$DORAD_BIN" tx bank send "$(account_address alice)" "$(account_address receiver)" "102${DENOM}" \
      "${alice_flags[@]}"

  prepare_and_sign_bank_bundle alice signing1 "$(account_address receiver)" "103${DENOM}" alice-bank-v1
  broadcast_signed_bundle "hybrid-protected bank transaction succeeds" alice "$WORK_DIR/tx/alice-bank-v1.signed.json"

  jq '.sign_doc_sha256_base64 = "AA=="' \
    "$WORK_DIR/tx/alice-bank-v1.prepared.json" >"$WORK_DIR/tx/alice-bank-tampered.prepared.json"
  command_fails "offline signer rejects tampered bundle" "SHA-256 mismatch" \
    "$DORAD_BIN" tx pqcauth sign-bundle \
      "$WORK_DIR/tx/alice-bank-tampered.prepared.json" \
      "$(key_private_file alice signing1)" \
      "$WORK_DIR/tx/alice-bank-tampered.signed.json" \
      --home "$CLIENT_HOME" --yes

  prepare_and_sign_bank_bundle alice signing1 "$(account_address receiver)" "104${DENOM}" alice-stale-before-rotate
  create_pqc_key alice signing3
  create_key_proof alice signing3 3 signing rotate-signing 1
  local signing3_public signing3_proof
  signing3_public="$(jq -r '.public_key_base64' "$(key_json_file alice signing3)")"
  signing3_proof="$(jq -r '.proof_base64' "$(proof_json_file alice signing3 rotate-signing)")"
  broadcast_ok "rotate signing key with active PQC authorization" \
    "$DORAD_BIN" tx pqcauth rotate-key 3 "$signing3_public" "$signing3_proof" \
      --pqc-private-key-file "$(key_private_file alice signing1)" \
      "${alice_flags[@]}"
  wait_for_height $((LAST_TX_HEIGHT + 1))
  wait_for_policy "$(account_address alice)" 3 2 2 "signing key rotation activates at H+1"
  command_fails "pre-rotation signed bundle becomes stale" "stale" \
    "$DORAD_BIN" tx pqcauth broadcast-bundle "$WORK_DIR/tx/alice-stale-before-rotate.signed.json" \
      --from alice --keyring-backend test --home "$CLIENT_HOME" \
      --chain-id "$CHAIN_ID" --node "$RPC_URL" --broadcast-mode sync --output json --yes
  prepare_and_sign_bank_bundle alice signing3 "$(account_address receiver)" "105${DENOM}" alice-bank-v2
  broadcast_signed_bundle "new signing key authorizes protected transaction" alice "$WORK_DIR/tx/alice-bank-v2.signed.json"

  create_pqc_key alice recovery4
  create_key_proof alice recovery4 4 recovery rotate-recovery 2
  local recovery4_public recovery4_proof
  recovery4_public="$(jq -r '.public_key_base64' "$(key_json_file alice recovery4)")"
  recovery4_proof="$(jq -r '.proof_base64' "$(proof_json_file alice recovery4 rotate-recovery)")"
  broadcast_ok "rotate recovery key with current signing key" \
    "$DORAD_BIN" tx pqcauth rotate-recovery-key 4 "$recovery4_public" "$recovery4_proof" \
      --pqc-private-key-file "$(key_private_file alice signing3)" \
      "${alice_flags[@]}"
  wait_for_height $((LAST_TX_HEIGHT + 1))
  wait_for_policy "$(account_address alice)" 3 4 3 "recovery key rotation activates at H+1"

  broadcast_ok "revoke inactive historical signing key" \
    "$DORAD_BIN" tx pqcauth revoke-key 1 \
      --pqc-private-key-file "$(key_private_file alice signing3)" \
      "${alice_flags[@]}"
  local revoked_file="$REPORT_DIR/alice-key1-revoked.json"
  "$DORAD_BIN" query pqcauth key "$(account_address alice)" 1 \
    --node "$RPC_URL" --output json >"$revoked_file"
  [[ "$(jq -r '.key.status' "$revoked_file")" == "KEY_STATUS_REVOKED" ]] || die "historical signing key was not revoked"
  pass "historical key query reports permanent revocation"

  prepare_and_sign_bank_bundle dave signing1 "$(account_address receiver)" "106${DENOM}" dave-stale-before-recovery
  create_pqc_key dave signing3
  create_key_proof dave signing3 3 signing recover-signing 1
  local dave_signing3_public dave_signing3_proof
  dave_signing3_public="$(jq -r '.public_key_base64' "$(key_json_file dave signing3)")"
  dave_signing3_proof="$(jq -r '.proof_base64' "$(proof_json_file dave signing3 recover-signing)")"
  local recovery_prepared="$WORK_DIR/tx/dave-recovery.prepared.json"
  local recovery_signed="$WORK_DIR/tx/dave-recovery.signed.json"
  "$DORAD_BIN" tx pqcauth recover-key 2 3 "$dave_signing3_public" "$dave_signing3_proof" \
    --recovery-sign-bundle-output "$recovery_prepared" \
    --from dave --keyring-backend test --home "$CLIENT_HOME" \
    --chain-id "$CHAIN_ID" --node "$RPC_URL" \
    --gas "$TX_GAS" --fees "$TX_FEE" --output json --yes \
    >"$WORK_DIR/tx/dave-recovery.prepare-result.json"
  "$DORAD_BIN" tx pqcauth sign-recovery-bundle \
    "$recovery_prepared" "$(key_private_file dave recovery2)" "$recovery_signed" \
    --home "$CLIENT_HOME" --yes >"$WORK_DIR/tx/dave-recovery.sign-result.json"
  broadcast_ok "transaction-bound offline recovery succeeds" \
    "$DORAD_BIN" tx pqcauth broadcast-recovery-bundle "$recovery_signed" \
      --from dave --keyring-backend test --home "$CLIENT_HOME" \
      --chain-id "$CHAIN_ID" --node "$RPC_URL" \
      --broadcast-mode sync --output json --yes
  prepare_and_sign_bank_bundle dave signing1 "$(account_address receiver)" "107${DENOM}" dave-recovery-challenge-window
  broadcast_signed_bundle "current signing key remains active during recovery challenge window" dave \
    "$WORK_DIR/tx/dave-recovery-challenge-window.signed.json"
  local dave_flags=()
  while IFS= read -r -d '' item; do dave_flags+=("$item"); done < <(common_tx_flags dave)
  broadcast_ok "current signing key cancels pending recovery" \
    "$DORAD_BIN" tx pqcauth cancel-recovery 3 2 \
      --pqc-private-key-file "$(key_private_file dave signing1)" \
      "${dave_flags[@]}"
  wait_for_policy "$(account_address dave)" 1 2 1 "cancelled recovery preserves the current signing key"
  local cancelled_recovery_key="$REPORT_DIR/dave-cancelled-recovery-key3.json"
  "$DORAD_BIN" query pqcauth key "$(account_address dave)" 3 \
    --node "$RPC_URL" --output json >"$cancelled_recovery_key"
  [[ "$(jq -r '.key.status' "$cancelled_recovery_key")" == "KEY_STATUS_REVOKED" ]] || \
    die "cancelled recovery key was not permanently revoked"
  pass "cancelled recovery consumes and revokes the proposed key identifier"

  create_pqc_key dave signing4
  create_key_proof dave signing4 4 signing recover-signing 1
  local dave_signing4_public dave_signing4_proof
  dave_signing4_public="$(jq -r '.public_key_base64' "$(key_json_file dave signing4)")"
  dave_signing4_proof="$(jq -r '.proof_base64' "$(proof_json_file dave signing4 recover-signing)")"
  local recovery2_prepared="$WORK_DIR/tx/dave-recovery2.prepared.json"
  local recovery2_signed="$WORK_DIR/tx/dave-recovery2.signed.json"
  "$DORAD_BIN" tx pqcauth recover-key 2 4 "$dave_signing4_public" "$dave_signing4_proof" \
    --recovery-sign-bundle-output "$recovery2_prepared" \
    --from dave --keyring-backend test --home "$CLIENT_HOME" \
    --chain-id "$CHAIN_ID" --node "$RPC_URL" \
    --gas "$TX_GAS" --fees "$TX_FEE" --output json --yes \
    >"$WORK_DIR/tx/dave-recovery2.prepare-result.json"
  "$DORAD_BIN" tx pqcauth sign-recovery-bundle \
    "$recovery2_prepared" "$(key_private_file dave recovery2)" "$recovery2_signed" \
    --home "$CLIENT_HOME" --yes >"$WORK_DIR/tx/dave-recovery2.sign-result.json"
  broadcast_ok "second offline recovery request succeeds after cancellation" \
    "$DORAD_BIN" tx pqcauth broadcast-recovery-bundle "$recovery2_signed" \
      --from dave --keyring-backend test --home "$CLIENT_HOME" \
      --chain-id "$CHAIN_ID" --node "$RPC_URL" \
      --broadcast-mode sync --output json --yes
  wait_for_height $((LAST_TX_HEIGHT + 12))
  wait_for_policy "$(account_address dave)" 4 2 2 "recovered signing key activates after challenge delay"
  command_fails "pre-recovery signed bundle becomes stale" "stale" \
    "$DORAD_BIN" tx pqcauth broadcast-bundle "$WORK_DIR/tx/dave-stale-before-recovery.signed.json" \
      --from dave --keyring-backend test --home "$CLIENT_HOME" \
      --chain-id "$CHAIN_ID" --node "$RPC_URL" --broadcast-mode sync --output json --yes
  prepare_and_sign_bank_bundle dave signing4 "$(account_address receiver)" "108${DENOM}" dave-bank-recovered
  broadcast_signed_bundle "recovered signing key authorizes protected transaction" dave "$WORK_DIR/tx/dave-bank-recovered.signed.json"

  broadcast_ok "self-protection disable requires current PQC key" \
    "$DORAD_BIN" tx pqcauth set-protection false \
      --pqc-private-key-file "$(key_private_file alice signing3)" \
      "${alice_flags[@]}"
  wait_for_height $((LAST_TX_HEIGHT + 1))
  wait_for_policy "$(account_address alice)" 3 4 4 "self-protection disable activates at H+1"
  broadcast_ok "classic transaction works after optional self-protection disable" \
    "$DORAD_BIN" tx bank send "$(account_address alice)" "$(account_address receiver)" "108${DENOM}" \
      "${alice_flags[@]}"

  local gas_auto_label="PQC lifecycle gas auto simulates then executes"
  broadcast_ok "$gas_auto_label" \
    "$DORAD_BIN" tx pqcauth set-protection true \
      --pqc-private-key-file "$(key_private_file alice signing3)" \
      --from alice --keyring-backend test --home "$CLIENT_HOME" \
      --chain-id "$CHAIN_ID" --node "$RPC_URL" \
      --gas auto --gas-adjustment 1.2 --fees "$TX_FEE" \
      --broadcast-mode sync --output json --yes
  local gas_auto_stderr="$WORK_DIR/tx/$(artifact_name "$gas_auto_label").broadcast.stderr"
  grep -Fq 'gas estimate:' "$gas_auto_stderr" || die "PQC gas-auto path did not report a simulation estimate"
  wait_for_height $((LAST_TX_HEIGHT + 1))
  wait_for_policy "$(account_address alice)" 3 4 5 "gas-auto protection change activates at H+1"

  prepare_and_sign_bank_bundle alice signing3 "$(account_address receiver)" "110${DENOM}" alice-adversarial-base
  local adversarial_bundle="$WORK_DIR/tx/alice-adversarial-base.signed.json"
  forge_and_reject invalid-signature "invalid PQC signature" "$adversarial_bundle"
  forge_and_reject wrong-signer "signer address mismatch" "$adversarial_bundle"
  forge_and_reject wrong-key "key or policy mismatch" "$adversarial_bundle"
  forge_and_reject wrong-policy "key or policy mismatch" "$adversarial_bundle"
  forge_and_reject out-of-range-signer "out of range" "$adversarial_bundle"
  forge_and_reject unknown-algorithm "unsupported" "$adversarial_bundle"
  forge_and_reject short-signature "invalid signature length" "$adversarial_bundle"
  forge_and_reject empty-entries "PQC authorization" "$adversarial_bundle"
  forge_and_reject noncritical "critical extension" "$adversarial_bundle"
  forge_and_reject not-last "must be last" "$adversarial_bundle"
  forge_and_reject noncanonical "non-canonical" "$adversarial_bundle"
  forge_and_reject oversized "exceeds size limit" "$adversarial_bundle"
  broadcast_signed_bundle "valid transaction succeeds after adversarial rejection matrix" alice "$adversarial_bundle"

  run_authz_security_scenarios
  run_feegrant_security_scenarios
  run_nested_authz_scenario
  run_history_compaction_scenario

  if (( NODES >= 4 )); then
    local before_stop
    before_stop="$(rpc_height 0)"
    stop_one_node 3
    wait_for_height $((before_stop + 3)) 0
    prepare_and_sign_bank_bundle dave signing4 "$(account_address receiver)" "109${DENOM}" dave-bank-node-down
    broadcast_signed_bundle "network commits protected transaction with one validator offline" dave "$WORK_DIR/tx/dave-bank-node-down.signed.json"
    start_one_node 3
    wait_for_rpc 3
    local catchup_target
    catchup_target="$(rpc_height 0)"
    wait_for_height "$catchup_target" 3
    local node3_status="$REPORT_DIR/node3-rejoined-status.json"
    wait_for_node_synced 3 >"$node3_status"
    local rejoined_height
    rejoined_height="$(jq -r '.result.sync_info.latest_block_height | tonumber' "$node3_status")"
    pass "stopped validator rejoins and catches up" "height=$rejoined_height"
  fi

  run_governance_scenarios
  assert_same_app_hash "all live validators converge on one app hash"
}

initialize_network
start_network
run_scenarios

log "summary: passed=$PASS_COUNT failed=$FAIL_COUNT"
