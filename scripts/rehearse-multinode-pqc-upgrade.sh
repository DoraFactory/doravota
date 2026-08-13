#!/usr/bin/env bash

# Production-shaped, single-host rehearsal:
#
#   4-validator v0.4.4 network (Ed25519 consensus keys)
#     -> sdk-v0.53-bridge
#     -> v1.0.0 / SDK v0.55
#     -> x/pqcauth ML-DSA registration for wallets and validator operators
#     -> sequential Ed25519 -> ML-DSA-65 validator consensus-key rotation
#
# All node homes, logs, committed transactions, key-rotation evidence and a
# Markdown report are preserved. The work directory must not already exist.

set -Eeuo pipefail
umask 077

OLD_BIN=""
BRIDGE_BIN=""
TARGET_BIN=""
WORK_DIR=""
CHAIN_ID="doravota-pqc-upgrade-$(date -u +%Y%m%dT%H%M%SZ)"
PORT_BASE=42650
TIMEOUT=300
KEEP_RUNNING=false
NODES=4
DENOM=peaka
GENESIS_BALANCE="1000000000000000000000000000peaka"
STAKE_AMOUNT="1000000000000000000000000peaka"
TX_GAS=5000000
TX_FEE="100000peaka"
MIN_GAS_PRICE="0.001peaka"
RUN_STARTED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
RUN_STARTED_EPOCH="$(date +%s)"
ACTIVE_BIN=""
CLIENT_HOME=""
RPC_URL=""
RESULT=FAIL
REPORT_WRITTEN=false
LAST_TX_HASH=""
LAST_TX_HEIGHT=0
NODE_PIDS=("" "" "" "")
NODE_START_COUNTS=(0 0 0 0)

usage() {
  printf '%s\n' \
    'Usage: scripts/rehearse-multinode-pqc-upgrade.sh [options]' \
    '' \
    'Required:' \
    '  --old-bin FILE       v0.4.4 binary (SDK v0.47 / CometBFT v0.37)' \
    '  --bridge-bin FILE    SDK v0.53 / IBC-Go v10 bridge binary' \
    '  --target-bin FILE    SDK v0.55 + x/pqcauth target binary' \
    '  --work-dir DIR       New directory for the rehearsal artifacts' \
    '' \
    'Options:' \
    '  --chain-id ID        Isolated chain ID' \
    '  --port-base PORT     Node0 P2P port; each node uses ten ports' \
    '  --timeout SECONDS    Per-operation timeout (default 300)' \
    '  --keep-running       Leave the final ML-DSA network running'
}

log() { printf '[pqc-upgrade-e2e] %s\n' "$*" >&2; }
die() { printf '[pqc-upgrade-e2e] ERROR: %s\n' "$*" >&2; exit 1; }
artifact_name() { printf '%s' "$1" | tr -cs 'A-Za-z0-9._-' '_'; }

while [[ $# -gt 0 ]]; do
  case "$1" in
    --old-bin) OLD_BIN="$2"; shift 2 ;;
    --bridge-bin) BRIDGE_BIN="$2"; shift 2 ;;
    --target-bin) TARGET_BIN="$2"; shift 2 ;;
    --work-dir) WORK_DIR="$2"; shift 2 ;;
    --chain-id) CHAIN_ID="$2"; shift 2 ;;
    --port-base) PORT_BASE="$2"; shift 2 ;;
    --timeout) TIMEOUT="$2"; shift 2 ;;
    --keep-running) KEEP_RUNNING=true; shift ;;
    --help|-h) usage; exit 0 ;;
    *) die "unknown option: $1" ;;
  esac
done

for command in jq curl awk sed timeout sha256sum; do
  command -v "$command" >/dev/null 2>&1 || die "required command not found: $command"
done
for binary in "$OLD_BIN" "$BRIDGE_BIN" "$TARGET_BIN"; do
  [[ -x "$binary" ]] || die "binary is not executable: $binary"
done
[[ -n "$WORK_DIR" ]] || die '--work-dir is required'
[[ ! -e "$WORK_DIR" ]] || die "work directory already exists: $WORK_DIR"
[[ "$PORT_BASE" =~ ^[0-9]+$ ]] || die '--port-base must be an integer'
[[ "$TIMEOUT" =~ ^[0-9]+$ ]] || die '--timeout must be an integer'
(( PORT_BASE >= 1024 && PORT_BASE + 39 <= 65535 )) || die 'port range is invalid'

mkdir -p "$WORK_DIR"/{bin,logs,nodes,clients,secrets,pqc,tx,report,rotation}
WORK_DIR="$(cd "$WORK_DIR" && pwd -P)"
CLIENT_HOME="$WORK_DIR/clients/wallets"
RPC_URL="tcp://127.0.0.1:$((PORT_BASE + 1))"
TX_RECORDS="$WORK_DIR/report/transactions.jsonl"
STEP_RECORDS="$WORK_DIR/report/steps.jsonl"
: >"$TX_RECORDS"
: >"$STEP_RECORDS"
printf 'doravota multi-node PQC upgrade rehearsal\n' >"$WORK_DIR/.pqc-upgrade-rehearsal"

node_home() { printf '%s/nodes/node%s' "$WORK_DIR" "$1"; }
node_p2p_port() { printf '%d' $((PORT_BASE + ($1 * 10))); }
node_rpc_port() { printf '%d' $((PORT_BASE + ($1 * 10) + 1)); }
node_abci_port() { printf '%d' $((PORT_BASE + ($1 * 10) + 2)); }
node_grpc_port() { printf '%d' $((PORT_BASE + ($1 * 10) + 3)); }
node_api_port() { printf '%d' $((PORT_BASE + ($1 * 10) + 4)); }
node_rpc_http() { printf 'http://127.0.0.1:%d' "$(node_rpc_port "$1")"; }

record_step() {
  local phase="$1" label="$2" detail="${3:-}"
  jq -cn --arg at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" --arg phase "$phase" \
    --arg label "$label" --arg detail "$detail" \
    '{at:$at,phase:$phase,"label":$label,detail:$detail}' >>"$STEP_RECORDS"
  log "$phase: $label${detail:+ ($detail)}"
}

record_tx() {
  local phase="$1" label="$2" committed="$3"
  jq -c --arg phase "$phase" --arg label "$label" \
    '{phase:$phase,"label":$label,txhash:(.txhash // .tx_response.txhash),height:((.height // .tx_response.height)|tonumber),code:((.code // .tx_response.code // 0)|tonumber),gas_wanted:(.gas_wanted // .tx_response.gas_wanted // "0"),gas_used:(.gas_used // .tx_response.gas_used // "0"),message_types:[.tx.body.messages[]?["@type"]]}' \
    "$committed" >>"$TX_RECORDS"
}

rpc_height() {
  local index="${1:-0}"
  curl -fsS --max-time 3 "$(node_rpc_http "$index")/status" \
    | jq -r '.result.sync_info.latest_block_height | tonumber'
}

wait_for_rpc() {
  local index="$1" deadline=$(( $(date +%s) + TIMEOUT ))
  while (( $(date +%s) < deadline )); do
    local pid="${NODE_PIDS[$index]:-}"
    if [[ -n "$pid" ]] && ! kill -0 "$pid" >/dev/null 2>&1; then
      die "node$index exited before RPC became ready"
    fi
    rpc_height "$index" >/dev/null 2>&1 && return 0
    sleep 1
  done
  die "node$index RPC did not become ready"
}

wait_for_height() {
  local expected="$1" index="${2:-0}" deadline=$(( $(date +%s) + TIMEOUT )) current=0
  while (( $(date +%s) < deadline )); do
    current="$(rpc_height "$index" 2>/dev/null || printf 0)"
    (( current >= expected )) && return 0
    sleep 1
  done
  die "node$index stopped at height $current while waiting for $expected"
}

stable_query() {
  local binary="$1" output="$2"
  shift 2
  local height=$(( $(rpc_height 0) - 1 ))
  (( height > 0 )) || height=1
  "$binary" query "$@" --height "$height" --node "$RPC_URL" --output json >"$output" 2>"$output.stderr"
}

stop_one_node() {
  local index="$1" pid="${NODE_PIDS[$index]:-}"
  if [[ -z "$pid" ]] || ! kill -0 "$pid" >/dev/null 2>&1; then
    NODE_PIDS[$index]=""
    return 0
  fi
  kill "$pid" >/dev/null 2>&1 || true
  local deadline=$(( $(date +%s) + 15 ))
  while kill -0 "$pid" >/dev/null 2>&1 && (( $(date +%s) < deadline )); do sleep 1; done
  if kill -0 "$pid" >/dev/null 2>&1; then kill -KILL "$pid" >/dev/null 2>&1 || true; fi
  wait "$pid" >/dev/null 2>&1 || true
  NODE_PIDS[$index]=""
}

stop_network() {
  local index
  for ((index=0; index<NODES; index++)); do stop_one_node "$index"; done
}

persistent_peers_for() {
  local own="$1" peers="" index peer
  for ((index=0; index<NODES; index++)); do
    (( index == own )) && continue
    peer="$(<"$WORK_DIR/nodes/node${index}.id")@127.0.0.1:$(node_p2p_port "$index")"
    [[ -n "$peers" ]] && peers+=","; peers+="$peer"
  done
  printf '%s' "$peers"
}

start_one_node() {
  local index="$1" binary="$2" phase="$3"
  NODE_START_COUNTS[$index]=$((NODE_START_COUNTS[$index] + 1))
  local log_file="$WORK_DIR/logs/${phase}-node${index}-start${NODE_START_COUNTS[$index]}.log"
  "$binary" start \
    --home "$(node_home "$index")" \
    --minimum-gas-prices "$MIN_GAS_PRICE" \
    --rpc.laddr "tcp://127.0.0.1:$(node_rpc_port "$index")" \
    --p2p.laddr "tcp://127.0.0.1:$(node_p2p_port "$index")" \
    --address "tcp://127.0.0.1:$(node_abci_port "$index")" \
    --grpc.address "127.0.0.1:$(node_grpc_port "$index")" \
    --api.enable=true \
    --api.address "tcp://127.0.0.1:$(node_api_port "$index")" \
    --p2p.persistent_peers "$(persistent_peers_for "$index")" \
    --p2p.pex=false \
    --pruning nothing >"$log_file" 2>&1 &
  NODE_PIDS[$index]=$!
  printf '%s %s %s %s\n' "$phase" "$index" "${NODE_PIDS[$index]}" "$log_file" >>"$WORK_DIR/report/node-processes.txt"
}

start_network() {
  local binary="$1" phase="$2" index
  ACTIVE_BIN="$binary"
  for ((index=0; index<NODES; index++)); do start_one_node "$index" "$binary" "$phase"; done
  for ((index=0; index<NODES; index++)); do wait_for_rpc "$index"; done
  wait_for_height $(( $(rpc_height 0) + 2 )) 0
  record_step "$phase" 'all four validator processes are running' "height=$(rpc_height 0)"
}

wait_for_tx() {
  local binary="$1" hash="$2" output="$3" deadline=$(( $(date +%s) + TIMEOUT ))
  while (( $(date +%s) < deadline )); do
    if "$binary" query tx "$hash" --node "$RPC_URL" --output json >"$output" 2>"$output.stderr"; then return 0; fi
    sleep 1
  done
  die "transaction $hash was not committed"
}

broadcast_tx() {
  local phase="$1" label="$2" binary="$3" home="$4" from="$5"
  shift 5
  local name response committed code
  name="$(artifact_name "$phase-$label")"
  response="$WORK_DIR/tx/$name.broadcast.json"
  committed="$WORK_DIR/tx/$name.committed.json"
  local attempt command_status=1
  local common_flags=(
    --from "$from" --home "$home" --keyring-backend test
    --chain-id "$CHAIN_ID" --node "$RPC_URL"
    --broadcast-mode sync --output json -y
  )
  # prepare-bundle freezes fee, gas, memo, timeout and signer metadata into the
  # ML-DSA sign document. Supplying these flags again is an attempted override
  # and must be rejected by the client. Ordinary transactions still receive
  # the rehearsal defaults here.
  if [[ "${1:-}" != tx || "${2:-}" != pqcauth || "${3:-}" != broadcast-bundle ]]; then
    common_flags+=(--gas "$TX_GAS" --fees "$TX_FEE")
  fi
  for attempt in 1 2 3 4 5; do
    set +e
    "$binary" "$@" "${common_flags[@]}" >"$response" 2>"$response.stderr"
    command_status=$?
    set -e
    if (( command_status == 0 )); then break; fi
    if grep -Eqi 'version does not exist|failed to load state at height|height.*must be less than or equal' \
      "$response" "$response.stderr"; then
      sleep 2
      continue
    fi
    die "$phase/$label command failed: $(tail -20 "$response.stderr" | tr '\n' ' ')"
  done
  (( command_status == 0 )) || die "$phase/$label could not read a stable application height after retries"
  code="$(jq -r '.code // .tx_response.code // 0' "$response")"
  [[ "$code" == 0 ]] || die "$phase/$label failed CheckTx: $(jq -r '.raw_log // .tx_response.raw_log // ""' "$response")"
  LAST_TX_HASH="$(jq -r '.txhash // .tx_response.txhash // empty' "$response")"
  [[ -n "$LAST_TX_HASH" ]] || die "$phase/$label returned no tx hash"
  wait_for_tx "$binary" "$LAST_TX_HASH" "$committed"
  code="$(jq -r '.code // .tx_response.code // 0' "$committed")"
  [[ "$code" == 0 ]] || die "$phase/$label failed DeliverTx: $(jq -r '.raw_log // .tx_response.raw_log // ""' "$committed")"
  LAST_TX_HEIGHT="$(jq -r '(.height // .tx_response.height) | tonumber' "$committed")"
  record_tx "$phase" "$label" "$committed"
  record_step "$phase" "$label" "height=$LAST_TX_HEIGHT tx=$LAST_TX_HASH"
}

broadcast_rejected() {
  local phase="$1" label="$2" expected="$3" binary="$4" home="$5" from="$6"
  shift 6
  local name response stderr code combined
  name="$(artifact_name "$phase-$label")"
  response="$WORK_DIR/tx/$name.rejected.json"
  stderr="$WORK_DIR/tx/$name.rejected.stderr"
  set +e
  "$binary" "$@" --from "$from" --home "$home" --keyring-backend test \
    --chain-id "$CHAIN_ID" --node "$RPC_URL" --gas "$TX_GAS" --fees "$TX_FEE" \
    --broadcast-mode sync --output json -y >"$response" 2>"$stderr"
  local exit_code=$?
  set -e
  code="$(jq -r '.code // .tx_response.code // 0' "$response" 2>/dev/null || printf command)"
  if (( exit_code == 0 )) && [[ "$code" == 0 ]]; then die "$phase/$label unexpectedly succeeded"; fi
  combined="$(printf '%s\n' "$(<"$response")" "$(<"$stderr")")"
  [[ -z "$expected" ]] || grep -Fqi "$expected" <<<"$combined" || die "$phase/$label failed for an unexpected reason"
  record_step "$phase" "$label" "rejected as expected (code=$code)"
}

proposal_id_from() {
  local phase="$1" label="$2" name
  name="$(artifact_name "$phase-$label")"
  jq -r '[((.logs[]?.events[]?), (.events[]?)) | select(.type=="submit_proposal") | .attributes[]? | select(.key=="proposal_id") | .value][0] // empty' \
    "$WORK_DIR/tx/$name.committed.json"
}

vote_all() {
  local phase="$1" binary="$2" proposal_id="$3" index
  for ((index=0; index<NODES; index++)); do
    broadcast_tx "$phase" "validator$index votes yes on proposal $proposal_id" "$binary" \
      "$(node_home "$index")" "validator-$index" tx gov vote "$proposal_id" yes
  done
}

wait_for_proposal_passed() {
  local phase="$1" binary="$2" proposal_id="$3"
  local output="$WORK_DIR/report/$(artifact_name "$phase-proposal-$proposal_id").json"
  local deadline=$(( $(date +%s) + TIMEOUT )) status=""
  while (( $(date +%s) < deadline )); do
    if "$binary" query gov proposal "$proposal_id" --node "$RPC_URL" --output json >"$output" 2>"$output.stderr"; then
      status="$(jq -r '.proposal.status // .status // empty' "$output")"
      [[ "$status" == PROPOSAL_STATUS_PASSED ]] && { record_step "$phase" "proposal $proposal_id passed"; return 0; }
      [[ "$status" == PROPOSAL_STATUS_REJECTED || "$status" == PROPOSAL_STATUS_FAILED ]] && die "proposal $proposal_id ended as $status"
    fi
    sleep 1
  done
  die "proposal $proposal_id did not pass"
}

wait_for_upgrade_halt() {
  local phase="$1" height="$2" deadline=$(( $(date +%s) + TIMEOUT ))
  while (( $(date +%s) < deadline )); do
    local current="$(rpc_height 0 2>/dev/null || printf 0)"
    if (( current >= height )); then
      if grep -Eq 'UPGRADE .* NEEDED|upgrade.*needed|scheduled upgrade' "$WORK_DIR/logs/${phase}-node0-"*.log 2>/dev/null; then
        record_step "$phase" 'upgrade halt observed' "height=$current"
        stop_network
        return 0
      fi
    fi
    if [[ -z "${NODE_PIDS[0]:-}" ]] || ! kill -0 "${NODE_PIDS[0]}" >/dev/null 2>&1; then
      record_step "$phase" 'upgrade process exit observed' "planned_height=$height"
      stop_network
      return 0
    fi
    sleep 1
  done
  die "$phase did not halt at upgrade height $height"
}

assert_network_state() {
  local phase="$1" target index expected="" hash
  target="$(rpc_height 0)"
  for ((index=0; index<NODES; index++)); do wait_for_height "$target" "$index"; done
  for ((index=0; index<NODES; index++)); do
    hash="$(curl -fsS --max-time 5 "$(node_rpc_http "$index")/block?height=$target" | jq -r '.result.block.header.app_hash')"
    [[ -z "$expected" ]] && expected="$hash"
    [[ "$hash" == "$expected" ]] || die "$phase app hash mismatch on node$index at height $target"
  done
  # CometBFT may advertise height H a fraction before the application query
  # store can serve H. Query H-1, which is finalized on every node.
  "$ACTIVE_BIN" query staking validators --height $((target - 1)) --node "$RPC_URL" --output json \
    >"$WORK_DIR/report/$phase-validators.json"
  [[ "$(jq '[.validators[] | select(.status=="BOND_STATUS_BONDED")] | length' "$WORK_DIR/report/$phase-validators.json")" == 4 ]] \
    || die "$phase does not have four bonded validators"
  record_step "$phase" 'four nodes share one app hash' "height=$target app_hash=$expected"
}

account_address() { jq -r '.address' "$WORK_DIR/secrets/$1.json"; }
account_home() {
  case "$1" in
    wallet-*) printf '%s' "$CLIENT_HOME" ;;
    validator-*) printf '%s' "$(node_home "${1#validator-}")" ;;
    *) die "unknown account $1" ;;
  esac
}

initialize_v044_network() {
  record_step v0.4.4 'initialize four Ed25519 validators and four independent wallet accounts'
  local index home coordinator genesis tmp account address
  for ((index=0; index<NODES; index++)); do
    home="$(node_home "$index")"
    "$OLD_BIN" init "doravota-validator-$index" --chain-id "$CHAIN_ID" --home "$home" \
      >"$WORK_DIR/logs/init-node$index.json" 2>"$WORK_DIR/logs/init-node$index.stderr"
    "$OLD_BIN" keys add "validator-$index" --keyring-backend test --home "$home" --output json \
      >"$WORK_DIR/secrets/validator-$index.json"
    sed -i.rehearsal 's/^timeout_propose = .*/timeout_propose = "1s"/' "$home/config/config.toml"
    sed -i.rehearsal 's/^timeout_commit = .*/timeout_commit = "1s"/' "$home/config/config.toml"
    sed -i.rehearsal 's/^addr_book_strict = .*/addr_book_strict = false/' "$home/config/config.toml"
    sed -i.rehearsal 's/^allow_duplicate_ip = .*/allow_duplicate_ip = true/' "$home/config/config.toml"
    sed -i.rehearsal 's/^pprof_laddr = .*/pprof_laddr = ""/' "$home/config/config.toml"
  done
  for ((index=0; index<NODES; index++)); do
    account="wallet-$index"
    "$OLD_BIN" keys add "$account" --keyring-backend test --home "$CLIENT_HOME" --output json \
      >"$WORK_DIR/secrets/$account.json"
  done

  coordinator="$(node_home 0)"
  genesis="$coordinator/config/genesis.json"
  tmp="$coordinator/config/genesis.rehearsal.json"
  jq '
    walk(if type == "string" and . == "stake" then "peaka" else . end)
    | .consensus_params.block.max_gas = "100000000"
    | .app_state.gov.deposit_params.min_deposit = [{"denom":"peaka","amount":"1000000"}]
    | .app_state.gov.deposit_params.max_deposit_period = "30s"
    | .app_state.gov.voting_params.voting_period = "30s"
    | .app_state.gov.params.min_deposit = [{"denom":"peaka","amount":"1000000"}]
    | .app_state.gov.params.max_deposit_period = "30s"
    | .app_state.gov.params.voting_period = "30s"
  ' "$genesis" >"$tmp"
  mv "$tmp" "$genesis"

  for ((index=0; index<NODES; index++)); do
    address="$(account_address "validator-$index")"
    "$OLD_BIN" add-genesis-account "$address" "$GENESIS_BALANCE" --home "$coordinator"
    address="$(account_address "wallet-$index")"
    "$OLD_BIN" add-genesis-account "$address" "$GENESIS_BALANCE" --home "$coordinator"
  done
  for ((index=1; index<NODES; index++)); do cp "$genesis" "$(node_home "$index")/config/genesis.json"; done
  for ((index=0; index<NODES; index++)); do
    "$OLD_BIN" gentx "validator-$index" "$STAKE_AMOUNT" --chain-id "$CHAIN_ID" \
      --keyring-backend test --home "$(node_home "$index")" --moniker "doravota-validator-$index" \
      >"$WORK_DIR/logs/gentx-node$index.json" 2>"$WORK_DIR/logs/gentx-node$index.stderr"
    if (( index > 0 )); then
      find "$(node_home "$index")/config/gentx" -type f -name '*.json' -exec cp '{}' "$coordinator/config/gentx/" ';'
    fi
  done
  "$OLD_BIN" collect-gentxs --home "$coordinator" >"$WORK_DIR/logs/collect-gentxs.txt" \
    2>"$WORK_DIR/logs/collect-gentxs.stderr"
  "$OLD_BIN" validate-genesis --home "$coordinator" >"$WORK_DIR/report/v044-genesis-validation.txt" \
    2>"$WORK_DIR/report/v044-genesis-validation.stderr"
  for ((index=1; index<NODES; index++)); do cp "$genesis" "$(node_home "$index")/config/genesis.json"; done
  for ((index=0; index<NODES; index++)); do
    "$OLD_BIN" tendermint show-node-id --home "$(node_home "$index")" >"$WORK_DIR/nodes/node$index.id"
    cp "$(node_home "$index")/config/priv_validator_key.json" "$WORK_DIR/rotation/node$index-ed25519-priv-validator-key.json"
  done
}

run_classic_wallet_transactions() {
  local phase="$1" binary="$2" index next
  for ((index=0; index<NODES; index++)); do
    next=$(((index + 1) % NODES))
    broadcast_tx "$phase" "wallet$index classic transfer" "$binary" "$CLIENT_HOME" "wallet-$index" \
      tx bank send "$(account_address "wallet-$index")" "$(account_address "wallet-$next")" "$((index + 1))peaka"
  done
}

schedule_bridge_upgrade() {
  local height=$(( $(rpc_height 0) + 35 )) proposal_id
  printf '%s\n' "$height" >"$WORK_DIR/report/bridge-upgrade-height.txt"
  broadcast_tx v0.4.4 'submit SDK v0.53 bridge upgrade' "$OLD_BIN" "$(node_home 0)" validator-0 \
    tx gov submit-legacy-proposal software-upgrade sdk-v0.53-bridge \
    --title 'SDK v0.53 bridge' --description 'Bridge SDK, IBC-Go and Wasmd migrations' \
    --upgrade-height "$height" --upgrade-info '{}' --no-validate --deposit 1000000peaka
  proposal_id="$(proposal_id_from v0.4.4 'submit SDK v0.53 bridge upgrade')"
  [[ -n "$proposal_id" ]] || die 'cannot resolve bridge proposal id'
  vote_all v0.4.4 "$OLD_BIN" "$proposal_id"
  wait_for_proposal_passed v0.4.4 "$OLD_BIN" "$proposal_id"
  wait_for_upgrade_halt v0.4.4 "$height"
}

schedule_target_upgrade() {
  local height=$(( $(rpc_height 0) + 40 )) authority proposal_id
  printf '%s\n' "$height" >"$WORK_DIR/report/target-upgrade-height.txt"
  stable_query "$BRIDGE_BIN" "$WORK_DIR/report/gov-module-account.json" auth module-account gov
  authority="$(jq -r '.account.base_account.address // .account.baseAccount.address // .account.value.address // empty' "$WORK_DIR/report/gov-module-account.json")"
  [[ -n "$authority" ]] || die 'cannot resolve governance authority'
  jq -n --arg authority "$authority" --arg height "$height" \
    '{messages:[{"@type":"/cosmos.upgrade.v1beta1.MsgSoftwareUpgrade",authority:$authority,plan:{name:"v1.0.0",time:"0001-01-01T00:00:00Z",height:$height,info:"{}",upgraded_client_state:null}}],metadata:"",deposit:"1000000peaka",title:"v1.0.0 SDK v0.55 and PQC",summary:"Enable SDK v0.55, x/pqcauth and native ML-DSA",expedited:false}' \
    >"$WORK_DIR/report/target-upgrade-proposal.json"
  broadcast_tx sdk-v0.53-bridge 'submit v1.0.0 target upgrade' "$BRIDGE_BIN" "$(node_home 0)" validator-0 \
    tx gov submit-proposal "$WORK_DIR/report/target-upgrade-proposal.json"
  proposal_id="$(proposal_id_from sdk-v0.53-bridge 'submit v1.0.0 target upgrade')"
  [[ -n "$proposal_id" ]] || die 'cannot resolve target proposal id'
  vote_all sdk-v0.53-bridge "$BRIDGE_BIN" "$proposal_id"
  wait_for_proposal_passed sdk-v0.53-bridge "$BRIDGE_BIN" "$proposal_id"
  wait_for_upgrade_halt sdk-v0.53-bridge "$height"
}

enable_mldsa_consensus_keys() {
  local proposal_id authority
  stable_query "$TARGET_BIN" "$WORK_DIR/report/consensus-params-before.json" consensus params
  jq '.params | .validator.pub_key_types = ([.validator.pub_key_types[], "ml_dsa_65"] | unique)' \
    "$WORK_DIR/report/consensus-params-before.json" >"$WORK_DIR/report/consensus-params-mldsa.json"
  stable_query "$TARGET_BIN" "$WORK_DIR/report/target-gov-module-account.json" auth module-account gov
  authority="$(jq -r '.account.base_account.address // .account.baseAccount.address // .account.value.address // empty' "$WORK_DIR/report/target-gov-module-account.json")"
  [[ -n "$authority" ]] || die 'cannot resolve target governance authority'
  jq -n --arg authority "$authority" --slurpfile params "$WORK_DIR/report/consensus-params-mldsa.json" \
    '{messages:[{"@type":"/cosmos.consensus.v1.MsgUpdateParams",authority:$authority,block:$params[0].block,evidence:$params[0].evidence,validator:$params[0].validator,abci:($params[0].abci // null),auth:($params[0].auth // null)}],metadata:"",deposit:"1000000peaka",title:"Allow ML-DSA-65 validator keys",summary:"Permit staged Ed25519 to ML-DSA-65 consensus key rotation",expedited:false}' \
    >"$WORK_DIR/report/consensus-params-proposal.json"
  broadcast_tx sdk-v0.55 'propose ML-DSA-65 consensus key support' "$TARGET_BIN" "$(node_home 0)" validator-0 \
    tx gov submit-proposal "$WORK_DIR/report/consensus-params-proposal.json"
  proposal_id="$(proposal_id_from sdk-v0.55 'propose ML-DSA-65 consensus key support')"
  [[ -n "$proposal_id" ]] || die 'cannot resolve consensus params proposal id'
  vote_all sdk-v0.55 "$TARGET_BIN" "$proposal_id"
  wait_for_proposal_passed sdk-v0.55 "$TARGET_BIN" "$proposal_id"
  local deadline=$(( $(date +%s) + TIMEOUT ))
  while (( $(date +%s) < deadline )); do
    stable_query "$TARGET_BIN" "$WORK_DIR/report/consensus-params-after.json" consensus params
    if jq -e '.params.validator.pub_key_types | index("ml_dsa_65") != null' "$WORK_DIR/report/consensus-params-after.json" >/dev/null; then
      record_step sdk-v0.55 'consensus parameters now allow ML-DSA-65'
      return 0
    fi
    sleep 1
  done
  die 'ML-DSA-65 did not appear in consensus validator pubkey types'
}

pqc_private_file() { printf '%s/%s-signing.mldsa65' "$WORK_DIR/pqc" "$1"; }

register_pqc_account() {
  local logical="$1" home name address signing_key recovery_key signing_pub recovery_pub signing_proof recovery_proof
  home="$(account_home "$logical")"
  name="$logical"
  address="$(account_address "$logical")"
  signing_key="$(pqc_private_file "$logical")"
  recovery_key="$WORK_DIR/pqc/$logical-recovery.mldsa65"
  "$TARGET_BIN" tx pqcauth keygen "$signing_key" >"$WORK_DIR/pqc/$logical-signing-key.json"
  "$TARGET_BIN" tx pqcauth keygen "$recovery_key" >"$WORK_DIR/pqc/$logical-recovery-key.json"
  "$TARGET_BIN" tx pqcauth create-key-proof "$signing_key" "$address" 1 signing register-signing \
    --network-id-base64 "$NETWORK_ID" --policy-version 0 --chain-id "$CHAIN_ID" \
    >"$WORK_DIR/pqc/$logical-signing-proof.json"
  "$TARGET_BIN" tx pqcauth create-key-proof "$recovery_key" "$address" 2 recovery register-recovery \
    --network-id-base64 "$NETWORK_ID" --policy-version 0 --chain-id "$CHAIN_ID" \
    >"$WORK_DIR/pqc/$logical-recovery-proof.json"
  signing_pub="$(jq -r '.public_key_base64' "$WORK_DIR/pqc/$logical-signing-key.json")"
  recovery_pub="$(jq -r '.public_key_base64' "$WORK_DIR/pqc/$logical-recovery-key.json")"
  signing_proof="$(jq -r '.proof_base64' "$WORK_DIR/pqc/$logical-signing-proof.json")"
  recovery_proof="$(jq -r '.proof_base64' "$WORK_DIR/pqc/$logical-recovery-proof.json")"
  broadcast_tx pqcauth "register $logical ML-DSA signing and recovery keys" "$TARGET_BIN" "$home" "$name" \
    tx pqcauth register-key 1 "$signing_pub" "$signing_proof" \
    --recovery-public-key-base64 "$recovery_pub" --recovery-proof-base64 "$recovery_proof" --self-enforce=true
  wait_for_height $((LAST_TX_HEIGHT + 1))
  "$TARGET_BIN" query pqcauth account "$address" --node "$RPC_URL" --output json >"$WORK_DIR/report/$logical-pqcauth-account.json"
  jq -e '.policy.current_signing_key_id=="1" and .policy.recovery_key_id=="2" and .policy.self_enforced==true' \
    "$WORK_DIR/report/$logical-pqcauth-account.json" >/dev/null || die "$logical PQC policy did not activate"
  record_step pqcauth "$logical PQC policy active" "address=$address"
}

prepare_and_broadcast_hybrid() {
  local phase="$1" label="$2" logical="$3" unsigned="$4"
  local home prepared signed
  home="$(account_home "$logical")"
  prepared="$WORK_DIR/tx/$(artifact_name "$phase-$label").prepared.json"
  signed="$WORK_DIR/tx/$(artifact_name "$phase-$label").signed.json"
  "$TARGET_BIN" tx pqcauth prepare-bundle "$unsigned" "$prepared" --from "$logical" --home "$home" \
    --keyring-backend test --chain-id "$CHAIN_ID" --node "$RPC_URL" --output json -y \
    >"$prepared.result.json"
  "$TARGET_BIN" tx pqcauth sign-bundle "$prepared" "$(pqc_private_file "$logical")" "$signed" \
    --home "$home" -y >"$signed.result.json"
  broadcast_tx "$phase" "$label" "$TARGET_BIN" "$home" "$logical" tx pqcauth broadcast-bundle "$signed"
}

run_wallet_pqc_transactions() {
  local index next logical unsigned home
  for ((index=0; index<NODES; index++)); do
    logical="wallet-$index"
    next=$(((index + 1) % NODES))
    home="$(account_home "$logical")"
    broadcast_rejected pqcauth "$logical rejects classic-only transfer" 'PQC authorization' \
      "$TARGET_BIN" "$home" "$logical" tx bank send "$(account_address "$logical")" \
      "$(account_address "wallet-$next")" "$((100 + index))peaka"
    unsigned="$WORK_DIR/tx/$logical-hybrid-bank.unsigned.json"
    "$TARGET_BIN" tx bank send "$(account_address "$logical")" "$(account_address "wallet-$next")" \
      "$((200 + index))peaka" --from "$logical" --home "$home" --keyring-backend test \
      --chain-id "$CHAIN_ID" --node "$RPC_URL" --gas "$TX_GAS" --fees "$TX_FEE" \
      --generate-only --output json >"$unsigned"
    prepare_and_broadcast_hybrid pqcauth "$logical hybrid ML-DSA transfer" "$logical" "$unsigned"
  done
}

wait_for_new_consensus_signature() {
  local index="$1" address="$2" deadline=$(( $(date +%s) + TIMEOUT )) height output
  while (( $(date +%s) < deadline )); do
    height="$(rpc_height "$index" 2>/dev/null || printf 0)"
    output="$WORK_DIR/rotation/node$index-mldsa-signature-block-$height.json"
    if curl -fsS --max-time 5 "$(node_rpc_http "$index")/block?height=$height" >"$output" 2>/dev/null; then
      if jq -e --arg address "$address" '.result.block.last_commit.signatures | any(.validator_address==$address)' "$output" >/dev/null; then
        printf '%s' "$height" >"$WORK_DIR/rotation/node$index-first-observed-mldsa-signature-height.txt"
        return 0
      fi
    fi
    sleep 1
  done
  die "node$index did not produce an observable ML-DSA consensus signature"
}

rotate_validator_consensus_key() {
  local index="$1" logical="validator-$1" home temp_home pub_json unsigned apply_height observer new_address old_address
  home="$(node_home "$index")"
  temp_home="$WORK_DIR/rotation/node$index-mldsa-home"
  "$TARGET_BIN" init "doravota-validator-$index-mldsa" --chain-id "$CHAIN_ID-rotation-$index" \
    --home "$temp_home" --consensus-key-algo ml_dsa_65 \
    >"$WORK_DIR/rotation/node$index-mldsa-init.json" 2>"$WORK_DIR/rotation/node$index-mldsa-init.stderr"
  "$TARGET_BIN" comet show-validator --home "$temp_home" >"$WORK_DIR/rotation/node$index-mldsa-pubkey.json"
  pub_json="$(jq -c . "$WORK_DIR/rotation/node$index-mldsa-pubkey.json")"
  old_address="$(jq -r '.address' "$home/config/priv_validator_key.json")"
  new_address="$(jq -r '.address' "$temp_home/config/priv_validator_key.json")"
  unsigned="$WORK_DIR/tx/node$index-consensus-rotation.unsigned.json"
  "$TARGET_BIN" tx staking rotate-cons-pub-key "$pub_json" --from "$logical" --home "$home" \
    --keyring-backend test --chain-id "$CHAIN_ID" --node "$RPC_URL" --gas "$TX_GAS" --fees "$TX_FEE" \
    --generate-only --output json >"$unsigned"
  prepare_and_broadcast_hybrid consensus-rotation "validator$index Ed25519 to ML-DSA-65" "$logical" "$unsigned"
  local committed="$WORK_DIR/tx/$(artifact_name "consensus-rotation-validator$index Ed25519 to ML-DSA-65").committed.json"
  apply_height="$(jq -r '[((.logs[]?.events[]?), (.events[]?)) | .attributes[]? | select(.key=="apply_height") | .value][0] // empty' "$committed")"
  [[ "$apply_height" =~ ^[0-9]+$ ]] || die "validator$index rotation returned no apply_height"
  jq -n --argjson index "$index" --arg old "$old_address" --arg new "$new_address" \
    --arg tx "$LAST_TX_HASH" --argjson tx_height "$LAST_TX_HEIGHT" --argjson apply_height "$apply_height" \
    '{validator_index:$index,old_consensus_address:$old,new_consensus_address:$new,txhash:$tx,tx_height:$tx_height,apply_height:$apply_height}' \
    >"$WORK_DIR/rotation/node$index-rotation.json"

  stop_one_node "$index"
  cp "$home/config/priv_validator_key.json" "$WORK_DIR/rotation/node$index-ed25519-key-before-install.json"
  cp "$temp_home/config/priv_validator_key.json" "$home/config/priv_validator_key.json"
  observer=$(((index + 1) % NODES))
  wait_for_height $((apply_height + 1)) "$observer"
  start_one_node "$index" "$TARGET_BIN" mldsa-consensus
  wait_for_rpc "$index"
  wait_for_height $((apply_height + 3)) "$index"

  local valoper
  valoper="$("$TARGET_BIN" keys show "$logical" --bech val -a --home "$home" --keyring-backend test)"
  "$TARGET_BIN" query staking validator "$valoper" --node "$RPC_URL" --output json \
    >"$WORK_DIR/rotation/node$index-staking-validator-after.json"
  jq -e '((.validator.consensus_pubkey["@type"] // .validator.consensus_pubkey.type // "") | ascii_downcase | contains("mldsa65"))' \
    "$WORK_DIR/rotation/node$index-staking-validator-after.json" >/dev/null \
    || die "validator$index staking state does not use ML-DSA-65"
  curl -fsS --max-time 5 "$(node_rpc_http "$observer")/validators?height=$(rpc_height "$observer")" \
    >"$WORK_DIR/rotation/node$index-comet-validator-set-after.json"
  jq -e --arg address "$new_address" '.result.validators | any(.address==$address)' \
    "$WORK_DIR/rotation/node$index-comet-validator-set-after.json" >/dev/null \
    || die "validator$index new consensus address is absent from CometBFT validator set"
  wait_for_new_consensus_signature "$index" "$new_address"
  record_step consensus-rotation "validator$index signs blocks with ML-DSA-65" \
    "old=$old_address new=$new_address apply_height=$apply_height"
}

write_report() {
  local exit_code="$1" finished_at duration status final_height=0 final_hash=""
  finished_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  duration=$(( $(date +%s) - RUN_STARTED_EPOCH ))
  status=FAIL
  (( exit_code == 0 )) && status="$RESULT"
  if rpc_height 0 >/dev/null 2>&1; then
    final_height="$(rpc_height 0)"
    final_hash="$(curl -fsS --max-time 5 "$(node_rpc_http 0)/block?height=$final_height" | jq -r '.result.block.header.app_hash')"
  fi
  jq -s '.' "$TX_RECORDS" >"$WORK_DIR/report/transactions.json"
  jq -s '.' "$STEP_RECORDS" >"$WORK_DIR/report/steps.json"
  jq -n --arg result "$status" --arg chain_id "$CHAIN_ID" --arg work_dir "$WORK_DIR" \
    --arg started_at "$RUN_STARTED_AT" --arg finished_at "$finished_at" --arg final_app_hash "$final_hash" \
    --argjson duration_seconds "$duration" --argjson final_height "$final_height" \
    --slurpfile transactions "$WORK_DIR/report/transactions.json" --slurpfile steps "$WORK_DIR/report/steps.json" \
    '{result:$result,chain_id:$chain_id,work_dir:$work_dir,started_at:$started_at,finished_at:$finished_at,duration_seconds:$duration_seconds,final_height:$final_height,final_app_hash:$final_app_hash,transactions:$transactions[0],steps:$steps[0]}' \
    >"$WORK_DIR/report/summary.json"

  {
    printf '# Doravota 多节点 PQC 双层升级演练报告\n\n'
    printf -- '- 结果：`%s`\n' "$status"
    printf -- '- Chain ID：`%s`\n' "$CHAIN_ID"
    printf -- '- 节点：4 个验证人，单机隔离端口，独立 node home\n'
    printf -- '- 钱包：4 个普通钱包 + 4 个 validator operator 账户\n'
    printf -- '- 起始版本：v0.4.4（SDK v0.47，Ed25519 共识）\n'
    printf -- '- 桥接版本：SDK v0.53 / IBC-Go v10\n'
    printf -- '- 目标版本：SDK v0.55 + x/pqcauth + ML-DSA-65 共识密钥\n'
    printf -- '- 最终高度：%s\n' "$final_height"
    printf -- '- 用时：%s 秒\n\n' "$duration"
    printf '## 演练过程\n\n'
    jq -r '.[] | "- [" + .at + "] **" + .phase + "** — " + .label + (if .detail=="" then "" else "："+.detail end)' "$WORK_DIR/report/steps.json"
    printf '\n## 全部链上交易\n\n'
    printf '| 阶段 | 交易 | 高度 | Tx Hash | Gas Used |\n|---|---|---:|---|---:|\n'
    jq -r '.[] | "| " + .phase + " | " + .label + " | " + (.height|tostring) + " | `" + .txhash + "` | " + (.gas_used|tostring) + " |"' "$WORK_DIR/report/transactions.json"
    printf '\n## 共识密钥轮换证据\n\n'
    local index
    for ((index=0; index<NODES; index++)); do
      if [[ -f "$WORK_DIR/rotation/node$index-rotation.json" ]]; then
        jq -r '"- validator"+(.validator_index|tostring)+": `"+.old_consensus_address+"` → `"+.new_consensus_address+"`, tx `"+.txhash+"`, 提交高度 "+(.tx_height|tostring)+", 生效高度 "+(.apply_height|tostring)' "$WORK_DIR/rotation/node$index-rotation.json"
      fi
    done
    printf '\n原始交易 JSON、节点日志、旧/新共识公钥、validator set 和包含新密钥签名的区块均保存在本报告同级目录。\n'
  } >"$WORK_DIR/report/rehearsal-report.md"
  REPORT_WRITTEN=true
}

on_exit() {
  local exit_code=$?
  trap - EXIT
  if [[ "$REPORT_WRITTEN" != true ]]; then write_report "$exit_code" || true; fi
  if [[ "$KEEP_RUNNING" != true || $exit_code -ne 0 ]]; then stop_network; fi
  if (( exit_code == 0 )); then
    log "PASS; artifacts: $WORK_DIR"
  else
    log "FAILED; diagnostics preserved: $WORK_DIR"
  fi
  exit "$exit_code"
}
trap on_exit EXIT
trap 'exit 130' INT TERM

for entry in "old:$OLD_BIN" "bridge:$BRIDGE_BIN" "target:$TARGET_BIN"; do
  label="${entry%%:*}"; binary="${entry#*:}"
  "$binary" version --long >"$WORK_DIR/report/$label-version.txt"
  sha256sum "$binary" >"$WORK_DIR/report/$label-binary.sha256"
done

initialize_v044_network
start_network "$OLD_BIN" v0.4.4
assert_network_state v0.4.4
run_classic_wallet_transactions v0.4.4 "$OLD_BIN"
schedule_bridge_upgrade

start_network "$BRIDGE_BIN" sdk-v0.53-bridge
wait_for_height $(( $(<"$WORK_DIR/report/bridge-upgrade-height.txt") + 2 ))
assert_network_state sdk-v0.53-bridge
stable_query "$BRIDGE_BIN" "$WORK_DIR/report/bridge-module-versions.json" upgrade module-versions
run_classic_wallet_transactions sdk-v0.53-bridge "$BRIDGE_BIN"
schedule_target_upgrade

start_network "$TARGET_BIN" sdk-v0.55
wait_for_height $(( $(<"$WORK_DIR/report/target-upgrade-height.txt") + 2 ))
assert_network_state sdk-v0.55
stable_query "$TARGET_BIN" "$WORK_DIR/report/pqcauth-params.json" pqcauth params
NETWORK_ID="$(jq -r '.params.network_id' "$WORK_DIR/report/pqcauth-params.json")"
[[ -n "$NETWORK_ID" && "$NETWORK_ID" != null ]] || die 'pqcauth network_id is missing'
run_classic_wallet_transactions sdk-v0.55 "$TARGET_BIN"
enable_mldsa_consensus_keys

for index in 0 1 2 3; do register_pqc_account "wallet-$index"; done
for index in 0 1 2 3; do register_pqc_account "validator-$index"; done
run_wallet_pqc_transactions

for index in 0 1 2 3; do
  rotate_validator_consensus_key "$index"
  assert_network_state "consensus-rotation-$index"
done

curl -fsS --max-time 5 "$(node_rpc_http 0)/validators?height=$(rpc_height 0)" >"$WORK_DIR/report/final-comet-validators.json"
[[ "$(jq '[.result.validators[] | select((.pub_key.type | ascii_downcase) | contains("mldsa"))] | length' "$WORK_DIR/report/final-comet-validators.json")" == 4 ]] \
  || die 'final CometBFT validator set is not entirely ML-DSA-65'
assert_network_state final-mldsa-network
RESULT=PASS
record_step final 'all four validators and all eight protected accounts passed' "height=$(rpc_height 0)"
write_report 0
jq . "$WORK_DIR/report/summary.json"
