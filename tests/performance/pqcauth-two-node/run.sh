#!/usr/bin/env bash
set -Eeuo pipefail

# Two-validator, Docker-constrained block-capacity benchmark for:
#   1. classic secp256k1 account transactions;
#   2. secp256k1 + pqcauth ML-DSA-65 hybrid transactions; and
#   3. native Cosmos SDK ML-DSA-65 account transactions.
# Both validators also use ML-DSA-65 consensus keys.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
RUN_ID="$(date -u +%Y%m%dT%H%M%SZ)"
WORK_DIR="${PQC_CAPACITY_WORK_DIR:-/tmp/doravota-pqcauth-capacity-$RUN_ID}"
PROFILE="${PQC_CAPACITY_PROFILE:-capacity}"
RUNTIME_IMAGE="${PQC_CAPACITY_RUNTIME_IMAGE:-golang:1.26.5-bookworm}"
NODE0_CPUS="${PQC_CAPACITY_NODE0_CPUS:-0-7}"
NODE1_CPUS="${PQC_CAPACITY_NODE1_CPUS:-8-15}"
NODE_MEMORY="${PQC_CAPACITY_NODE_MEMORY:-24g}"
LOAD_CPUS="${PQC_CAPACITY_LOAD_CPUS:-16-19}"
CHAIN_ID="${PQC_CAPACITY_CHAIN_ID:-pqcauth-capacity-$RUN_ID}"
CLASSIC_COUNT="${PQC_CAPACITY_CLASSIC_COUNT:-1250}"
HYBRID_COUNT="${PQC_CAPACITY_HYBRID_COUNT:-300}"
NATIVE_COUNT="${PQC_CAPACITY_NATIVE_COUNT:-480}"
CLASSIC_GAS="${PQC_CAPACITY_CLASSIC_GAS:-120000}"
HYBRID_GAS="${PQC_CAPACITY_HYBRID_GAS:-400000}"
NATIVE_GAS="${PQC_CAPACITY_NATIVE_GAS:-320000}"
BLOCK_MAX_GAS="${PQC_CAPACITY_BLOCK_MAX_GAS:-100000000}"
BLOCK_MAX_BYTES="${PQC_CAPACITY_BLOCK_MAX_BYTES:-22020096}"
BROADCAST_CONCURRENCY="${PQC_CAPACITY_BROADCAST_CONCURRENCY:-32}"
KEEP_RUNNING="${PQC_CAPACITY_KEEP_RUNNING:-0}"
STRESS_TARGETS="${PQC_STRESS_TARGETS:-30,60,90}"
STRESS_DURATION="${PQC_STRESS_DURATION:-120}"
ADVERSARIAL_DURATION="${PQC_ADVERSARIAL_DURATION:-120}"
ADVERSARIAL_VALID_TARGET="${PQC_ADVERSARIAL_VALID_TARGET:-60}"
ADVERSARIAL_RATE="${PQC_ADVERSARIAL_RATE:-300}"
VALID_WEIGHTS="${PQC_STRESS_VALID_WEIGHTS:-40,30,30}"
ATTACK_WEIGHTS="${PQC_STRESS_ATTACK_WEIGHTS:-85,1,4,10}"

BIN_DIR="$WORK_DIR/bin"
BUILD_CACHE="${PQC_CAPACITY_BUILD_CACHE:-$WORK_DIR/build-cache}"
FIXTURE_DIR="$WORK_DIR/fixtures"
NODE_DIR="$WORK_DIR/nodes"
REPORT_DIR="$WORK_DIR/report"
LOG_DIR="$WORK_DIR/logs"
STREAM_DIR="$WORK_DIR/streams"
PHASE_FILE="$WORK_DIR/current-phase"
MONITOR_STOP="$WORK_DIR/monitor.stop"
CONTAINER_PREFIX="pqcauth-capacity-${RUN_ID,,}"
NODE0_NAME="$CONTAINER_PREFIX-node0"
NODE1_NAME="$CONTAINER_PREFIX-node1"

log() { printf '[pqcauth-capacity] %s\n' "$*" >&2; }
die() { log "ERROR: $*"; exit 1; }

cleanup() {
  local exit_code=$?
  touch "$MONITOR_STOP" 2>/dev/null || true
  if [[ -n "${MONITOR_PID:-}" ]]; then wait "$MONITOR_PID" 2>/dev/null || true; fi
  if (( exit_code != 0 )); then
    docker logs "$NODE0_NAME" >"$LOG_DIR/node0-failure.log" 2>&1 || true
    docker logs "$NODE1_NAME" >"$LOG_DIR/node1-failure.log" 2>&1 || true
    docker inspect "$NODE0_NAME" "$NODE1_NAME" >"$REPORT_DIR/docker-inspect-failure.json" 2>/dev/null || true
  fi
  if [[ "$KEEP_RUNNING" != "1" || $exit_code -ne 0 ]]; then
    docker rm -f "$NODE0_NAME" "$NODE1_NAME" >/dev/null 2>&1 || true
  fi
  exit "$exit_code"
}
trap cleanup EXIT INT TERM

[[ ! -e "$WORK_DIR" ]] || die "work directory already exists: $WORK_DIR"
[[ "$PROFILE" == "capacity" || "$PROFILE" == "stress" ]] || die "PQC_CAPACITY_PROFILE must be capacity or stress"
command -v docker >/dev/null || die "docker is required"
command -v jq >/dev/null || die "jq is required"
command -v curl >/dev/null || die "curl is required"
command -v python3 >/dev/null || die "python3 is required"
docker info >/dev/null 2>&1 || die "docker daemon is unavailable"
docker image inspect "$RUNTIME_IMAGE" >/dev/null 2>&1 || docker pull "$RUNTIME_IMAGE"
mkdir -p "$BIN_DIR" "$BUILD_CACHE/go-mod" "$BUILD_CACHE/go-build" "$NODE_DIR" "$REPORT_DIR" "$LOG_DIR"

if [[ "$PROFILE" == "stress" ]]; then
  log "planning steady-state and adversarial transaction streams"
  python3 "$SCRIPT_DIR/build_stress_plan.py" \
    --plan-out "$REPORT_DIR/stress-plan.json" \
    --targets "$STRESS_TARGETS" \
    --steady-duration "$STRESS_DURATION" \
    --adversarial-duration "$ADVERSARIAL_DURATION" \
    --adversarial-valid-target "$ADVERSARIAL_VALID_TARGET" \
    --attack-rate "$ADVERSARIAL_RATE" \
    --valid-weights "$VALID_WEIGHTS" \
    --attack-weights "$ATTACK_WEIGHTS" \
    --block-max-gas "$BLOCK_MAX_GAS" \
    --classic-gas "$CLASSIC_GAS" --hybrid-gas "$HYBRID_GAS" --native-gas "$NATIVE_GAS" \
    >"$REPORT_DIR/stress-plan.stdout.json"
  CLASSIC_COUNT="$(jq -r '.total_counts.classic' "$REPORT_DIR/stress-plan.json")"
  HYBRID_COUNT="$(jq -r '.total_counts.hybrid' "$REPORT_DIR/stress-plan.json")"
  NATIVE_COUNT="$(jq -r '.total_counts.native' "$REPORT_DIR/stress-plan.json")"
  INVALID_PQC_COUNT="$(jq -r '.total_counts["invalid-pqc"]' "$REPORT_DIR/stress-plan.json")"
  OVERSIZED_COUNT="$(jq -r '.total_counts.oversized' "$REPORT_DIR/stress-plan.json")"
  NONCANONICAL_COUNT="$(jq -r '.total_counts.noncanonical' "$REPORT_DIR/stress-plan.json")"
  BAD_SEQUENCE_COUNT="$(jq -r '.total_counts["bad-sequence"]' "$REPORT_DIR/stress-plan.json")"
else
  INVALID_PQC_COUNT=0
  OVERSIZED_COUNT=0
  NONCANONICAL_COUNT=0
  BAD_SEQUENCE_COUNT=0
fi

docker rm -f "$NODE0_NAME" "$NODE1_NAME" >/dev/null 2>&1 || true

docker_build() {
  log "building dorad and benchmark tools from $(git -C "$REPO_ROOT" rev-parse --short HEAD)"
  docker run --rm \
    --cpuset-cpus "$LOAD_CPUS" \
    -v "$REPO_ROOT:/src:ro" \
    -v "$BIN_DIR:/out" \
    -v "$BUILD_CACHE/go-mod:/go/pkg/mod" \
    -v "$BUILD_CACHE/go-build:/root/.cache/go-build" \
    -w /src "$RUNTIME_IMAGE" sh -euc '
      CGO_ENABLED=1 go build -mod=readonly -o /out/dorad ./cmd/dorad
      CGO_ENABLED=1 go build -mod=readonly -o /out/pqcload ./tests/performance/pqcauth-two-node/cmd/pqcload
      CGO_ENABLED=1 go build -mod=readonly -o /out/pqcauth-gas-calibrate ./cmd/pqcauth-gas-calibrate
      lib=$(find /go/pkg/mod -type f -name "libwasmvm.x86_64.so" -print -quit)
      test -n "$lib"
      cp "$lib" /out/libwasmvm.x86_64.so
      chmod 0755 /out/dorad /out/pqcload /out/pqcauth-gas-calibrate
    '
}

runtime() {
  docker run --rm --network host --cpuset-cpus "$LOAD_CPUS" \
    -e "LD_LIBRARY_PATH=$BIN_DIR" \
    -v "$WORK_DIR:$WORK_DIR" -v "$BIN_DIR:$BIN_DIR:ro" \
    "$RUNTIME_IMAGE" "$@"
}

dorad() { runtime "$BIN_DIR/dorad" "$@"; }
pqcload() { runtime "$BIN_DIR/pqcload" "$@"; }

node_home() { printf '%s/node%s' "$NODE_DIR" "$1"; }
node_rpc_port() { printf '%d' "$((37657 + 1000 * $1))"; }
node_p2p_port() { printf '%d' "$((37656 + 1000 * $1))"; }
node_abci_port() { printf '%d' "$((37658 + 1000 * $1))"; }
node_grpc_port() { printf '%d' "$((39090 + 1000 * $1))"; }
node_rpc() { printf 'http://127.0.0.1:%s' "$(node_rpc_port "$1")"; }
container_name() { [[ "$1" == "0" ]] && printf '%s' "$NODE0_NAME" || printf '%s' "$NODE1_NAME"; }
node_cpus() { [[ "$1" == "0" ]] && printf '%s' "$NODE0_CPUS" || printf '%s' "$NODE1_CPUS"; }

configure_node() {
  local index="$1" home
  home="$(node_home "$index")"
  sed -i.capacity 's/^timeout_propose = .*/timeout_propose = "2s"/' "$home/config/config.toml"
  sed -i.capacity 's/^timeout_commit = .*/timeout_commit = "2s"/' "$home/config/config.toml"
  sed -i.capacity 's/^addr_book_strict = .*/addr_book_strict = false/' "$home/config/config.toml"
  sed -i.capacity 's/^allow_duplicate_ip = .*/allow_duplicate_ip = true/' "$home/config/config.toml"
  sed -i.capacity 's/^pprof_laddr = .*/pprof_laddr = ""/' "$home/config/config.toml"
  sed -i.capacity 's/^size = .*/size = 10000/' "$home/config/config.toml"
  sed -i.capacity 's/^max_txs_bytes = .*/max_txs_bytes = 1073741824/' "$home/config/config.toml"
  sed -i.capacity 's/^minimum-gas-prices = .*/minimum-gas-prices = "0peaka"/' "$home/config/app.toml"
  sed -i.capacity 's/^pruning = .*/pruning = "nothing"/' "$home/config/app.toml"
}

initialize_network() {
  log "initializing two ML-DSA-65 consensus validators"
  local index home genesis temporary address
  for index in 0 1; do
    home="$(node_home "$index")"
    dorad init "pqcauth-capacity-validator-$index" --chain-id "$CHAIN_ID" \
      --consensus-key-algo ml_dsa_65 --home "$home" \
      >"$LOG_DIR/node$index-init.json" 2>"$LOG_DIR/node$index-init.stderr"
    dorad keys add "validator-$index" --keyring-backend test --home "$home" --output json \
      >"$WORK_DIR/validator-$index.json"
    configure_node "$index"
  done

  genesis="$(node_home 0)/config/genesis.json"
  temporary="$genesis.capacity"
  jq --arg max_gas "$BLOCK_MAX_GAS" --arg max_bytes "$BLOCK_MAX_BYTES" '
    walk(if type == "string" and . == "stake" then "peaka" else . end)
    | .consensus_params.block.max_bytes = $max_bytes
    | .consensus_params.block.max_gas = $max_gas
    | .consensus_params.validator.pub_key_types = ["ed25519", "ml_dsa_65"]
    | .app_state.pqcauth.params.governance_safety_delay_blocks = "4"
    | .app_state.pqcauth.params.max_emergency_duration_blocks = "20"
    | .app_state.pqcauth.params.recovery_delay_blocks = "12"
  ' "$genesis" >"$temporary"
  mv "$temporary" "$genesis"

  for index in 0 1; do
    address="$(jq -r .address "$WORK_DIR/validator-$index.json")"
    dorad add-genesis-account "$address" 1000000000000000000000000peaka --home "$(node_home 0)"
  done
  cp "$genesis" "$(node_home 1)/config/genesis.json"
  for index in 0 1; do
    dorad gentx "validator-$index" 1000000000000000000000peaka --chain-id "$CHAIN_ID" \
      --keyring-backend test --home "$(node_home "$index")" \
      --moniker "pqcauth-capacity-validator-$index" \
      >"$LOG_DIR/node$index-gentx.json" 2>"$LOG_DIR/node$index-gentx.stderr"
    if [[ "$index" == "1" ]]; then
      find "$(node_home 1)/config/gentx" -type f -name '*.json' -exec cp '{}' "$(node_home 0)/config/gentx/" ';'
    fi
  done
  dorad collect-gentxs --home "$(node_home 0)" >"$LOG_DIR/collect-gentxs.log" 2>"$LOG_DIR/collect-gentxs.stderr"

  local recipient
  recipient="$(jq -r .address "$WORK_DIR/validator-0.json")"
  printf fixture-generation >"$PHASE_FILE"
  log "generating independent classic, hybrid, and native ML-DSA transactions"
  pqcload generate --out "$FIXTURE_DIR" --chain-id "$CHAIN_ID" --recipient "$recipient" \
    --classic-count "$CLASSIC_COUNT" --hybrid-count "$HYBRID_COUNT" --native-count "$NATIVE_COUNT" \
    --invalid-pqc-count "$INVALID_PQC_COUNT" --oversized-count "$OVERSIZED_COUNT" \
    --noncanonical-count "$NONCANONICAL_COUNT" --bad-sequence-count "$BAD_SEQUENCE_COUNT" \
    --classic-gas "$CLASSIC_GAS" --hybrid-gas "$HYBRID_GAS" --native-gas "$NATIVE_GAS" \
    >"$REPORT_DIR/fixture-manifest.json"

  jq --slurpfile patch "$FIXTURE_DIR/genesis-patch.json" --arg max_bytes "$BLOCK_MAX_BYTES" --arg max_gas "$BLOCK_MAX_GAS" '
    ($patch[0]) as $p
    | .app_state.auth.accounts += $p.auth_accounts
    | .app_state.bank.balances += $p.bank_balances
    | .app_state.pqcauth.params.network_id = $p.network_id_base64
    | .app_state.pqcauth.keys += $p.pqc_keys
    | .app_state.pqcauth.policies += $p.pqc_policies
    | .app_state.pqcauth.key_sequences += $p.pqc_key_sequences
    | .initial_height = ((.initial_height // 1) | tostring)
    | .consensus_params = {
        block:{max_bytes:$max_bytes,max_gas:$max_gas},
        evidence:{max_age_num_blocks:"100000",max_age_duration:"172800000000000",max_bytes:"1048576"},
        validator:{pub_key_types:["ed25519","ml_dsa_65"]},
        version:{app:"0"},
        abci:{vote_extensions_enable_height:"0"},
        authority:{authority:""}
      }
  ' "$genesis" >"$temporary"
  mv "$temporary" "$genesis"
  python3 "$SCRIPT_DIR/normalize_genesis_supply.py" "$genesis"
  dorad validate-genesis --home "$(node_home 0)" >"$REPORT_DIR/validate-genesis.log" 2>"$REPORT_DIR/validate-genesis.stderr"
  cp "$genesis" "$(node_home 1)/config/genesis.json"

  for index in 0 1; do
    dorad comet show-node-id --home "$(node_home "$index")" >"$WORK_DIR/node$index.id"
  done
  local peer0 peer1
  peer0="$(cat "$WORK_DIR/node0.id")@127.0.0.1:$(node_p2p_port 0)"
  peer1="$(cat "$WORK_DIR/node1.id")@127.0.0.1:$(node_p2p_port 1)"
  sed -i.capacity "s#^persistent_peers = .*#persistent_peers = \"$peer1\"#" "$(node_home 0)/config/config.toml"
  sed -i.capacity "s#^persistent_peers = .*#persistent_peers = \"$peer0\"#" "$(node_home 1)/config/config.toml"

  if [[ "$PROFILE" == "stress" ]]; then
    log "materializing paced transaction streams"
    python3 "$SCRIPT_DIR/build_stress_plan.py" --materialize \
      --plan "$REPORT_DIR/stress-plan.json" --fixtures "$FIXTURE_DIR" --output "$STREAM_DIR"
  fi
}

start_node() {
  local index="$1" name cpus
  name="$(container_name "$index")"
  cpus="$(node_cpus "$index")"
  docker rm -f "$name" >/dev/null 2>&1 || true
  docker run -d --name "$name" --network host \
    --cpuset-cpus "$cpus" --memory "$NODE_MEMORY" --memory-swap "$NODE_MEMORY" \
    --pids-limit 4096 --ulimit nofile=65536:65536 \
    -e "LD_LIBRARY_PATH=$BIN_DIR" -e GOMAXPROCS=8 \
    -v "$WORK_DIR:$WORK_DIR" -v "$BIN_DIR:$BIN_DIR:ro" \
    "$RUNTIME_IMAGE" "$BIN_DIR/dorad" start \
      --home "$(node_home "$index")" --minimum-gas-prices 0peaka \
      --rpc.laddr "tcp://127.0.0.1:$(node_rpc_port "$index")" \
      --p2p.laddr "tcp://127.0.0.1:$(node_p2p_port "$index")" \
      --address "tcp://127.0.0.1:$(node_abci_port "$index")" \
      --grpc.address "127.0.0.1:$(node_grpc_port "$index")" \
      >"$LOG_DIR/node$index-container-id.txt"
}

stop_node() {
  docker stop --time 20 "$(container_name "$1")" >/dev/null
}

wait_rpc() {
  local index="$1" deadline=$((SECONDS + 120))
  until curl -fsS --max-time 2 "$(node_rpc "$index")/status" >/dev/null 2>&1; do
    (( SECONDS < deadline )) || die "node$index RPC did not become ready"
    sleep 1
  done
}

height() {
  curl -fsS --max-time 3 "$(node_rpc "$1")/status" | jq -r '.result.sync_info.latest_block_height | tonumber'
}

wait_height() {
  local target="$1" index="${2:-0}" deadline=$((SECONDS + 180)) current=0
  while (( SECONDS < deadline )); do
    current="$(height "$index" 2>/dev/null || printf 0)"
    (( current >= target )) && return 0
    sleep 1
  done
  die "node$index did not reach height $target (last=$current)"
}

start_monitor() {
  : >"$REPORT_DIR/docker-stats.csv"
  printf 'timestamp_utc,phase,container,cpu_percent,memory_usage,memory_percent,network_io,block_io,pids\n' \
    >"$REPORT_DIR/docker-stats.csv"
  (
    while [[ ! -e "$MONITOR_STOP" ]]; do
      local_phase="$(cat "$PHASE_FILE" 2>/dev/null || printf setup)"
      timestamp="$(date -u +%FT%TZ)"
      docker stats --no-stream --format '{{.Name}},{{.CPUPerc}},{{.MemUsage}},{{.MemPerc}},{{.NetIO}},{{.BlockIO}},{{.PIDs}}' \
        "$NODE0_NAME" "$NODE1_NAME" 2>/dev/null \
        | while IFS= read -r line; do printf '%s,%s,%s\n' "$timestamp" "$local_phase" "$line"; done
      sleep 1
    done
  ) >>"$REPORT_DIR/docker-stats.csv" &
  MONITOR_PID=$!
}

run_mode() {
  local mode="$1" expected="$2" current start_height
  printf '%s' "$mode-preload" >"$PHASE_FILE"
  current="$(height 0)"
  stop_node 1
  sleep 3
  start_height="$(height 0)"
  [[ "$start_height" == "$current" || "$start_height" -le "$((current + 1))" ]] \
    || die "consensus did not halt after stopping node1"

  log "preloading $expected $mode transactions while two-validator consensus is halted"
  set +e
  pqcload broadcast --input "$FIXTURE_DIR/$mode.txs.jsonl" --rpc "$(node_rpc 0)" \
    --out "$REPORT_DIR/$mode-broadcast-results.jsonl" --concurrency "$BROADCAST_CONCURRENCY" \
    >"$REPORT_DIR/$mode-broadcast-summary.json"
  local broadcast_exit=$?
  set -e
  local accepted rejected
  accepted="$(jq -r .accepted "$REPORT_DIR/$mode-broadcast-summary.json")"
  rejected="$(jq -r .rejected "$REPORT_DIR/$mode-broadcast-summary.json")"
  [[ "$broadcast_exit" == "0" && "$accepted" == "$expected" && "$rejected" == "0" ]] \
    || die "$mode preload rejected transactions: accepted=$accepted rejected=$rejected"

  local mempool_count
  mempool_count="$(curl -fsS "$(node_rpc 0)/num_unconfirmed_txs" | jq -r '.result.n_txs | tonumber')"
  [[ "$mempool_count" == "$expected" ]] || die "$mode mempool count $mempool_count, expected $expected"
  printf '%s' "$mode-commit" >"$PHASE_FILE"
  start_node 1
  wait_rpc 1
  python3 "$SCRIPT_DIR/collect_blocks.py" --rpc "$(node_rpc 0)" --mode "$mode" \
    --start-height "$start_height" --expected "$expected" \
    --blocks-out "$REPORT_DIR/$mode-blocks.jsonl" --summary-out "$REPORT_DIR/$mode-block-summary.json" \
    >"$REPORT_DIR/$mode-block-summary.stdout.json"
  local failed_deliveries
  failed_deliveries="$(jq -r .failed_deliveries "$REPORT_DIR/$mode-block-summary.json")"
  [[ "$failed_deliveries" == "0" ]] \
    || die "$mode committed $failed_deliveries failed DeliverTx results"
  log "$mode complete: $(jq -c '{committed_transactions,nonempty_blocks,max_transactions_in_one_block,max_gas_used_in_one_block}' "$REPORT_DIR/$mode-block-summary.json")"
}

run_stress_phase() {
  local name="$1" expected="$2" rate="$3" start_height broadcast_exit accepted rejected timeout
  local observer_stop observer_pid observer_exit
  printf '%s' "$name" >"$PHASE_FILE"
  start_height="$(height 0)"
  observer_stop="$WORK_DIR/$name-observer.stop"
  timeout="$((STRESS_DURATION + 900))"
  python3 "$SCRIPT_DIR/collect_stress.py" watch --rpc "$(node_rpc 0)" \
    --start-height "$start_height" --stop-file "$observer_stop" \
    --blocks-out "$REPORT_DIR/$name-blocks.jsonl" --timeout "$timeout" \
    >"$REPORT_DIR/$name-observer.stdout" 2>"$REPORT_DIR/$name-observer.stderr" &
  observer_pid=$!
  log "running $name: expected=$expected, paced_rate=$rate tx/s"
  set +e
  pqcload broadcast --input "$STREAM_DIR/$name.txs.jsonl" --rpc "$(node_rpc 0)" \
    --out "$REPORT_DIR/$name-broadcast-results.jsonl" --concurrency "$BROADCAST_CONCURRENCY" \
    --rate "$rate" --expect accepted >"$REPORT_DIR/$name-broadcast-summary.json"
  broadcast_exit=$?
  touch "$observer_stop"
  wait "$observer_pid"; observer_exit=$?
  set -e
  accepted="$(jq -r .accepted "$REPORT_DIR/$name-broadcast-summary.json")"
  rejected="$(jq -r .rejected "$REPORT_DIR/$name-broadcast-summary.json")"
  [[ "$broadcast_exit" == "0" && "$accepted" == "$expected" && "$rejected" == "0" ]] \
    || die "$name broadcast failed: accepted=$accepted rejected=$rejected exit=$broadcast_exit"
  [[ "$observer_exit" == "0" ]] || die "$name live block observer failed: exit=$observer_exit"
  python3 "$SCRIPT_DIR/collect_stress.py" analyze --phase "$name" \
    --broadcast-results "$REPORT_DIR/$name-broadcast-results.jsonl" \
    --observations "$REPORT_DIR/$name-blocks.jsonl" --summary-out "$REPORT_DIR/$name-summary.json" \
    >"$REPORT_DIR/$name-summary.stdout.json"
  [[ "$(jq -r .failed_deliveries "$REPORT_DIR/$name-summary.json")" == "0" ]] \
    || die "$name committed failed DeliverTx results"
  log "$name complete: $(jq -c '{committed_transactions,committed_transactions_per_second,confirmation_latency_seconds,block_interval_seconds,consensus_rounds}' "$REPORT_DIR/$name-summary.json")"
}

run_adversarial_phase() {
  local valid_name attack_name valid_expected valid_rate attack_expected attack_rate start_height
  local valid_pid attack_pid valid_exit attack_exit valid_accepted valid_rejected attack_accepted attack_rejected
  local observer_stop observer_pid observer_exit
  valid_name="$(jq -r '.adversarial_phase.concurrent_valid_phase' "$REPORT_DIR/stress-plan.json")"
  attack_name="$(jq -r '.adversarial_phase.name' "$REPORT_DIR/stress-plan.json")"
  valid_expected="$(jq -r --arg name "$valid_name" '.valid_phases[] | select(.name==$name) | .total_transactions' "$REPORT_DIR/stress-plan.json")"
  valid_rate="$(jq -r --arg name "$valid_name" '.valid_phases[] | select(.name==$name) | .rate_per_second' "$REPORT_DIR/stress-plan.json")"
  attack_expected="$(jq -r '.adversarial_phase.total_transactions' "$REPORT_DIR/stress-plan.json")"
  attack_rate="$(jq -r '.adversarial_phase.rate_per_second' "$REPORT_DIR/stress-plan.json")"
  printf adversarial >"$PHASE_FILE"
  start_height="$(height 0)"
  observer_stop="$WORK_DIR/$valid_name-observer.stop"
  python3 "$SCRIPT_DIR/collect_stress.py" watch --rpc "$(node_rpc 0)" \
    --start-height "$start_height" --stop-file "$observer_stop" \
    --blocks-out "$REPORT_DIR/$valid_name-blocks.jsonl" --timeout "$((ADVERSARIAL_DURATION + 900))" \
    >"$REPORT_DIR/$valid_name-observer.stdout" 2>"$REPORT_DIR/$valid_name-observer.stderr" &
  observer_pid=$!
  log "running adversarial phase: valid=$valid_expected@$valid_rate tx/s, rejected=$attack_expected@$attack_rate tx/s"

  set +e
  pqcload broadcast --input "$STREAM_DIR/$attack_name.txs.jsonl" --rpc "$(node_rpc 0)" \
    --out "$REPORT_DIR/$attack_name-broadcast-results.jsonl" --concurrency "$BROADCAST_CONCURRENCY" \
    --rate "$attack_rate" --expect rejected >"$REPORT_DIR/$attack_name-broadcast-summary.json" &
  attack_pid=$!
  pqcload broadcast --input "$STREAM_DIR/$valid_name.txs.jsonl" --rpc "$(node_rpc 0)" \
    --out "$REPORT_DIR/$valid_name-broadcast-results.jsonl" --concurrency "$BROADCAST_CONCURRENCY" \
    --rate "$valid_rate" --expect accepted >"$REPORT_DIR/$valid_name-broadcast-summary.json" &
  valid_pid=$!
  wait "$valid_pid"; valid_exit=$?
  wait "$attack_pid"; attack_exit=$?
  touch "$observer_stop"
  wait "$observer_pid"; observer_exit=$?
  set -e

  valid_accepted="$(jq -r .accepted "$REPORT_DIR/$valid_name-broadcast-summary.json")"
  valid_rejected="$(jq -r .rejected "$REPORT_DIR/$valid_name-broadcast-summary.json")"
  attack_accepted="$(jq -r .accepted "$REPORT_DIR/$attack_name-broadcast-summary.json")"
  attack_rejected="$(jq -r .rejected "$REPORT_DIR/$attack_name-broadcast-summary.json")"
  [[ "$valid_exit" == "0" && "$valid_accepted" == "$valid_expected" && "$valid_rejected" == "0" ]] \
    || die "adversarial valid stream failed: accepted=$valid_accepted rejected=$valid_rejected exit=$valid_exit"
  [[ "$attack_exit" == "0" && "$attack_accepted" == "0" && "$attack_rejected" == "$attack_expected" ]] \
    || die "adversarial rejection stream failed: accepted=$attack_accepted rejected=$attack_rejected exit=$attack_exit"
  [[ "$observer_exit" == "0" ]] || die "adversarial live block observer failed: exit=$observer_exit"

  python3 "$SCRIPT_DIR/collect_stress.py" analyze --phase "$valid_name" \
    --broadcast-results "$REPORT_DIR/$valid_name-broadcast-results.jsonl" \
    --observations "$REPORT_DIR/$valid_name-blocks.jsonl" --summary-out "$REPORT_DIR/$valid_name-summary.json" \
    >"$REPORT_DIR/$valid_name-summary.stdout.json"
  [[ "$(jq -r .failed_deliveries "$REPORT_DIR/$valid_name-summary.json")" == "0" ]] \
    || die "adversarial valid stream committed failed DeliverTx results"
  log "adversarial phase complete: $(jq -c '{committed_transactions,confirmation_latency_seconds,block_interval_seconds,consensus_rounds}' "$REPORT_DIR/$valid_name-summary.json")"
}

write_environment_report() {
  {
    printf '{\n'
    printf '  "run_id": %s,\n' "$(jq -Rn --arg value "$RUN_ID" '$value')"
	printf '  "profile": %s,\n' "$(jq -Rn --arg value "$PROFILE" '$value')"
    printf '  "git_commit": %s,\n' "$(git -C "$REPO_ROOT" rev-parse HEAD | jq -R .)"
    printf '  "chain_id": %s,\n' "$(jq -Rn --arg value "$CHAIN_ID" '$value')"
    printf '  "runtime_image": %s,\n' "$(jq -Rn --arg value "$RUNTIME_IMAGE" '$value')"
    printf '  "node0_cpus": %s,\n' "$(jq -Rn --arg value "$NODE0_CPUS" '$value')"
    printf '  "node1_cpus": %s,\n' "$(jq -Rn --arg value "$NODE1_CPUS" '$value')"
    printf '  "node_memory": %s,\n' "$(jq -Rn --arg value "$NODE_MEMORY" '$value')"
    printf '  "load_cpus": %s,\n' "$(jq -Rn --arg value "$LOAD_CPUS" '$value')"
    printf '  "block_max_gas": %s,\n' "$BLOCK_MAX_GAS"
    printf '  "block_max_bytes": %s,\n' "$BLOCK_MAX_BYTES"
    printf '  "docker_version": %s,\n' "$(docker version --format '{{.Server.Version}}' | jq -R .)"
    printf '  "kernel": %s\n' "$(uname -a | jq -R .)"
    printf '}\n'
  } >"$REPORT_DIR/environment.json"
  docker inspect "$NODE0_NAME" "$NODE1_NAME" >"$REPORT_DIR/docker-inspect.json"
}

docker_build
printf gas-calibration >"$PHASE_FILE"
log "calibrating ML-DSA-65 verification gas on the constrained validator CPU set"
docker run --rm --cpuset-cpus "$NODE0_CPUS" --memory "$NODE_MEMORY" --memory-swap "$NODE_MEMORY" \
  -e "LD_LIBRARY_PATH=$BIN_DIR" -e GOMAXPROCS=8 \
  -v "$WORK_DIR:$WORK_DIR" -v "$BIN_DIR:$BIN_DIR:ro" "$RUNTIME_IMAGE" \
  "$BIN_DIR/pqcauth-gas-calibrate" --samples 20000 --message-bytes 4096 \
  --block-max-gas "$BLOCK_MAX_GAS" --block-time 2s --pqc-cpu-budget 0.25 --safety-factor 2 \
  >"$REPORT_DIR/gas-calibration.json"

initialize_network
printf startup >"$PHASE_FILE"
start_node 0
start_node 1
start_monitor
wait_rpc 0
wait_rpc 1
wait_height 3 0
write_environment_report
if [[ "$PROFILE" == "capacity" ]]; then
  run_mode classic "$CLASSIC_COUNT"
  run_mode hybrid "$HYBRID_COUNT"
  run_mode native "$NATIVE_COUNT"
else
  while IFS=$'\t' read -r phase expected rate; do
    [[ "$phase" == adversarial-valid-* ]] && continue
    run_stress_phase "$phase" "$expected" "$rate"
  done < <(jq -r '.valid_phases[] | [.name,.total_transactions,.rate_per_second] | @tsv' "$REPORT_DIR/stress-plan.json")
  run_adversarial_phase
fi

printf complete >"$PHASE_FILE"
touch "$MONITOR_STOP"
wait "$MONITOR_PID" || true
MONITOR_PID=""
if [[ "$PROFILE" == "capacity" ]]; then
  jq -s '{generated_at_utc:(now|todate),modes:map({key:.mode,value:.})|from_entries}' \
    "$REPORT_DIR/classic-block-summary.json" "$REPORT_DIR/hybrid-block-summary.json" "$REPORT_DIR/native-block-summary.json" \
    >"$REPORT_DIR/capacity-summary.json"
  log "benchmark complete: $REPORT_DIR/capacity-summary.json"
  cat "$REPORT_DIR/capacity-summary.json"
else
  summary_paths=()
  while IFS= read -r phase; do
    summary_paths+=("$REPORT_DIR/$phase-summary.json")
  done < <(jq -r '.valid_phases[].name' "$REPORT_DIR/stress-plan.json")
  jq -n --slurpfile plan "$REPORT_DIR/stress-plan.json" \
    --slurpfile summaries <(jq -s '.' "${summary_paths[@]}") \
    --slurpfile adversarial "$REPORT_DIR/adversarial-rejected-broadcast-summary.json" \
    '{generated_at_utc:(now|todate),plan:$plan[0],phases:$summaries[0],adversarial_rejections:$adversarial[0]}' \
    >"$REPORT_DIR/stress-summary.json"
  log "stress benchmark complete: $REPORT_DIR/stress-summary.json"
  cat "$REPORT_DIR/stress-summary.json"
fi
