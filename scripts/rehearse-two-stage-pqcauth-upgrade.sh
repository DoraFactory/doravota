#!/usr/bin/env bash

# Rehearses the production upgrade path on one isolated validator:
#
#   deployed v0.4.x -> sdk-v0.53-bridge -> v1.0.0 (SDK v0.55 + pqcauth)
#
# The script accepts prebuilt binaries so the bridge may live in a separate
# worktree. It preserves the test home and all transaction artifacts.

set -Eeuo pipefail
umask 077

OLD_BIN=""
BRIDGE_BIN=""
TARGET_BIN=""
WORK_DIR=""
CHAIN_ID="doravota-two-stage-rehearsal"
RPC_PORT=29657
P2P_PORT=29656
GRPC_PORT=29990
API_PORT=29317
TIMEOUT=180
NODE_PID=""
ACTIVE_BIN=""
HOME_DIR=""
RPC_URL=""
ADDRESS=""

usage() {
  printf '%s\n' \
    'Usage: scripts/rehearse-two-stage-pqcauth-upgrade.sh [options]' \
    '' \
    'Required:' \
    '  --old-bin FILE       Deployed v0.4.x dorad binary' \
    '  --bridge-bin FILE    SDK v0.53 / IBC-Go v10 bridge binary' \
    '  --target-bin FILE    SDK v0.55 / pqcauth target binary' \
    '' \
    'Options:' \
    '  --work-dir DIR       New artifact directory (must not exist)' \
    '  --chain-id ID        Isolated chain ID' \
    '  --rpc-port PORT      RPC port (default 29657)' \
    '  --p2p-port PORT      P2P port (default 29656)' \
    '  --grpc-port PORT     gRPC port (default 29990)' \
    '  --api-port PORT      API port (default 29317)' \
    '  --timeout SECONDS    Per phase timeout (default 180)'
}

log() { printf '[two-stage] %s\n' "$*" >&2; }
die() { printf '[two-stage] ERROR: %s\n' "$*" >&2; exit 1; }

sha256_file() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  else
    shasum -a 256 "$1" | awk '{print $1}'
  fi
}

stop_node() {
  if [[ -n "$NODE_PID" ]] && kill -0 "$NODE_PID" >/dev/null 2>&1; then
    kill "$NODE_PID" >/dev/null 2>&1 || true
    wait "$NODE_PID" >/dev/null 2>&1 || true
  fi
  NODE_PID=""
}

cleanup() {
  local status=$?
  stop_node
  if [[ -n "$WORK_DIR" && -d "$WORK_DIR" ]]; then
    log "artifacts preserved at $WORK_DIR"
  fi
  return "$status"
}
trap cleanup EXIT
trap 'exit 130' INT TERM

while [[ $# -gt 0 ]]; do
  case "$1" in
    --old-bin) OLD_BIN="$2"; shift 2 ;;
    --bridge-bin) BRIDGE_BIN="$2"; shift 2 ;;
    --target-bin) TARGET_BIN="$2"; shift 2 ;;
    --work-dir) WORK_DIR="$2"; shift 2 ;;
    --chain-id) CHAIN_ID="$2"; shift 2 ;;
    --rpc-port) RPC_PORT="$2"; shift 2 ;;
    --p2p-port) P2P_PORT="$2"; shift 2 ;;
    --grpc-port) GRPC_PORT="$2"; shift 2 ;;
    --api-port) API_PORT="$2"; shift 2 ;;
    --timeout) TIMEOUT="$2"; shift 2 ;;
    --help|-h) usage; exit 0 ;;
    *) die "unknown option: $1" ;;
  esac
done

for command in jq curl awk sed; do
  command -v "$command" >/dev/null 2>&1 || die "required command not found: $command"
done
for binary in "$OLD_BIN" "$BRIDGE_BIN" "$TARGET_BIN"; do
  [[ -x "$binary" ]] || die "binary is not executable: $binary"
done
if [[ -z "$WORK_DIR" ]]; then
  WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/doravota-two-stage.XXXXXX")"
else
  [[ ! -e "$WORK_DIR" ]] || die "work directory already exists: $WORK_DIR"
  mkdir -p "$WORK_DIR"
fi
WORK_DIR="$(cd "$WORK_DIR" && pwd -P)"
HOME_DIR="$WORK_DIR/home"
RPC_URL="tcp://127.0.0.1:$RPC_PORT"
mkdir -p "$WORK_DIR/logs" "$WORK_DIR/tx" "$WORK_DIR/pqc" "$WORK_DIR/report"

for entry in "old:$OLD_BIN" "bridge:$BRIDGE_BIN" "target:$TARGET_BIN"; do
  label="${entry%%:*}"
  binary="${entry#*:}"
  "$binary" version --long >"$WORK_DIR/report/$label-version.txt"
done
jq -n \
  --arg old_path "$OLD_BIN" --arg old_sha256 "$(sha256_file "$OLD_BIN")" \
  --arg bridge_path "$BRIDGE_BIN" --arg bridge_sha256 "$(sha256_file "$BRIDGE_BIN")" \
  --arg target_path "$TARGET_BIN" --arg target_sha256 "$(sha256_file "$TARGET_BIN")" \
  '{old:{path:$old_path,sha256:$old_sha256},bridge:{path:$bridge_path,sha256:$bridge_sha256},target:{path:$target_path,sha256:$target_sha256}}' \
  >"$WORK_DIR/report/binaries.json"

rpc_height() {
  curl -fsS --max-time 3 "http://127.0.0.1:$RPC_PORT/status" \
    | jq -r '.result.sync_info.latest_block_height | tonumber'
}

wait_for_rpc() {
  local deadline=$(( $(date +%s) + TIMEOUT ))
  while (( $(date +%s) < deadline )); do
    if rpc_height >/dev/null 2>&1; then return 0; fi
    if [[ -n "$NODE_PID" ]] && ! kill -0 "$NODE_PID" >/dev/null 2>&1; then
      die "node exited before RPC became ready; inspect $WORK_DIR/logs"
    fi
    sleep 1
  done
  die "RPC did not become ready"
}

wait_for_height() {
  local expected="$1"
  local deadline=$(( $(date +%s) + TIMEOUT ))
  while (( $(date +%s) < deadline )); do
    local current
    current="$(rpc_height 2>/dev/null || printf 0)"
    if (( current >= expected )); then return 0; fi
    sleep 1
  done
  die "height $expected was not reached"
}

start_node() {
  local binary="$1"
  local label="$2"
  ACTIVE_BIN="$binary"
  "$binary" start \
    --home "$HOME_DIR" \
    --rpc.laddr "tcp://127.0.0.1:$RPC_PORT" \
    --p2p.laddr "tcp://127.0.0.1:$P2P_PORT" \
    --grpc.address "127.0.0.1:$GRPC_PORT" \
    --api.address "tcp://127.0.0.1:$API_PORT" \
    --minimum-gas-prices 100000000000peaka \
    --log_level info >"$WORK_DIR/logs/$label.log" 2>&1 &
  NODE_PID=$!
  wait_for_rpc
}

wait_for_halt() {
  local label="$1"
  local expected_height="$2"
  local deadline=$(( $(date +%s) + TIMEOUT ))
  while (( $(date +%s) < deadline )); do
    if ! kill -0 "$NODE_PID" >/dev/null 2>&1; then
      set +e
      wait "$NODE_PID"
      local exit_code=$?
      set -e
      printf '%s\n' "$exit_code" >"$WORK_DIR/report/$label-exit-code.txt"
      NODE_PID=""
      return 0
    fi
    local current
    current="$(rpc_height 2>/dev/null || printf 0)"
    if (( current >= expected_height )) && grep -Eq 'UPGRADE .* NEEDED' "$WORK_DIR/logs/$label.log"; then
      printf '%s\n' "upgrade halt detected at height $current; process stopped by rehearsal harness" \
        >"$WORK_DIR/report/$label-exit-code.txt"
      stop_node
      return 0
    fi
    sleep 1
  done
  die "$label did not halt for its scheduled upgrade"
}

wait_for_tx() {
  local binary="$1"
  local hash="$2"
  local output="$3"
  local deadline=$(( $(date +%s) + TIMEOUT ))
  while (( $(date +%s) < deadline )); do
    if "$binary" query tx "$hash" --node "$RPC_URL" --output json >"$output" 2>"$output.stderr"; then
      [[ "$(jq -r '.code // 0' "$output")" == "0" ]] || die "transaction $hash failed"
      return 0
    fi
    sleep 1
  done
  die "transaction $hash was not committed"
}

broadcast() {
  local label="$1"
  local binary="$2"
  shift 2
  local response="$WORK_DIR/tx/$label-broadcast.json"
  "$binary" "$@" \
    --home "$HOME_DIR" --keyring-backend test --chain-id "$CHAIN_ID" \
    --node "$RPC_URL" --broadcast-mode sync --output json -y >"$response"
  [[ "$(jq -r '.code // 0' "$response")" == "0" ]] || die "$label failed CheckTx"
  local hash
  hash="$(jq -r '.txhash' "$response")"
  wait_for_tx "$binary" "$hash" "$WORK_DIR/tx/$label.json"
  printf '%s' "$hash"
}

wait_for_proposal_passed() {
  local binary="$1"
  local proposal_id="$2"
  local label="$3"
  local deadline=$(( $(date +%s) + TIMEOUT ))
  while (( $(date +%s) < deadline )); do
    if "$binary" query gov proposal "$proposal_id" --node "$RPC_URL" --output json \
      >"$WORK_DIR/report/$label-proposal.json" 2>/dev/null; then
      local status
      status="$(jq -r '.proposal.status // .status // empty' "$WORK_DIR/report/$label-proposal.json")"
      if [[ "$status" == "PROPOSAL_STATUS_PASSED" ]]; then return 0; fi
      if [[ "$status" == "PROPOSAL_STATUS_REJECTED" || "$status" == "PROPOSAL_STATUS_FAILED" ]]; then
        die "$label proposal ended as $status"
      fi
    fi
    sleep 1
  done
  die "$label proposal did not pass"
}

log "initializing disposable v0.4.x chain"
"$OLD_BIN" init validator --chain-id "$CHAIN_ID" --home "$HOME_DIR" >"$WORK_DIR/logs/init.json"
"$OLD_BIN" keys add validator --home "$HOME_DIR" --keyring-backend test --output json \
  >"$WORK_DIR/report/validator-key.json"
ADDRESS="$(jq -r '.address' "$WORK_DIR/report/validator-key.json")"
"$OLD_BIN" add-genesis-account "$ADDRESS" 1000000000000000000000000000peaka --home "$HOME_DIR"
"$OLD_BIN" gentx validator 1000000000000000000000000peaka \
  --home "$HOME_DIR" --keyring-backend test --chain-id "$CHAIN_ID" >"$WORK_DIR/logs/gentx.json"
"$OLD_BIN" collect-gentxs --home "$HOME_DIR" >"$WORK_DIR/logs/collect-gentxs.txt"
jq '
  .consensus_params.block.max_gas = "100000000"
  | .app_state.gov.deposit_params.min_deposit = [{"denom":"peaka","amount":"1000000"}]
  | .app_state.gov.deposit_params.max_deposit_period = "10s"
  | .app_state.gov.voting_params.voting_period = "10s"
  | .app_state.gov.params.min_deposit = [{"denom":"peaka","amount":"1000000"}]
  | .app_state.gov.params.max_deposit_period = "10s"
  | .app_state.gov.params.voting_period = "10s"
' "$HOME_DIR/config/genesis.json" >"$HOME_DIR/config/genesis.rehearsal.json"
mv "$HOME_DIR/config/genesis.rehearsal.json" "$HOME_DIR/config/genesis.json"
sed -i.bak 's/^timeout_commit = .*/timeout_commit = "1s"/' "$HOME_DIR/config/config.toml"
sed -i.bak 's/^pprof_laddr = .*/pprof_laddr = ""/' "$HOME_DIR/config/config.toml"
rm -f "$HOME_DIR/config/config.toml.bak"

start_node "$OLD_BIN" old
wait_for_height 2

BRIDGE_HEIGHT=$(( $(rpc_height) + 30 ))
log "scheduling sdk-v0.53-bridge at height $BRIDGE_HEIGHT"
BRIDGE_PROPOSAL_HASH="$(broadcast bridge-proposal "$OLD_BIN" \
  tx gov submit-legacy-proposal software-upgrade sdk-v0.53-bridge \
  --title 'SDK v0.53 bridge' --description 'Bridge SDK, IBC and Wasmd migrations' \
  --upgrade-height "$BRIDGE_HEIGHT" --upgrade-info '{}' --no-validate --deposit 1000000peaka \
  --from validator --gas 500000 --fees 60000000000000000peaka)"
BRIDGE_PROPOSAL_ID="$(jq -r '[.logs[]?.events[]? | select(.type=="submit_proposal") | .attributes[]? | select(.key=="proposal_id") | .value][0]' "$WORK_DIR/tx/bridge-proposal.json")"
BRIDGE_VOTE_HASH="$(broadcast bridge-vote "$OLD_BIN" tx gov vote "$BRIDGE_PROPOSAL_ID" yes \
  --from validator --gas 200000 --fees 30000000000000000peaka)"
wait_for_proposal_passed "$OLD_BIN" "$BRIDGE_PROPOSAL_ID" bridge
wait_for_halt old "$BRIDGE_HEIGHT"

log "starting SDK v0.53 / IBC-Go v10 bridge"
start_node "$BRIDGE_BIN" bridge
wait_for_height $((BRIDGE_HEIGHT + 2))
"$BRIDGE_BIN" query upgrade applied sdk-v0.53-bridge --node "$RPC_URL" --output json \
  >"$WORK_DIR/report/bridge-applied.json"
"$BRIDGE_BIN" query upgrade module-versions --node "$RPC_URL" --output json \
  >"$WORK_DIR/report/bridge-module-versions.json"
BRIDGE_CLASSIC_HASH="$(broadcast bridge-classic "$BRIDGE_BIN" tx bank send "$ADDRESS" "$ADDRESS" 1peaka \
  --from validator --gas 200000 --fees 30000000000000000peaka)"

TARGET_HEIGHT=$(( $(rpc_height) + 35 ))
GOV_AUTHORITY="dora10d07y265gmmuvt4z0w9aw880jnsr700jeckgp9"
jq -n \
  --arg authority "$GOV_AUTHORITY" \
  --arg height "$TARGET_HEIGHT" \
  '{messages:[{"@type":"/cosmos.upgrade.v1beta1.MsgSoftwareUpgrade",authority:$authority,plan:{name:"v1.0.0",time:"0001-01-01T00:00:00Z",height:$height,info:"{}",upgraded_client_state:null}}],metadata:"",deposit:"1000000peaka",title:"v1.0.0 PQC authentication",summary:"Add pqcauth and sponsor stores after the SDK v0.53 bridge",expedited:false}' \
  >"$WORK_DIR/target-upgrade-proposal.json"
log "scheduling v1.0.0 at height $TARGET_HEIGHT"
TARGET_PROPOSAL_HASH="$(broadcast target-proposal "$BRIDGE_BIN" \
  tx gov submit-proposal "$WORK_DIR/target-upgrade-proposal.json" \
  --from validator --gas 500000 --fees 60000000000000000peaka)"
TARGET_PROPOSAL_ID="$(jq -r '[.logs[]?.events[]? | select(.type=="submit_proposal") | .attributes[]? | select(.key=="proposal_id") | .value][0]' "$WORK_DIR/tx/target-proposal.json")"
if [[ -z "$TARGET_PROPOSAL_ID" || "$TARGET_PROPOSAL_ID" == "null" ]]; then
  TARGET_PROPOSAL_ID="$(jq -r '[.events[]? | select(.type=="submit_proposal") | .attributes[]? | select(.key=="proposal_id") | .value][0]' "$WORK_DIR/tx/target-proposal.json")"
fi
TARGET_VOTE_HASH="$(broadcast target-vote "$BRIDGE_BIN" tx gov vote "$TARGET_PROPOSAL_ID" yes \
  --from validator --gas 200000 --fees 30000000000000000peaka)"
wait_for_proposal_passed "$BRIDGE_BIN" "$TARGET_PROPOSAL_ID" target
wait_for_halt bridge "$TARGET_HEIGHT"

log "starting SDK v0.55 + pqcauth target"
start_node "$TARGET_BIN" target
wait_for_height $((TARGET_HEIGHT + 2))
"$TARGET_BIN" query upgrade applied v1.0.0 --node "$RPC_URL" --output json \
  >"$WORK_DIR/report/target-applied.json"
"$TARGET_BIN" query pqcauth params --node "$RPC_URL" --output json \
  >"$WORK_DIR/report/pqcauth-params.json"
"$TARGET_BIN" query consensus params --node "$RPC_URL" --output json \
  >"$WORK_DIR/report/consensus-params.json"
jq -e '
  .params.block != null
  and .params.evidence != null
  and .params.validator != null
  and (.params.block.max_bytes | tonumber) > 0
  and (.params.block.max_gas | tonumber) > 0
' "$WORK_DIR/report/consensus-params.json" >/dev/null \
  || die "consensus parameters were not fully migrated"
TARGET_CLASSIC_HASH="$(broadcast target-classic "$TARGET_BIN" tx bank send "$ADDRESS" "$ADDRESS" 1peaka \
  --from validator --gas 200000 --fees 30000000000000000peaka)"

NETWORK_ID="$(jq -r '.params.network_id' "$WORK_DIR/report/pqcauth-params.json")"
"$TARGET_BIN" tx pqcauth keygen "$WORK_DIR/pqc/signing1.mldsa65" >"$WORK_DIR/pqc/signing1.json"
"$TARGET_BIN" tx pqcauth keygen "$WORK_DIR/pqc/recovery2.mldsa65" >"$WORK_DIR/pqc/recovery2.json"
"$TARGET_BIN" tx pqcauth create-key-proof "$WORK_DIR/pqc/signing1.mldsa65" "$ADDRESS" 1 signing register-signing \
  --network-id-base64 "$NETWORK_ID" --policy-version 0 --chain-id "$CHAIN_ID" >"$WORK_DIR/pqc/signing1-proof.json"
"$TARGET_BIN" tx pqcauth create-key-proof "$WORK_DIR/pqc/recovery2.mldsa65" "$ADDRESS" 2 recovery register-recovery \
  --network-id-base64 "$NETWORK_ID" --policy-version 0 --chain-id "$CHAIN_ID" >"$WORK_DIR/pqc/recovery2-proof.json"
REGISTER_HASH="$(broadcast pqc-register "$TARGET_BIN" tx pqcauth register-key 1 \
  "$(jq -r '.public_key_base64' "$WORK_DIR/pqc/signing1.json")" \
  "$(jq -r '.proof_base64' "$WORK_DIR/pqc/signing1-proof.json")" \
  --recovery-public-key-base64 "$(jq -r '.public_key_base64' "$WORK_DIR/pqc/recovery2.json")" \
  --recovery-proof-base64 "$(jq -r '.proof_base64' "$WORK_DIR/pqc/recovery2-proof.json")" \
  --self-enforce=true --from validator --gas 1200000 --fees 150000000000000000peaka)"
wait_for_height $(( $(jq -r '.height|tonumber' "$WORK_DIR/tx/pqc-register.json") + 1 ))
"$TARGET_BIN" query pqcauth account "$ADDRESS" --node "$RPC_URL" --output json \
  >"$WORK_DIR/report/pqcauth-account.json"
jq -e '.policy.current_signing_key_id == "1" and .policy.recovery_key_id == "2" and .policy.self_enforced == true' \
  "$WORK_DIR/report/pqcauth-account.json" >/dev/null || die "PQC policy did not activate at H+1"

set +e
"$TARGET_BIN" tx bank send "$ADDRESS" "$ADDRESS" 1peaka \
  --from validator --home "$HOME_DIR" --keyring-backend test --chain-id "$CHAIN_ID" \
  --node "$RPC_URL" --gas 500000 --fees 60000000000000000peaka \
  --broadcast-mode sync --output json -y >"$WORK_DIR/tx/classic-rejected.json" 2>"$WORK_DIR/tx/classic-rejected.stderr"
set -e
jq -e '.codespace == "pqcauth" and .code == 11' "$WORK_DIR/tx/classic-rejected.json" >/dev/null \
  || die "self-enforced account did not reject classic-only authorization"
CLASSIC_REJECTED_HASH="$(jq -r '.txhash' "$WORK_DIR/tx/classic-rejected.json")"

"$TARGET_BIN" tx bank send "$ADDRESS" "$ADDRESS" 2peaka \
  --from validator --home "$HOME_DIR" --keyring-backend test --chain-id "$CHAIN_ID" \
  --node "$RPC_URL" --gas 800000 --fees 100000000000000000peaka \
  --generate-only --output json >"$WORK_DIR/pqc/bank.unsigned.json"
"$TARGET_BIN" tx pqcauth prepare-bundle "$WORK_DIR/pqc/bank.unsigned.json" "$WORK_DIR/pqc/bank.prepared.json" \
  --from validator --home "$HOME_DIR" --keyring-backend test --chain-id "$CHAIN_ID" \
  --node "$RPC_URL" --output json -y >"$WORK_DIR/pqc/bank.prepare-result.json"
"$TARGET_BIN" tx pqcauth sign-bundle "$WORK_DIR/pqc/bank.prepared.json" \
  "$WORK_DIR/pqc/signing1.mldsa65" "$WORK_DIR/pqc/bank.signed.json" --home "$HOME_DIR" -y \
  >"$WORK_DIR/pqc/bank.sign-result.json"
PQC_BANK_HASH="$(broadcast pqc-bank "$TARGET_BIN" tx pqcauth broadcast-bundle "$WORK_DIR/pqc/bank.signed.json" \
  --from validator)"

HEIGHT_BEFORE_RESTART="$(rpc_height)"
stop_node
"$TARGET_BIN" export --home "$HOME_DIR" --height -1 >"$WORK_DIR/report/export.json"
jq -e '.app_state.pqcauth.params.allowed_algorithms[0] == "ALGORITHM_ML_DSA_65"' \
  "$WORK_DIR/report/export.json" >/dev/null || die "export omitted pqcauth genesis state"
jq -e '
  .consensus.params.block != null
  and .consensus.params.evidence != null
  and .consensus.params.validator != null
' "$WORK_DIR/report/export.json" >/dev/null || die "export omitted complete consensus parameters"
start_node "$TARGET_BIN" target-restart
wait_for_height $((HEIGHT_BEFORE_RESTART + 2))
HEIGHT_AFTER_RESTART="$(rpc_height)"

jq -n \
  --arg chain_id "$CHAIN_ID" \
  --arg work_dir "$WORK_DIR" \
  --arg address "$ADDRESS" \
  --argjson bridge_height "$BRIDGE_HEIGHT" \
  --argjson target_height "$TARGET_HEIGHT" \
  --argjson restart_height "$HEIGHT_AFTER_RESTART" \
  --arg bridge_proposal "$BRIDGE_PROPOSAL_HASH" \
  --arg bridge_vote "$BRIDGE_VOTE_HASH" \
  --arg bridge_classic "$BRIDGE_CLASSIC_HASH" \
  --arg target_proposal "$TARGET_PROPOSAL_HASH" \
  --arg target_vote "$TARGET_VOTE_HASH" \
  --arg target_classic "$TARGET_CLASSIC_HASH" \
  --arg register "$REGISTER_HASH" \
  --arg classic_rejected "$CLASSIC_REJECTED_HASH" \
  --arg pqc_bank "$PQC_BANK_HASH" \
  '{result:"PASS",chain_id:$chain_id,work_dir:$work_dir,address:$address,heights:{bridge:$bridge_height,target:$target_height,after_restart:$restart_height},transactions:{bridge_proposal:$bridge_proposal,bridge_vote:$bridge_vote,bridge_classic:$bridge_classic,target_proposal:$target_proposal,target_vote:$target_vote,target_classic:$target_classic,pqc_register:$register,classic_rejected:$classic_rejected,pqc_bank:$pqc_bank},checks:["v0.4.x governance halt","SDK v0.53 cumulative migrations","classic transaction after bridge","v1.0.0 governance halt","SDK v0.55 target migrations","complete consensus-parameter migration","classic transaction after target","ML-DSA signing and recovery registration","H+1 activation","classic-only rejection after self-enforcement","hybrid classic plus ML-DSA transaction","state export","target restart"]}' \
  >"$WORK_DIR/report/summary.json"

log "PASS: two-stage upgrade, PQC lifecycle, export and restart all succeeded"
jq . "$WORK_DIR/report/summary.json"
