#!/usr/bin/env bash
set -Eeuo pipefail

DORAD_DIR="${DORAD_DIR:-/root/doravota-pqcauth-authz-feegrant-build-20260828}"
DORAD="${DORAD:-${DORAD_DIR}/dorad}"
WORK_ROOT="${WORK_ROOT:-/root/doravota-pqc-ibc-real}"
SOURCE_ROOT="${SOURCE_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)}"
GO_IMAGE="${GO_IMAGE:-golang:1.26.5-bookworm}"
RLY_IMAGE="${RLY_IMAGE:-ghcr.io/cosmos/relayer:latest}"
NODE_CPU="${NODE_CPU:-10}"
NODE_MEMORY="${NODE_MEMORY:-30g}"
KEEP_RUNNING="${KEEP_RUNNING:-1}"
DENOM="${DENOM:-peaka}"
RUN_ID="${RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
WORK_DIR="${WORK_ROOT}/${RUN_ID}"
BIN_DIR="${WORK_DIR}/bin"
ARTIFACTS="${WORK_DIR}/artifacts"
SECRETS="${WORK_DIR}/secrets"
RLY_HOME="${WORK_DIR}/rly"
CHAIN_A_HOME="${WORK_DIR}/chain-a"
CHAIN_B_HOME="${WORK_DIR}/chain-b"
ROTATE_A_HOME="${WORK_DIR}/rotate-a"
ROTATE_B_HOME="${WORK_DIR}/rotate-b"
CHAIN_A_ID="dora-pqc-ibc-a-1"
CHAIN_B_ID="dora-pqc-ibc-b-1"
CHAIN_A_RPC="http://127.0.0.1:26657"
CHAIN_B_RPC="http://127.0.0.1:36657"
CHAIN_A_GRPC="127.0.0.1:9090"
CHAIN_B_GRPC="127.0.0.1:9190"
CONTAINER_A="dora-pqc-ibc-a-${RUN_ID}"
CONTAINER_B="dora-pqc-ibc-b-${RUN_ID}"
RELAYER_KEY="pqc-relayer"
RLY_KEY="rly-relayer"
VALIDATOR_KEY="validator"

log() { printf '[pqc-ibc-real] %s\n' "$*" >&2; }
fail() { log "ERROR: $*"; exit 1; }

cleanup_on_error() {
  local code=$?
  if (( code != 0 )); then
    log "failed; preserving ${WORK_DIR}"
    docker logs --tail 200 "${CONTAINER_A}" >"${ARTIFACTS}/chain-a.failure.log" 2>&1 || true
    docker logs --tail 200 "${CONTAINER_B}" >"${ARTIFACTS}/chain-b.failure.log" 2>&1 || true
    docker rm -f "${CONTAINER_A}" "${CONTAINER_B}" >/dev/null 2>&1 || true
  fi
  exit "${code}"
}
trap cleanup_on_error EXIT

[[ -x "${DORAD}" ]] || fail "dorad not executable: ${DORAD}"
[[ -f "${DORAD_DIR}/libwasmvm.x86_64.so" ]] || fail "missing wasmvm shared library in ${DORAD_DIR}"
command -v docker >/dev/null || fail "docker is required"
command -v jq >/dev/null || fail "jq is required"
command -v curl >/dev/null || fail "curl is required"
[[ ! -e "${WORK_DIR}" ]] || fail "work directory already exists: ${WORK_DIR}"

mkdir -p "${BIN_DIR}" "${ARTIFACTS}" "${SECRETS}" "${RLY_HOME}"
chmod 700 "${SECRETS}" "${RLY_HOME}"
cp "${DORAD}" "${BIN_DIR}/dorad"
cp "${DORAD_DIR}/libwasmvm.x86_64.so" "${BIN_DIR}/libwasmvm.x86_64.so"

dora() { LD_LIBRARY_PATH="${BIN_DIR}" "${BIN_DIR}/dorad" "$@"; }
rly() {
  docker run --rm --network host --user 0:0 \
    --entrypoint rly \
    -v "${RLY_HOME}:/root/.relayer" \
    -v "${WORK_DIR}:${WORK_DIR}" \
    "${RLY_IMAGE}" --home /root/.relayer "$@"
}

build_relayer() {
  log "building current-SDK PQC IBC relayer"
  docker run --rm \
    -v "${SOURCE_ROOT}:/src:ro" \
    -v "${BIN_DIR}:/out" \
    -v doravota-pqc-ibc-go-mod:/go/pkg/mod \
    -v doravota-pqc-ibc-go-build:/root/.cache/go-build \
    -w /src "${GO_IMAGE}" \
    bash -c 'CGO_ENABLED=1 go build -trimpath -o /out/pqcibc-relayer ./cmd/pqcibc-relayer'
}

configure_files() {
  local home=$1 rpc=$2 p2p=$3 grpc=$4 api=$5 pprof=$6
  sed -i -E \
    -e "s#tcp://127.0.0.1:26657#tcp://0.0.0.0:${rpc}#" \
    -e "s#tcp://0.0.0.0:26656#tcp://0.0.0.0:${p2p}#" \
    -e "s#pprof_laddr = \"localhost:6060\"#pprof_laddr = \"localhost:${pprof}\"#" \
    -e 's#timeout_commit = "5s"#timeout_commit = "1s"#' \
    -e 's#timeout_propose = "3s"#timeout_propose = "1s"#' \
    "${home}/config/config.toml"
  sed -i -E \
    -e 's#^minimum-gas-prices = .*$#minimum-gas-prices = "0peaka"#' \
    -e "s#tcp://localhost:1317#tcp://0.0.0.0:${api}#" \
    -e "s#localhost:9090#0.0.0.0:${grpc}#" \
    "${home}/config/app.toml"
}

init_chain() {
  local label=$1 chain_id=$2 home=$3 rpc=$4 p2p=$5 grpc=$6 api=$7 pprof=$8
  log "initializing ${label} (${chain_id})"
  dora init "${label}" --chain-id "${chain_id}" --default-denom "${DENOM}" --home "${home}" >"${ARTIFACTS}/${label}.init.log" 2>&1
  dora keys add "${VALIDATOR_KEY}" --keyring-backend test --home "${home}" --output json >"${SECRETS}/${label}.validator.json"
  dora keys add "${RELAYER_KEY}" --key-type ml_dsa_65 --keyring-backend test --home "${home}" --output json >"${SECRETS}/${label}.pqc-relayer.json"
  dora keys add "${RLY_KEY}" --keyring-backend test --home "${home}" --output json >"${SECRETS}/${label}.rly-relayer.json"
  chmod 600 "${SECRETS}/${label}."*.json

  local validator_addr relayer_addr rly_addr
  validator_addr=$(jq -r .address "${SECRETS}/${label}.validator.json")
  relayer_addr=$(jq -r .address "${SECRETS}/${label}.pqc-relayer.json")
  rly_addr=$(jq -r .address "${SECRETS}/${label}.rly-relayer.json")
  dora genesis add-genesis-account "${validator_addr}" "100000000000000000000000${DENOM}" --home "${home}"
  dora genesis add-genesis-account "${relayer_addr}" "10000000000000000000000${DENOM}" --home "${home}"
  dora genesis add-genesis-account "${rly_addr}" "10000000000000000000000${DENOM}" --home "${home}"
  dora genesis gentx "${VALIDATOR_KEY}" "1000000000000000000${DENOM}" \
    --chain-id "${chain_id}" --home "${home}" --keyring-backend test --moniker "${label}" >/dev/null 2>&1
  dora genesis collect-gentxs --home "${home}" >/dev/null 2>&1

  local tmp="${home}/config/genesis.json.tmp"
  # CometBFT v0.40's GenesisDoc uses protobuf JSON for int64 fields. The SDK
  # init command currently emits initial_height as a JSON number, so normalize
  # it before the first node start.
  jq '.initial_height = ((.initial_height // 1) | tostring)
      | .app_state.gov.params.min_deposit = [{"denom":"peaka","amount":"1000000"}]
      | .app_state.gov.params.max_deposit_period = "15s"
      | .app_state.gov.params.voting_period = "15s"
      | .app_state.gov.params.expedited_voting_period = "5s"' \
    "${home}/config/genesis.json" >"${tmp}"
  mv "${tmp}" "${home}/config/genesis.json"
  dora genesis validate-genesis --home "${home}" >/dev/null
  configure_files "${home}" "${rpc}" "${p2p}" "${grpc}" "${api}" "${pprof}"
}

start_node() {
  local name=$1 home=$2
  docker rm -f "${name}" >/dev/null 2>&1 || true
  docker run -d --name "${name}" --network host \
    --cpus "${NODE_CPU}" --memory "${NODE_MEMORY}" \
    -e LD_LIBRARY_PATH=/runtime \
    -v "${BIN_DIR}:/runtime:ro" -v "${home}:${home}" \
    "${GO_IMAGE}" /runtime/dorad start --home "${home}" --log_level info >/dev/null
}

wait_rpc() {
  local rpc=$1 label=$2
  for _ in $(seq 1 120); do
    if curl -fsS "${rpc}/status" 2>/dev/null | jq -e '.result.sync_info.catching_up == false' >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  fail "${label} RPC did not become ready"
}

height() { curl -fsS "$1/status" | jq -r '.result.sync_info.latest_block_height | tonumber'; }

wait_height() {
  local rpc=$1 target=$2 label=$3
  for _ in $(seq 1 180); do
    local current
    current=$(height "${rpc}" 2>/dev/null || printf 0)
    if (( current >= target )); then return 0; fi
    sleep 1
  done
  fail "${label} did not reach height ${target}"
}

wait_tx() {
  local rpc=$1 hash=$2 output=$3
  for _ in $(seq 1 90); do
    if curl -fsS "${rpc}/tx?hash=0x${hash}&prove=false" >"${output}.tmp" 2>/dev/null && \
       jq -e '.result.tx_result' "${output}.tmp" >/dev/null 2>&1; then
      mv "${output}.tmp" "${output}"
      [[ $(jq -r '.result.tx_result.code // 0' "${output}") == 0 ]] || fail "tx ${hash} failed: $(jq -r '.result.tx_result.log' "${output}")"
      return 0
    fi
    sleep 1
  done
  fail "transaction ${hash} was not committed"
}

broadcast_cli() {
  local label=$1 rpc=$2 output=$3
  shift 3
  dora "$@" --node "${rpc}" --broadcast-mode sync --output json >"${output}.broadcast.json"
  local code hash
  code=$(jq -r '.code // 0' "${output}.broadcast.json")
  hash=$(jq -r '.txhash // .hash // empty' "${output}.broadcast.json")
  [[ "${code}" == 0 && -n "${hash}" ]] || fail "${label} broadcast failed: $(cat "${output}.broadcast.json")"
  wait_tx "${rpc}" "${hash}" "${output}.commit.json"
  printf '%s' "${hash}"
}

write_rly_chain() {
  local file=$1 key=$2 chain_id=$3 rpc=$4 grpc=$5
  jq -n \
    --arg key "${key}" --arg chain "${chain_id}" --arg rpc "${rpc}" --arg grpc "http://${grpc}" --arg denom "${DENOM}" \
    '{type:"cosmos",value:{key:$key,"chain-id":$chain,"rpc-addr":$rpc,"grpc-addr":$grpc,"account-prefix":"dora","keyring-backend":"test","gas-adjustment":1.5,"gas-prices":("0.001"+$denom),debug:true,timeout:"30s","output-format":"json","sign-mode":"direct","extra-codecs":[]}}' >"${file}"
}

setup_ibc() {
  log "creating pre-rotation IBC clients, connection and ICS20 channel"
  rly config init >/dev/null 2>&1 || true
  write_rly_chain "${WORK_DIR}/rly-chain-a.json" "${RLY_KEY}" "${CHAIN_A_ID}" "${CHAIN_A_RPC}" "${CHAIN_A_GRPC}"
  write_rly_chain "${WORK_DIR}/rly-chain-b.json" "${RLY_KEY}" "${CHAIN_B_ID}" "${CHAIN_B_RPC}" "${CHAIN_B_GRPC}"
  rly chains add --file "${WORK_DIR}/rly-chain-a.json" "${CHAIN_A_ID}" >"${ARTIFACTS}/rly-add-a.log"
  rly chains add --file "${WORK_DIR}/rly-chain-b.json" "${CHAIN_B_ID}" >"${ARTIFACTS}/rly-add-b.log"

  rly keys restore "${CHAIN_A_ID}" "${RLY_KEY}" "$(jq -r .mnemonic "${SECRETS}/chain-a.rly-relayer.json")" >"${ARTIFACTS}/rly-restore-a.log"
  rly keys restore "${CHAIN_B_ID}" "${RLY_KEY}" "$(jq -r .mnemonic "${SECRETS}/chain-b.rly-relayer.json")" >"${ARTIFACTS}/rly-restore-b.log"
  rly paths new "${CHAIN_A_ID}" "${CHAIN_B_ID}" pqc-ibc >"${ARTIFACTS}/rly-path-new.log"
  rly tx link pqc-ibc --debug >"${ARTIFACTS}/rly-link.log" 2>&1
  rly paths show pqc-ibc --json >"${ARTIFACTS}/rly-path.json"
}

proposal_id_from_commit() {
  jq -r '[.result.tx_result.events[] | select(.type == "submit_proposal") | .attributes[] | select(.key == "proposal_id") | .value][0] // empty' "$1"
}

enable_mldsa_consensus() {
  local label=$1 home=$2 chain_id=$3 rpc=$4
  local prefix="${ARTIFACTS}/${label}.allow-mldsa" authority proposal_id submit_hash vote_hash
  log "enabling ML-DSA-65 validator keys by governance on ${label}"
  dora query consensus params --node "${rpc}" --output json >"${prefix}.params-before.json"
  dora query auth module-account gov --node "${rpc}" --output json >"${prefix}.gov-account.json"
  authority=$(jq -r '.account.base_account.address // .account.baseAccount.address // .account.value.address // empty' "${prefix}.gov-account.json")
  [[ -n "${authority}" ]] || fail "cannot resolve ${label} governance authority"
  jq '.params | .validator.pub_key_types = ([.validator.pub_key_types[], "ml_dsa_65"] | unique)' \
    "${prefix}.params-before.json" >"${prefix}.params-requested.json"
  jq -n --arg authority "${authority}" --slurpfile params "${prefix}.params-requested.json" \
    '{messages:[{"@type":"/cosmos.consensus.v1.MsgUpdateParams",authority:$authority,block:$params[0].block,evidence:$params[0].evidence,validator:$params[0].validator,abci:($params[0].abci // null),auth:($params[0].auth // null)}],metadata:"",deposit:"1000000peaka",title:"Allow ML-DSA-65 validator keys",summary:"Permit staged Ed25519 to ML-DSA-65 consensus key rotation",expedited:false}' \
    >"${prefix}.proposal.json"
  submit_hash=$(broadcast_cli "${label}-submit-consensus-params" "${rpc}" "${prefix}.submit" tx gov submit-proposal "${prefix}.proposal.json" \
    --from "${VALIDATOR_KEY}" --home "${home}" --keyring-backend test --chain-id "${chain_id}" \
    --gas 1500000 --fees "1500${DENOM}" --yes)
  proposal_id=$(proposal_id_from_commit "${prefix}.submit.commit.json")
  [[ -n "${proposal_id}" ]] || fail "cannot resolve ${label} consensus params proposal ID"
  vote_hash=$(broadcast_cli "${label}-vote-consensus-params" "${rpc}" "${prefix}.vote" tx gov vote "${proposal_id}" yes \
    --from "${VALIDATOR_KEY}" --home "${home}" --keyring-backend test --chain-id "${chain_id}" \
    --gas 500000 --fees "500${DENOM}" --yes)
  for _ in $(seq 1 90); do
    dora query gov proposal "${proposal_id}" --node "${rpc}" --output json >"${prefix}.proposal-state.json" 2>/dev/null || true
    if [[ $(jq -r '.proposal.status // empty' "${prefix}.proposal-state.json" 2>/dev/null) == "PROPOSAL_STATUS_PASSED" ]]; then
      break
    fi
    sleep 1
  done
  [[ $(jq -r '.proposal.status // empty' "${prefix}.proposal-state.json") == "PROPOSAL_STATUS_PASSED" ]] || \
    fail "${label} consensus params proposal did not pass"
  for _ in $(seq 1 30); do
    dora query consensus params --node "${rpc}" --output json >"${prefix}.params-after.json"
    if jq -e '.params.validator.pub_key_types | index("ml_dsa_65") != null' "${prefix}.params-after.json" >/dev/null; then
      jq -n --arg proposal_id "${proposal_id}" --arg submit_tx "${submit_hash}" --arg vote_tx "${vote_hash}" \
        '{proposal_id:$proposal_id,submit_tx:$submit_tx,vote_tx:$vote_tx}' >"${prefix}.result.json"
      return 0
    fi
    sleep 1
  done
  fail "${label} consensus params do not allow ML-DSA-65 after passed proposal"
}

discover_path() {
  local path_json="${ARTIFACTS}/rly-path.json"
  CLIENT_A=$(jq -r '.chains.src["client-id"] // empty' "${path_json}")
  CLIENT_B=$(jq -r '.chains.dst["client-id"] // empty' "${path_json}")
  dora query ibc channel channels --node "${CHAIN_A_RPC}" --output json >"${ARTIFACTS}/chain-a.channels.json"
  dora query ibc channel channels --node "${CHAIN_B_RPC}" --output json >"${ARTIFACTS}/chain-b.channels.json"
  CHANNEL_A=$(jq -r '[.channels[] | select(.port_id == "transfer") | .channel_id][0] // empty' "${ARTIFACTS}/chain-a.channels.json")
  CHANNEL_B=$(jq -r '[.channels[] | select(.port_id == "transfer") | .channel_id][0] // empty' "${ARTIFACTS}/chain-b.channels.json")
  [[ -n "${CLIENT_A}" && -n "${CLIENT_B}" && -n "${CHANNEL_A}" && -n "${CHANNEL_B}" ]] || \
    fail "unable to discover IBC identifiers from ${path_json}"
  export CLIENT_A CLIENT_B CHANNEL_A CHANNEL_B
  jq -n --arg client_a "${CLIENT_A}" --arg client_b "${CLIENT_B}" --arg channel_a "${CHANNEL_A}" --arg channel_b "${CHANNEL_B}" \
    '{client_a:$client_a,client_b:$client_b,channel_a:$channel_a,channel_b:$channel_b}' >"${ARTIFACTS}/ibc-identifiers.json"
}

pqc_relay() {
  local direction=$1 tx_hash=$2 output=$3
  local source_id source_rpc source_home source_client destination_id destination_rpc destination_home destination_client
  if [[ "${direction}" == "a-to-b" ]]; then
    source_id=${CHAIN_A_ID}; source_rpc=${CHAIN_A_RPC}; source_home=${CHAIN_A_HOME}; source_client=${CLIENT_A}
    destination_id=${CHAIN_B_ID}; destination_rpc=${CHAIN_B_RPC}; destination_home=${CHAIN_B_HOME}; destination_client=${CLIENT_B}
  else
    source_id=${CHAIN_B_ID}; source_rpc=${CHAIN_B_RPC}; source_home=${CHAIN_B_HOME}; source_client=${CLIENT_B}
    destination_id=${CHAIN_A_ID}; destination_rpc=${CHAIN_A_RPC}; destination_home=${CHAIN_A_HOME}; destination_client=${CLIENT_A}
  fi
  LD_LIBRARY_PATH="${BIN_DIR}" "${BIN_DIR}/pqcibc-relayer" relay-transfer \
    --source-chain-id "${source_id}" --source-rpc "${source_rpc}" --source-home "${source_home}" --source-key "${RELAYER_KEY}" --source-client-id "${source_client}" \
    --destination-chain-id "${destination_id}" --destination-rpc "${destination_rpc}" --destination-home "${destination_home}" --destination-key "${RELAYER_KEY}" --destination-client-id "${destination_client}" \
    --tx-hash "${tx_hash}" --gas 2500000 --fees "2500${DENOM}" >"${output}"
}

pqc_update() {
  local source_id=$1 source_rpc=$2 destination_id=$3 destination_rpc=$4 destination_home=$5 destination_client=$6 target=$7 output=$8
  LD_LIBRARY_PATH="${BIN_DIR}" "${BIN_DIR}/pqcibc-relayer" update-client \
    --source-chain-id "${source_id}" --source-rpc "${source_rpc}" \
    --destination-chain-id "${destination_id}" --destination-rpc "${destination_rpc}" --destination-home "${destination_home}" --destination-key "${RELAYER_KEY}" --destination-client-id "${destination_client}" \
    --target-height "${target}" --gas 2500000 --fees "2500${DENOM}" >"${output}"
}

send_transfer() {
  local label=$1 home=$2 chain_id=$3 rpc=$4 channel=$5 recipient=$6 amount=$7 output=$8
  broadcast_cli "${label}" "${rpc}" "${output}" tx ibc-transfer transfer transfer "${channel}" "${recipient}" "${amount}${DENOM}" \
    --from "${RELAYER_KEY}" --home "${home}" --keyring-backend test --chain-id "${chain_id}" --sign-mode direct \
    --gas 1200000 --fees "1200${DENOM}" --yes
}

new_consensus_key() {
  local label=$1 home=$2 chain_id=$3
  dora init "${label}-rotated" --chain-id "${chain_id}" --default-denom "${DENOM}" --consensus-key-algo ml_dsa_65 --home "${home}" >"${ARTIFACTS}/${label}.rotate-init.log" 2>&1
  dora comet show-validator --home "${home}" >"${ARTIFACTS}/${label}.new-consensus-pubkey.json"
}

rotation_apply_height() {
  jq -r '[.result.tx_result.events[]?.attributes[]? | select(.key=="apply_height") | .value][0] // empty' "$1"
}

rotate_chain_a() {
  log "rotating chain A consensus key to ML-DSA-65"
  new_consensus_key chain-a "${ROTATE_A_HOME}" "${CHAIN_A_ID}"
  local pubkey hash apply transition
  pubkey=$(jq -c . "${ARTIFACTS}/chain-a.new-consensus-pubkey.json")
  hash=$(broadcast_cli rotate-a "${CHAIN_A_RPC}" "${ARTIFACTS}/rotate-a" tx staking rotate-cons-pub-key "${pubkey}" \
    --from "${VALIDATOR_KEY}" --home "${CHAIN_A_HOME}" --keyring-backend test --chain-id "${CHAIN_A_ID}" \
    --gas 1000000 --fees "1000${DENOM}" --yes)
  apply=$(rotation_apply_height "${ARTIFACTS}/rotate-a.commit.json")
  [[ "${apply}" =~ ^[0-9]+$ ]] || fail "chain A rotation apply height missing"
  transition=$((apply - 1))
  wait_height "${CHAIN_A_RPC}" "${transition}" chain-a
  pqc_update "${CHAIN_A_ID}" "${CHAIN_A_RPC}" "${CHAIN_B_ID}" "${CHAIN_B_RPC}" "${CHAIN_B_HOME}" "${CLIENT_B}" "${transition}" "${ARTIFACTS}/transition-a-to-b.json"
  docker stop "${CONTAINER_A}" >/dev/null
  cp "${CHAIN_A_HOME}/config/priv_validator_key.json" "${ARTIFACTS}/chain-a.old-priv-validator-key.json"
  cp "${ROTATE_A_HOME}/config/priv_validator_key.json" "${CHAIN_A_HOME}/config/priv_validator_key.json"
  start_node "${CONTAINER_A}" "${CHAIN_A_HOME}"
  wait_rpc "${CHAIN_A_RPC}" chain-a
  wait_height "${CHAIN_A_RPC}" "$((apply + 2))" chain-a
  pqc_update "${CHAIN_A_ID}" "${CHAIN_A_RPC}" "${CHAIN_B_ID}" "${CHAIN_B_RPC}" "${CHAIN_B_HOME}" "${CLIENT_B}" 0 "${ARTIFACTS}/post-rotation-a-to-b.json"
  jq -n --arg tx "${hash}" --argjson apply "${apply}" --argjson transition "${transition}" '{tx_hash:$tx,apply_height:$apply,transition_height:$transition}' >"${ARTIFACTS}/rotation-a.json"
}

rotate_chain_b() {
  log "rotating chain B consensus key to ML-DSA-65"
  new_consensus_key chain-b "${ROTATE_B_HOME}" "${CHAIN_B_ID}"
  local pubkey hash apply transition
  pubkey=$(jq -c . "${ARTIFACTS}/chain-b.new-consensus-pubkey.json")
  hash=$(broadcast_cli rotate-b "${CHAIN_B_RPC}" "${ARTIFACTS}/rotate-b" tx staking rotate-cons-pub-key "${pubkey}" \
    --from "${VALIDATOR_KEY}" --home "${CHAIN_B_HOME}" --keyring-backend test --chain-id "${CHAIN_B_ID}" \
    --gas 1000000 --fees "1000${DENOM}" --yes)
  apply=$(rotation_apply_height "${ARTIFACTS}/rotate-b.commit.json")
  [[ "${apply}" =~ ^[0-9]+$ ]] || fail "chain B rotation apply height missing"
  transition=$((apply - 1))
  wait_height "${CHAIN_B_RPC}" "${transition}" chain-b
  pqc_update "${CHAIN_B_ID}" "${CHAIN_B_RPC}" "${CHAIN_A_ID}" "${CHAIN_A_RPC}" "${CHAIN_A_HOME}" "${CLIENT_A}" "${transition}" "${ARTIFACTS}/transition-b-to-a.json"
  docker stop "${CONTAINER_B}" >/dev/null
  cp "${CHAIN_B_HOME}/config/priv_validator_key.json" "${ARTIFACTS}/chain-b.old-priv-validator-key.json"
  cp "${ROTATE_B_HOME}/config/priv_validator_key.json" "${CHAIN_B_HOME}/config/priv_validator_key.json"
  start_node "${CONTAINER_B}" "${CHAIN_B_HOME}"
  wait_rpc "${CHAIN_B_RPC}" chain-b
  wait_height "${CHAIN_B_RPC}" "$((apply + 2))" chain-b
  pqc_update "${CHAIN_B_ID}" "${CHAIN_B_RPC}" "${CHAIN_A_ID}" "${CHAIN_A_RPC}" "${CHAIN_A_HOME}" "${CLIENT_A}" 0 "${ARTIFACTS}/post-rotation-b-to-a.json"
  jq -n --arg tx "${hash}" --argjson apply "${apply}" --argjson transition "${transition}" '{tx_hash:$tx,apply_height:$apply,transition_height:$transition}' >"${ARTIFACTS}/rotation-b.json"
}

collect_evidence() {
  curl -fsS "${CHAIN_A_RPC}/status" >"${ARTIFACTS}/chain-a.status.json"
  curl -fsS "${CHAIN_B_RPC}/status" >"${ARTIFACTS}/chain-b.status.json"
  curl -fsS "${CHAIN_A_RPC}/validators" >"${ARTIFACTS}/chain-a.validators.json"
  curl -fsS "${CHAIN_B_RPC}/validators" >"${ARTIFACTS}/chain-b.validators.json"
  docker inspect "${CONTAINER_A}" "${CONTAINER_B}" >"${ARTIFACTS}/containers.json"
  docker logs "${CONTAINER_A}" >"${ARTIFACTS}/chain-a.log" 2>&1
  docker logs "${CONTAINER_B}" >"${ARTIFACTS}/chain-b.log" 2>&1

  local a_type b_type
  a_type=$(jq -r '.result.validators[0].pub_key.type' "${ARTIFACTS}/chain-a.validators.json")
  b_type=$(jq -r '.result.validators[0].pub_key.type' "${ARTIFACTS}/chain-b.validators.json")
  [[ "${a_type}" == *"MlDsa"* || "${a_type}" == *"MLDSA"* || "${a_type}" == *"mldsa"* ]] || fail "chain A validator is not ML-DSA: ${a_type}"
  [[ "${b_type}" == *"MlDsa"* || "${b_type}" == *"MLDSA"* || "${b_type}" == *"mldsa"* ]] || fail "chain B validator is not ML-DSA: ${b_type}"

  jq -n \
    --arg run_id "${RUN_ID}" --arg work_dir "${WORK_DIR}" \
    --arg cpu_per_node "${NODE_CPU}" --arg memory_per_node "${NODE_MEMORY}" \
    --arg chain_a "${CHAIN_A_ID}" --arg chain_b "${CHAIN_B_ID}" \
    --arg rpc_a "${CHAIN_A_RPC}" --arg rpc_b "${CHAIN_B_RPC}" \
    --arg client_a "${CLIENT_A}" --arg client_b "${CLIENT_B}" \
    --arg channel_a "${CHANNEL_A}" --arg channel_b "${CHANNEL_B}" \
    --arg validator_a "${a_type}" --arg validator_b "${b_type}" \
    --arg pre_send "${PRE_SEND_HASH}" --arg post_send_a "${POST_SEND_A_HASH}" --arg post_send_b "${POST_SEND_B_HASH}" \
    --slurpfile rotation_a "${ARTIFACTS}/rotation-a.json" --slurpfile rotation_b "${ARTIFACTS}/rotation-b.json" \
    --slurpfile pre_relay "${ARTIFACTS}/pre-rotation-relay.json" \
    --slurpfile post_relay_a "${ARTIFACTS}/post-rotation-a-to-b-relay.json" \
    --slurpfile post_relay_b "${ARTIFACTS}/post-rotation-b-to-a-relay.json" \
    '{status:"PASS",run_id:$run_id,work_dir:$work_dir,resources:{nodes:2,cpu_per_node:$cpu_per_node,memory_per_node:$memory_per_node},chains:{a:{chain_id:$chain_a,rpc:$rpc_a,client_id:$client_a,channel_id:$channel_a,validator_key_type:$validator_a},b:{chain_id:$chain_b,rpc:$rpc_b,client_id:$client_b,channel_id:$channel_b,validator_key_type:$validator_b}},rotation:{a:$rotation_a[0],b:$rotation_b[0]},transactions:{pre_rotation_transfer:$pre_send,post_rotation_a_to_b:$post_send_a,post_rotation_b_to_a:$post_send_b},relay:{pre_rotation:$pre_relay[0],post_rotation_a_to_b:$post_relay_a[0],post_rotation_b_to_a:$post_relay_b[0]}}' \
    >"${ARTIFACTS}/result.json"
}

write_report() {
  local result="${ARTIFACTS}/result.json"
  {
    printf '# PQC-IBC 双链真实节点模拟报告\n\n'
    printf -- '- 结果：**%s**\n' "$(jq -r .status "${result}")"
    printf -- '- 运行编号：`%s`\n' "${RUN_ID}"
    printf -- '- 资源：2 个独立节点，每节点 `%s CPU / %s`\n' "${NODE_CPU}" "${NODE_MEMORY}"
    printf -- '- Chain A：`%s`，RPC `%s`\n' "${CHAIN_A_ID}" "${CHAIN_A_RPC}"
    printf -- '- Chain B：`%s`，RPC `%s`\n\n' "${CHAIN_B_ID}" "${CHAIN_B_RPC}"
    printf '## 验证范围\n\n'
    printf '1. Ed25519 共识阶段建立 IBC client、connection 和 ICS20 channel。\n'
    printf '2. 使用原生 ML-DSA-65 relayer 账户完成轮换前 IBC 转账、RecvPacket 与 Acknowledgement。\n'
    printf '3. 两条链分别通过 `MsgRotateConsPubKey` 在 H+1 过渡 header 后切换 ML-DSA-65 共识密钥。\n'
    printf '4. PQC relayer 在对端提交并验证包含 ML-DSA-65 validator set 的 Tendermint header。\n'
    printf '5. 两条链均完成轮换后，再完成 A→B 和 B→A 双向 IBC 转账。\n\n'
    printf '## 核心交易\n\n'
    printf -- '- 轮换前 A→B transfer：`%s`\n' "${PRE_SEND_HASH}"
    printf -- '- Chain A 共识密钥轮换：`%s`\n' "$(jq -r .tx_hash "${ARTIFACTS}/rotation-a.json")"
    printf -- '- Chain B 共识密钥轮换：`%s`\n' "$(jq -r .tx_hash "${ARTIFACTS}/rotation-b.json")"
    printf -- '- 轮换后 A→B transfer：`%s`\n' "${POST_SEND_A_HASH}"
    printf -- '- 轮换后 B→A transfer：`%s`\n\n' "${POST_SEND_B_HASH}"
    printf '完整的 client update、recv packet 和 acknowledgement 交易记录见 `result.json`。\n'
  } >"${ARTIFACTS}/report-zh.md"
}

log "work directory: ${WORK_DIR}"
build_relayer
init_chain chain-a "${CHAIN_A_ID}" "${CHAIN_A_HOME}" 26657 26656 9090 1317 6060
init_chain chain-b "${CHAIN_B_ID}" "${CHAIN_B_HOME}" 36657 36656 9190 1417 6061
start_node "${CONTAINER_A}" "${CHAIN_A_HOME}"
start_node "${CONTAINER_B}" "${CHAIN_B_HOME}"
wait_rpc "${CHAIN_A_RPC}" chain-a
wait_rpc "${CHAIN_B_RPC}" chain-b
setup_ibc
discover_path

ADDR_A=$(jq -r .address "${SECRETS}/chain-a.pqc-relayer.json")
ADDR_B=$(jq -r .address "${SECRETS}/chain-b.pqc-relayer.json")
PRE_SEND_HASH=$(send_transfer pre-rotation-a-to-b "${CHAIN_A_HOME}" "${CHAIN_A_ID}" "${CHAIN_A_RPC}" "${CHANNEL_A}" "${ADDR_B}" 1000000 "${ARTIFACTS}/pre-rotation-send")
pqc_relay a-to-b "${PRE_SEND_HASH}" "${ARTIFACTS}/pre-rotation-relay.json"

enable_mldsa_consensus chain-a "${CHAIN_A_HOME}" "${CHAIN_A_ID}" "${CHAIN_A_RPC}"
enable_mldsa_consensus chain-b "${CHAIN_B_HOME}" "${CHAIN_B_ID}" "${CHAIN_B_RPC}"

rotate_chain_a
rotate_chain_b

POST_SEND_A_HASH=$(send_transfer post-rotation-a-to-b "${CHAIN_A_HOME}" "${CHAIN_A_ID}" "${CHAIN_A_RPC}" "${CHANNEL_A}" "${ADDR_B}" 2000000 "${ARTIFACTS}/post-rotation-a-to-b-send")
pqc_relay a-to-b "${POST_SEND_A_HASH}" "${ARTIFACTS}/post-rotation-a-to-b-relay.json"
POST_SEND_B_HASH=$(send_transfer post-rotation-b-to-a "${CHAIN_B_HOME}" "${CHAIN_B_ID}" "${CHAIN_B_RPC}" "${CHANNEL_B}" "${ADDR_A}" 3000000 "${ARTIFACTS}/post-rotation-b-to-a-send")
pqc_relay b-to-a "${POST_SEND_B_HASH}" "${ARTIFACTS}/post-rotation-b-to-a-relay.json"

collect_evidence
write_report

if [[ "${KEEP_RUNNING}" == 0 ]]; then
  docker stop "${CONTAINER_A}" "${CONTAINER_B}" >/dev/null
fi
trap - EXIT
log "PASS: ${ARTIFACTS}/result.json"
printf '%s\n' "${WORK_DIR}"
