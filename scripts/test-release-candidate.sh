#!/usr/bin/env bash
# Run on the remote test host or CI. Logs distinguish execution from skipping.
set -euo pipefail
cd "$(dirname "$0")/.."
results=${RESULTS_DIR:-build/test-results}
mkdir -p "$results"
python3 scripts/test-release-tools.py
if ! go test ./... -count=1 -json >"$results/unit.jsonl" 2>&1; then
 cat "$results/unit.jsonl"; exit 1
fi
python3 scripts/check-test-results.py "$results/unit.jsonl" \
 TestLegacyWasmCodecRoundTripsAndHasNoHandlers \
 TestLegacyGrantsExportAndExpire \
 TestLegacyWasmStoredProposalDecode \
 TestLegacyWasmVotingProposalEndsWithoutHalting
if ! go test ./app -run '^TestApp(StateDeterminism|ImportExport|SimulationAfterImport)$' \
 -Enabled=true -Seed=42 -NumBlocks=10 -BlockSize=5 -Commit=true -count=1 -timeout=180s \
 -json >"$results/simulations.jsonl" 2>&1; then
 cat "$results/simulations.jsonl"; exit 1
fi
python3 scripts/check-test-results.py "$results/simulations.jsonl" \
 TestAppStateDeterminism TestAppImportExport TestAppSimulationAfterImport
