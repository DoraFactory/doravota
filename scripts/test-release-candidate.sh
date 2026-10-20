#!/usr/bin/env bash
# Run on the remote test host or CI. Logs distinguish execution from skipping.
set -euo pipefail
cd "$(dirname "$0")/.."
results=${RESULTS_DIR:-build/test-results}
mkdir -p "$results"
python3 scripts/test-release-tools.py
# Go dependency downloads and compiler diagnostics go to stderr, not JSON.
# Keep the JSON gate strict and retain diagnostics separately for cold-cache CI.
if ! go test ./... -count=1 -json >"$results/unit.jsonl" 2>"$results/unit.stderr.log"; then
 cat "$results/unit.stderr.log" "$results/unit.jsonl"; exit 1
fi
python3 scripts/check-test-results.py "$results/unit.jsonl" \
 TestPQCAuthRealFailedMessagesKeepFeegrantIndexConsistent \
 TestPQCAuthSDKKeyringRegistrationAndHybridTransfer \
 TestPQCAuthProposalBudgetsPreserveSDKGasPolicy \
 TestPQCAuthFourApplicationProposalActivationBoundary \
 TestPQCAuthCandidateUpgradeInitializesExistingFeegrantIndex \
 TestVersionedUpgradeHandlerRegistration \
 TestUpgradeIdentityMatchesReleaseVersion \
 TestLegacyWasmCodecRoundTripsAndHasNoHandlers \
 TestLegacyGrantsExportAndExpire \
 TestLegacyWasmStoredProposalDecode \
 TestLegacyWasmVotingProposalEndsWithoutHalting
python3 scripts/check-test-results.py "$results/unit.jsonl" \
 --package github.com/DoraFactory/doravota/x/pqcauth/client/cli \
 TestNewFactorAcknowledgementForExternalOwners
if ! go test ./app -run '^TestApp(StateDeterminism|ImportExport|SimulationAfterImport)$' \
 -Enabled=true -Seed=42 -NumBlocks=10 -BlockSize=5 -Commit=true -count=1 -timeout=180s \
 -json >"$results/simulations.jsonl" 2>"$results/simulations.stderr.log"; then
 cat "$results/simulations.stderr.log" "$results/simulations.jsonl"; exit 1
fi
python3 scripts/check-test-results.py "$results/simulations.jsonl" \
 TestAppStateDeterminism TestAppImportExport TestAppSimulationAfterImport
