#!/usr/bin/env bash
# Run on the remote test host or CI. Logs distinguish execution from skipping.
set -euo pipefail
cd "$(dirname "$0")/.."
results=${RESULTS_DIR:-build/test-results}
mkdir -p "$results"
python3 scripts/test-release-tools.py
python3 scripts/test-pqcauth-capacity.py
python3 scripts/verify-ibc-amino-snapshot.py
# Go dependency downloads and compiler diagnostics go to stderr, not JSON.
# Keep the JSON gate strict and retain diagnostics separately for cold-cache CI.
if ! go test ./... -count=1 -json >"$results/unit.jsonl" 2>"$results/unit.stderr.log"; then
 cat "$results/unit.stderr.log" "$results/unit.jsonl"; exit 1
fi
python3 scripts/check-test-results.py "$results/unit.jsonl" \
 TestPQCAuthNetworkLoadGenesis \
 TestPQCAuthGovernanceEndBlockOrderingAndRollback \
 TestPQCAuthGovernanceEmergencyGuardAndResubmission \
 TestPQCAuthSignedGovernanceSubmissionVoteAndRollback \
 TestPQCAuthMixedTrafficAndRecoveryWithoutQuota \
 TestPQCAuthBoundedInvalidAdmission \
 TestPQCAuthRecheckPreservesGasAndDelivery \
 TestRestartAdmissionUsesCommittedContext \
 TestStartupCheckContextScope \
 TestPQCAuthRecheckDoesNotAuthenticateNewBytes \
 TestPQCAuthRecheckRejectsChangedPolicy \
 TestPQCAuthRecheckRejectsPauseAndSequence \
 TestPQCAuthRecheckRequiresOrderedLifecycle \
 TestPQCAuthRecheckEvictsStaleRecoveryDuringPendingPolicy \
 TestPQCAuthRecheckBoundedSevenSigners \
 TestPQCAuthRegistrationRequiresDirect \
 TestPQCAuthOpenRegistrationCanRetryAfterMessageFailure \
 TestPQCAuthProposalPreservesSequenceDependencies \
 TestPQCAuthFreshClassicSDKDryRun \
 TestPQCAuthProtectedSimulationVersusDeliveryGas \
 TestPQCAuthVerificationPriceAppliedToSimulationAndDelivery \
 TestPQCAuthProofPriceAppliedToSimulationAndDelivery \
 TestPQCAuthFullPauseProtectedRecoveryPayer \
 TestPQCAuthLifecycleWithProtectedPayer \
 TestPQCAuthNativeMultisigUsesSDKLimits \
 TestSDKProposalPolicyWithoutBridgeOverrides \
 TestPQCAuthPhaseOnePreservesDelegationSemantics \
 TestPQCAuthPhaseOneDelegationCannotManageKeys \
 TestPQCAuthPhaseOneRecoveryPreservesDelegations \
 TestPQCAuthPhaseOneUpgradeDoesNotScanDelegations \
 TestPQCAuthRevokeRetiredKeyPreservesStateAudit \
 TestPQCAuthFeegrantExpiryPreservesSDKSemantics \
 TestPQCAuthExportHeightSafety \
 TestPQCAuthEmptyStateZeroHeightExport \
 TestPQCAuthRealFailedMessagesKeepSDKFeegrantSemantics \
 TestPQCAuthSDKKeyringRegistrationAndHybridTransfer \
 TestPQCAuthProposalPreservesSDKGasPolicy \
 TestPQCAuthCandidateUpgradePreservesExistingFeegrants \
 TestVersionedUpgradeHandlerRegistration \
 TestUpgradeIdentityMatchesReleaseVersion \
 TestAminoUpgradeLifecycle \
 TestPQCAuthRequiresV101Activation \
 TestIBCCompatDescriptorOnlyChange \
 TestIBCCompatAminoEncoding \
 TestIBCCompatUnchangedSignBytes \
 TestIBCCompatCheckTx \
 TestLegacyWasmCodecRoundTripsAndHasNoHandlers \
 TestLegacyGrantsExportAndExpire \
 TestLegacyWasmStoredProposalDecode \
 TestLegacyWasmVotingProposalEndsWithoutHalting
python3 scripts/check-test-results.py "$results/unit.jsonl" \
 --package github.com/DoraFactory/doravota/app/wasmarchive \
 TestPostArchiveModuleBoundary
python3 scripts/check-test-results.py "$results/unit.jsonl" \
 --package github.com/DoraFactory/doravota/x/pqcauth/client/cli \
 TestRegistrationRejectsIncompatibleBackend \
 TestNewFactorAcknowledgementForExternalOwners \
 TestRecoveryBundleCommandsPrepareAndSignRoundTrip \
 TestDelegationWarningDoesNotPolluteTransactionOutput
python3 scripts/check-test-results.py "$results/unit.jsonl" \
 --package github.com/DoraFactory/doravota/x/pqcauth/ante \
 TestRecheckKeepsAuthorizationGasAndKeyChecks \
 TestRecoveryAuthorizationBindsCompleteTransactionIntent \
 TestRecoveryEscapeRequiresSingleTopLevelMessage \
 TestFullPauseAllowsOnlyProtectedRecoveryEscapeExtension \
 TestPQCWireRejectsAmplificationBeforeDecode TestPQCWirePreflightBoundaries \
 TestFixedExtensionCaps \
 TestIndirectExecutionContainersRejectPQCAuthLifecycleMessages \
 TestIndirectExecutionInspectionRecursesAndPreservesOrdinaryMessages \
 TestIndirectExecutionInspectionFailsClosedOnMalformedContainer \
 TestAuthzNestedLifecycleMessageCannotInheritAnteAuthorization \
 TestMultisigNativeGasFloor TestNestedMultisigNativeGasFloorAndHigherCost
python3 scripts/check-test-results.py "$results/unit.jsonl" \
 --package github.com/DoraFactory/doravota/x/pqcauth/keeper \
  TestLaunchDefaultsEmergencyExpiryAndImmutableDelays \
 TestPhaseOneRequiredGovernanceCannotWriteState TestRecheckKeyProofRetainsGas \
 TestEmergencyOnlyRejectsSameBlockFullUpdate \
 TestEmergencyOnlySameBlockExplicitReplacement \
 TestReviewCancelOrdinaryRestrictionWhileKeepingPause \
 TestExplicitEmergencyRenewalPreservesOrdinaryIntent \
 TestEmergencyOnlyRejectsSmuggledChangesAndPreservesOrdinaryPlan \
 TestOrdinaryReplacementDoesNotRenewOrResurrectPause \
 TestEmergencyUpdatePreservesPendingRestrictions \
 TestEmergencyUpdateCannotInjectOtherChanges \
 TestEmergencyExpiryDoesNotResurrectAtPendingActivation \
 TestAuditStateRejectsInactiveCurrentKeys \
 TestLifecycleMessagesRequireExactAnteAuthorization \
 TestAllLifecycleServersRejectMissingOrDifferentAnteAuthorization \
 TestZeroHeightExportRequiresHeightIndependentPQCState \
 TestGovernanceCapacityUsesCurrentConsensusGas \
 TestCapacityPreflightPreservesEmergencyGovernance \
 TestKeyHistoryRetentionBeyondDefaultPage TestCancelledRecoveryHistoryDoesNotBlockLaterRotation
python3 scripts/check-test-results.py "$results/unit.jsonl" \
 --package github.com/DoraFactory/doravota/x/pqcauth/types \
  TestPhaseOneLaunchDelayDefaults \
 TestPhaseOneRejectsGlobalRequired \
 TestEmergencyIntentWireJSONAndSignBytes \
 TestIndependentEmergencyValidationAndCodec \
 TestVerificationGasUsesSDKBaseline TestVerificationGasPreservesStoredPricesAndActivation \
   TestPQCVerificationPriceCapacity TestSimplifiedParamsReserveRemovedFields TestLegacyPricesCannotSilentlyInitializeNewSchema
python3 scripts/check-test-results.py "$results/unit.jsonl" \
 --package github.com/DoraFactory/doravota/x/pqcauth \
 TestKeyHistoryOutOfOrderRetirementGenesisRoundTrip TestIndependentEmergencyExportImport
if ! go test ./app -run '^TestApp(StateDeterminism|ImportExport|SimulationAfterImport)$' \
 -Enabled=true -Seed=42 -NumBlocks=10 -BlockSize=5 -Commit=true -count=1 -timeout=180s \
 -json >"$results/simulations.jsonl" 2>"$results/simulations.stderr.log"; then
 cat "$results/simulations.stderr.log" "$results/simulations.jsonl"; exit 1
fi
python3 scripts/check-test-results.py "$results/simulations.jsonl" \
 TestAppStateDeterminism TestAppImportExport TestAppSimulationAfterImport
