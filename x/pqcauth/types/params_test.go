package types

import (
	"testing"

	"github.com/stretchr/testify/require"

	pqccrypto "github.com/DoraFactory/doravota/x/pqcauth/crypto"
)

func TestDefaultParamsValidate(t *testing.T) {
	params := DefaultParams()
	require.NoError(t, params.Validate())
	require.Equal(t, DefaultGovernanceSafetyDelayBlocks, params.GovernanceSafetyDelayBlocks)
	require.Equal(t, DefaultMaxEmergencyDurationBlocks, params.MaxEmergencyDurationBlocks)
	require.True(t, params.IsAlgorithmAllowed(Algorithm_ALGORITHM_ML_DSA_65))
	require.Equal(t, EnforcementMode_ENFORCEMENT_MODE_OPTIONAL, params.EffectiveEnforcementMode(10))
}

func TestEmergencyModeAutoExpiresAtExactHeight(t *testing.T) {
	params := DefaultParams()
	params.EmergencyMode = EmergencyMode_EMERGENCY_MODE_PAUSE_PQC_TRANSACTIONS
	params.EmergencyExpiresHeight = 20
	require.NoError(t, params.Validate())
	require.Equal(
		t,
		EmergencyMode_EMERGENCY_MODE_PAUSE_PQC_TRANSACTIONS,
		params.EffectiveEmergencyMode(19),
	)
	effective := params.Effective(20)
	require.Equal(t, EmergencyMode_EMERGENCY_MODE_NORMAL, effective.EmergencyMode)
	require.Zero(t, effective.EmergencyExpiresHeight)
}

func TestParamsEnforcementActivatesAtExactHeight(t *testing.T) {
	params := DefaultParams()
	pending := params.AsScheduled()
	pending.EnforcementMode = EnforcementMode_ENFORCEMENT_MODE_REQUIRED
	params.Pending = &pending
	params.PendingActivationHeight = 101

	require.Equal(t, EnforcementMode_ENFORCEMENT_MODE_OPTIONAL, params.EffectiveEnforcementMode(100))
	require.Equal(t, EnforcementMode_ENFORCEMENT_MODE_REQUIRED, params.EffectiveEnforcementMode(101))
}

func TestParamsRejectUnsafeResourceLimits(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Params)
	}{
		{"zero signers", func(p *Params) { p.MaxPqcSigners = 0 }},
		{"too many signers", func(p *Params) { p.MaxPqcSigners = AbsoluteMaxPQCSigners + 1 }},
		{"oversized auth", func(p *Params) { p.MaxPqcAuthBytes = AbsoluteMaxPQCAuthBytes + 1 }},
		{"too much key history", func(p *Params) {
			p.MaxRetainedKeyRecordsPerRole = AbsoluteMaxRetainedKeyRecordsPerRole + 1
		}},
		{"zero verification gas", func(p *Params) { p.SignatureVerificationGas = 0 }},
		{"signature gas below floor", func(p *Params) {
			p.SignatureVerificationGas = MinimumSignatureVerificationGas - 1
		}},
		{"proof gas below floor", func(p *Params) {
			p.ProofVerificationGas = MinimumProofVerificationGas - 1
		}},
		{"short network id", func(p *Params) { p.NetworkId = []byte("short") }},
		{"unknown algorithm", func(p *Params) { p.AllowedAlgorithms = []Algorithm{99} }},
		{"zero governance safety delay", func(p *Params) { p.GovernanceSafetyDelayBlocks = 0 }},
		{"excessive governance safety delay", func(p *Params) {
			p.GovernanceSafetyDelayBlocks = AbsoluteMaxGovernanceSafetyDelayBlocks + 1
		}},
		{"zero emergency duration", func(p *Params) { p.MaxEmergencyDurationBlocks = 0 }},
		{"excessive emergency duration", func(p *Params) {
			p.MaxEmergencyDurationBlocks = AbsoluteMaxEmergencyDurationBlocks + 1
		}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			params := DefaultParams()
			test.mutate(&params)
			require.Error(t, params.Validate())
		})
	}
}

func TestAccountPolicyHPlusOne(t *testing.T) {
	policy := AccountPolicy{
		Owner:                  "owner",
		CurrentSigningKeyId:    1,
		SelfEnforced:           false,
		PolicyVersion:          3,
		PendingSigningKeyId:    2,
		PendingEffectiveHeight: 20,
		PendingSelfEnforced:    true,
		PendingPolicyVersion:   4,
	}

	before := policy.Effective(19)
	require.Equal(t, uint64(1), before.CurrentSigningKeyId)
	require.False(t, before.SelfEnforced)

	atHeight := policy.Effective(20)
	require.Equal(t, uint64(2), atHeight.CurrentSigningKeyId)
	require.True(t, atHeight.SelfEnforced)
	require.Equal(t, uint64(4), atHeight.PolicyVersion)
	require.Zero(t, atHeight.PendingEffectiveHeight)
}

func TestEffectiveResourceDefaultsAndAlgorithmConversion(t *testing.T) {
	params := Params{}
	require.Equal(t, DefaultMaxPQCSigners, params.EffectiveMaxPQCSigners())
	require.Equal(t, DefaultMaxPQCAuthBytes, params.EffectiveMaxPQCAuthBytes())
	require.Equal(t, DefaultMaxRetainedKeyRecordsPerRole, params.EffectiveMaxRetainedKeyRecordsPerRole())
	require.Equal(t, DefaultSignatureVerificationGas, params.EffectiveSignatureVerificationGas())
	require.Equal(t, DefaultProofVerificationGas, params.EffectiveProofVerificationGas())

	params = DefaultParams()
	require.Equal(t, params.MaxPqcSigners, params.EffectiveMaxPQCSigners())
	require.Equal(t, params.MaxPqcAuthBytes, params.EffectiveMaxPQCAuthBytes())
	require.Equal(
		t,
		params.MaxRetainedKeyRecordsPerRole,
		params.EffectiveMaxRetainedKeyRecordsPerRole(),
	)
	require.Equal(t, params.SignatureVerificationGas, params.EffectiveSignatureVerificationGas())
	require.Equal(t, params.ProofVerificationGas, params.EffectiveProofVerificationGas())
	require.Equal(
		t,
		EmergencyMode_EMERGENCY_MODE_NORMAL,
		params.EffectiveEmergencyMode(1),
	)
	require.False(t, params.IsAlgorithmAllowed(Algorithm(99)))

	algorithm, err := CryptoAlgorithm(Algorithm_ALGORITHM_ML_DSA_65)
	require.NoError(t, err)
	require.Equal(t, pqccrypto.AlgorithmMLDSA65, algorithm)
	_, err = CryptoAlgorithm(Algorithm(99))
	require.ErrorIs(t, err, ErrUnsupportedAlgorithm)
}

func TestParamsRejectRemainingInvalidBoundsAndSchedules(t *testing.T) {
	testCases := []func(*Params){
		func(params *Params) { params.NetworkId = make([]byte, 65) },
		func(params *Params) { params.EnforcementMode = EnforcementMode(99) },
		func(params *Params) { params.AllowedAlgorithms = nil },
		func(params *Params) {
			params.AllowedAlgorithms = []Algorithm{
				Algorithm_ALGORITHM_ML_DSA_65,
				Algorithm_ALGORITHM_ML_DSA_65,
			}
		},
		func(params *Params) { params.SignatureVerificationGas = AbsoluteMaxVerificationGas + 1 },
		func(params *Params) { params.ProofVerificationGas = 0 },
		func(params *Params) { params.ProofVerificationGas = AbsoluteMaxVerificationGas + 1 },
		func(params *Params) { params.MaxPqcAuthBytes = 0 },
		func(params *Params) { params.MaxRetainedKeyRecordsPerRole = 0 },
		func(params *Params) { params.EmergencyMode = EmergencyMode(99) },
		func(params *Params) {
			params.EmergencyMode = EmergencyMode_EMERGENCY_MODE_PAUSE_NEW_KEYS
		},
		func(params *Params) { params.EmergencyExpiresHeight = 2 },
		func(params *Params) { params.Pending = new(ScheduledParams) },
		func(params *Params) { params.PendingActivationHeight = 2 },
		func(params *Params) {
			pending := params.AsScheduled()
			pending.MaxPqcSigners = 0
			params.Pending = &pending
			params.PendingActivationHeight = 2
		},
		func(params *Params) {
			pending := params.AsScheduled()
			pending.EmergencyMode = EmergencyMode_EMERGENCY_MODE_PAUSE_NEW_KEYS
			pending.EmergencyExpiresHeight = 2
			params.Pending = &pending
			params.PendingActivationHeight = 2
		},
	}
	for _, mutate := range testCases {
		params := DefaultParams()
		mutate(&params)
		require.Error(t, params.Validate())
	}
}

func TestGovernanceUpdateCannotChooseRuntimeSchedulingFields(t *testing.T) {
	params := DefaultParams()
	params.EmergencyMode = EmergencyMode_EMERGENCY_MODE_PAUSE_NEW_KEYS
	require.NoError(t, params.ValidateGovernanceUpdate())

	params.EmergencyExpiresHeight = 100
	require.Error(t, params.ValidateGovernanceUpdate())
	params.EmergencyExpiresHeight = 0
	pending := params.AsScheduled()
	params.Pending = &pending
	params.PendingActivationHeight = 10
	require.Error(t, params.ValidateGovernanceUpdate())
}

func TestPolicyAndKeyEffectivenessBoundaries(t *testing.T) {
	policy := AccountPolicy{
		CurrentSigningKeyId:    1,
		RecoveryKeyId:          2,
		PolicyVersion:          1,
		PendingSigningKeyId:    3,
		PendingRecoveryKeyId:   4,
		PendingEffectiveHeight: 20,
		PendingSelfEnforced:    true,
		PendingPolicyVersion:   2,
	}
	require.Equal(t, policy, policy.Effective(-1))
	require.True(t, policy.HasPendingChange(-1))
	require.True(t, policy.HasPendingChange(19))
	require.False(t, policy.HasPendingChange(20))

	effective := policy.Effective(20)
	require.Equal(t, uint64(3), effective.CurrentSigningKeyId)
	require.Equal(t, uint64(4), effective.RecoveryKeyId)
	require.True(t, effective.SelfEnforced)
	require.Zero(t, effective.PendingRecoveryKeyId)

	key := PQCKeyRecord{
		Status:             KeyStatus_KEY_STATUS_LIVE,
		EffectiveHeight:    10,
		InactiveFromHeight: 20,
	}
	require.False(t, key.IsEffective(-1))
	require.False(t, key.IsEffective(9))
	require.True(t, key.IsEffective(10))
	require.False(t, key.IsEffective(20))
	key.Status = KeyStatus_KEY_STATUS_REVOKED
	require.False(t, key.IsEffective(10))

	require.True(t, EqualNetworkID([]byte{1}, []byte{1}))
	require.False(t, EqualNetworkID([]byte{1}, []byte{2}))
}
