package types

import (
	"testing"

	"github.com/stretchr/testify/require"

	authtypes "github.com/cosmos/cosmos-sdk/x/auth/types"
)

func TestVerificationGasUsesSDKBaseline(t *testing.T) {
	// An SDK dependency update must not silently reprice this consensus rule.
	require.Equal(t, uint64(750), authtypes.DefaultSigVerifyCostMlDsa65)
	require.Equal(t, authtypes.DefaultSigVerifyCostMlDsa65, DefaultVerificationGas)
	require.Equal(t, DefaultVerificationGas, MinimumVerificationGas)
	for _, price := range []uint64{0, 749, 750, 751, 250_000} {
		p := DefaultParams()
		p.VerificationGas = price
		genesis := DefaultGenesisState()
		genesis.Params = p
		current := DefaultParams()
		pending := p.AsScheduled()
		current.Pending, current.PendingActivationHeight = &pending, 100
		for _, err := range []error{p.Validate(), p.ValidateGovernanceUpdate(), ValidateGenesis(*genesis), current.Validate()} {
			if price < 750 {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		}
	}
}

func TestVerificationGasPreservesStoredPricesAndActivation(t *testing.T) {
	p := DefaultParams()
	p.VerificationGas = 250_000
	pending := p.AsScheduled()
	pending.VerificationGas = 750
	p.Pending, p.PendingActivationHeight = &pending, 100
	require.NoError(t, p.Validate())
	for _, height := range []int64{99, 100, 101} {
		effective := p.Effective(height)
		want := uint64(750)
		if height < 100 {
			want = 250_000
		}
		require.Equal(t, want, effective.EffectiveVerificationGas())
		estimate, err := EstimateVerificationGas(effective, 1, 2)
		require.NoError(t, err)
		require.Equal(t, 3*want, estimate.Total)
	}
	require.Equal(t, uint64(250_000), p.VerificationGas, "reading effective params must not rewrite stored prices")
}

func TestDefaultParamsValidate(t *testing.T) {
	params := DefaultParams()
	require.NoError(t, params.Validate())
	require.Equal(t, DefaultGovernanceSafetyDelayBlocks, params.GovernanceSafetyDelayBlocks)
	require.Equal(t, DefaultMaxEmergencyDurationBlocks, params.MaxEmergencyDurationBlocks)
	require.Equal(t, DefaultRecoveryDelayBlocks, params.RecoveryDelayBlocks)
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
	pending.EnforcementMode = EnforcementMode_ENFORCEMENT_MODE_REQUIRED_FOR_REGISTERED
	params.Pending = &pending
	params.PendingActivationHeight = 101

	require.Equal(t, EnforcementMode_ENFORCEMENT_MODE_OPTIONAL, params.EffectiveEnforcementMode(100))
	require.Equal(t, EnforcementMode_ENFORCEMENT_MODE_REQUIRED_FOR_REGISTERED, params.EffectiveEnforcementMode(101))
}

func TestParamsRejectUnsafeResourceLimits(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Params)
	}{
		{"zero verification gas", func(p *Params) { p.VerificationGas = 0 }},
		{"verification gas below floor", func(p *Params) {
			p.VerificationGas = MinimumVerificationGas - 1
		}},
		{"short network id", func(p *Params) { p.NetworkId = []byte("short") }},
		{"zero governance safety delay", func(p *Params) { p.GovernanceSafetyDelayBlocks = 0 }},
		{"excessive governance safety delay", func(p *Params) {
			p.GovernanceSafetyDelayBlocks = AbsoluteMaxGovernanceSafetyDelayBlocks + 1
		}},
		{"zero emergency duration", func(p *Params) { p.MaxEmergencyDurationBlocks = 0 }},
		{"excessive emergency duration", func(p *Params) {
			p.MaxEmergencyDurationBlocks = AbsoluteMaxEmergencyDurationBlocks + 1
		}},
		{"recovery delay below minimum", func(p *Params) { p.RecoveryDelayBlocks = 1 }},
		{"excessive recovery delay", func(p *Params) {
			p.RecoveryDelayBlocks = AbsoluteMaxRecoveryDelayBlocks + 1
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
		PendingChangeKind:      PolicyChangeKind_POLICY_CHANGE_KIND_RECOVER_SIGNING,
		PendingCreatedHeight:   10,
	}

	before := policy.Effective(19)
	require.Equal(t, uint64(1), before.CurrentSigningKeyId)
	require.False(t, before.SelfEnforced)

	atHeight := policy.Effective(20)
	require.Equal(t, uint64(2), atHeight.CurrentSigningKeyId)
	require.True(t, atHeight.SelfEnforced)
	require.Equal(t, uint64(4), atHeight.PolicyVersion)
	require.Zero(t, atHeight.PendingEffectiveHeight)
	require.Equal(t, PolicyChangeKind_POLICY_CHANGE_KIND_UNSPECIFIED, atHeight.PendingChangeKind)
	require.Zero(t, atHeight.PendingCreatedHeight)
}

func TestParamsRejectRemainingInvalidBoundsAndSchedules(t *testing.T) {
	testCases := []func(*Params){
		func(params *Params) { params.NetworkId = make([]byte, 65) },
		func(params *Params) { params.EnforcementMode = EnforcementMode(99) },
		func(params *Params) { params.VerificationGas = AbsoluteMaxVerificationGas + 1 },
		func(params *Params) { params.VerificationGas = 0 },
		func(params *Params) { params.EmergencyMode = EmergencyMode(99) },
		func(params *Params) {
			params.EmergencyMode = EmergencyMode_EMERGENCY_MODE_PAUSE_NEW_KEYS
		},
		func(params *Params) { params.EmergencyExpiresHeight = 2 },
		func(params *Params) { params.Pending = new(ScheduledParams) },
		func(params *Params) { params.PendingActivationHeight = 2 },
		func(params *Params) {
			pending := params.AsScheduled()
			pending.VerificationGas = 0
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
