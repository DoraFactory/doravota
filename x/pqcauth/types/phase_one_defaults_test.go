package types

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestPhaseOneOpenRegistrationParameters(t *testing.T) {
	for _, mode := range []RegistrationMode{RegistrationMode_REGISTRATION_MODE_OPEN, RegistrationMode_REGISTRATION_MODE_UNSPECIFIED, RegistrationMode_REGISTRATION_MODE_CLOSED, RegistrationMode_REGISTRATION_MODE_FRESH_ACCOUNTS_ONLY} {
		for _, cutoff := range []uint64{0, 1, 1000} {
			p := DefaultParams()
			p.RegistrationMode, p.RegistrationCutoffHeight = mode, cutoff
			valid := cutoff == 0 && (mode == RegistrationMode_REGISTRATION_MODE_OPEN || mode == RegistrationMode_REGISTRATION_MODE_UNSPECIFIED)
			base := DefaultParams()
			scheduled := p.AsScheduled()
			base.Pending, base.PendingActivationHeight = &scheduled, 100
			for _, err := range []error{p.Validate(), p.ValidateGovernanceUpdate(), ValidateGenesis(GenesisState{Params: p}), base.Validate(), ValidateGenesis(GenesisState{Params: base})} {
				if valid {
					require.NoError(t, err)
				} else {
					require.ErrorIs(t, err, ErrInvalidParams)
				}
			}
			for _, h := range []int64{0, 99, 1000} {
				for _, fresh := range []bool{false, true} {
					err := CheckRegistrationAllowed(p, h, fresh)
					if valid {
						require.NoError(t, err)
					} else {
						require.ErrorIs(t, err, ErrRegistrationClosed)
					}
				}
			}
		}
	}
}

func TestPhaseOneLaunchDelayDefaults(t *testing.T) {
	p := DefaultParams()
	require.NoError(t, p.Validate())
	require.EqualValues(t, 107520, p.RecoveryDelayBlocks)
	require.EqualValues(t, 46080, p.MaxEmergencyDurationBlocks)
	require.EqualValues(t, 17280, p.GovernanceSafetyDelayBlocks)
	require.EqualValues(t, 750, p.SignatureVerificationGas)
	require.EqualValues(t, 750, p.ProofVerificationGas)
	require.EqualValues(t, 400, p.MaxPqcVerificationsPerBlock)
	require.EqualValues(t, 16, p.MaxPqcVerificationsPerTx)
	// Explicit experimental genesis values are not silently rewritten. Zero
	// recovery delay retains the existing fallback-to-current-default rule.
	p.RecoveryDelayBlocks, p.MaxEmergencyDurationBlocks = 17280, 17280
	require.NoError(t, p.Validate())
	require.EqualValues(t, 17280, p.Effective(100).RecoveryDelayBlocks)
	require.EqualValues(t, 17280, p.Effective(100).MaxEmergencyDurationBlocks)
	p.RecoveryDelayBlocks = 0
	require.EqualValues(t, 107520, p.EffectiveRecoveryDelayBlocks())

	const start = 100
	activation := uint64(start) + DefaultRecoveryDelayBlocks
	policy := AccountPolicy{CurrentSigningKeyId: 1, PolicyVersion: 1, PendingSigningKeyId: 2, PendingPolicyVersion: 2, PendingEffectiveHeight: activation, PendingChangeKind: PolicyChangeKind_POLICY_CHANGE_KIND_RECOVER_SIGNING}
	old := PQCKeyRecord{Status: KeyStatus_KEY_STATUS_LIVE, EffectiveHeight: 1, InactiveFromHeight: activation}
	newKey := PQCKeyRecord{Status: KeyStatus_KEY_STATUS_LIVE, EffectiveHeight: activation}
	for _, h := range []int64{int64(activation - 1), int64(activation), int64(activation + 1)} {
		before := uint64(h) < activation
		require.Equal(t, before, policy.HasPendingRecovery(h))
		require.Equal(t, before, old.IsEffective(h))
		require.Equal(t, !before, newKey.IsEffective(h))
		want := uint64(2)
		if before {
			want = 1
		}
		require.Equal(t, want, policy.Effective(h).CurrentSigningKeyId)
	}
}
