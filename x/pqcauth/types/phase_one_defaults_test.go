package types

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestPhaseOneLaunchDelayDefaults(t *testing.T) {
	p := DefaultParams()
	require.NoError(t, p.Validate())
	require.EqualValues(t, 107520, p.RecoveryDelayBlocks)
	require.EqualValues(t, 46080, p.MaxEmergencyDurationBlocks)
	require.EqualValues(t, 17280, p.GovernanceSafetyDelayBlocks)
	require.EqualValues(t, 750, p.VerificationGas)
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
