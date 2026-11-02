package keeper

import (
	"testing"

	"github.com/DoraFactory/doravota/x/pqcauth/types"
	"github.com/stretchr/testify/require"
)

func TestLaunchDefaultsEmergencyExpiryAndImmutableDelays(t *testing.T) {
	for _, mode := range []types.EmergencyMode{types.EmergencyMode_EMERGENCY_MODE_PAUSE_NEW_KEYS, types.EmergencyMode_EMERGENCY_MODE_PAUSE_PQC_TRANSACTIONS} {
		k, ctx := setupKeeper(t, 100)
		base := types.DefaultParams()
		require.NoError(t, k.SetParams(ctx, base))
		s := NewMsgServer(k)
		for _, field := range []string{"recovery", "emergency", "governance"} {
			bad := base
			switch field {
			case "recovery":
				bad.RecoveryDelayBlocks++
			case "emergency":
				bad.MaxEmergencyDurationBlocks++
			case "governance":
				bad.GovernanceSafetyDelayBlocks++
			}
			_, err := s.UpdateParams(ctx, &types.MsgUpdateParams{Authority: k.Authority(), Params: bad})
			require.ErrorIs(t, err, types.ErrInvalidParams)
			require.Equal(t, base, k.GetParams(ctx))
		}
		pause := base
		pause.EmergencyMode = mode
		r, err := s.UpdateParams(ctx, &types.MsgUpdateParams{Authority: k.Authority(), Params: pause, EmergencyOnly: true})
		require.NoError(t, err)
		require.EqualValues(t, 101, r.ActivationHeight)
		stored := k.GetParams(ctx)
		require.EqualValues(t, 101+46080, stored.PendingEmergency.ExpiresHeight)
		require.Equal(t, types.EmergencyMode_EMERGENCY_MODE_NORMAL, stored.Effective(100).EmergencyMode)
		require.Equal(t, mode, stored.Effective(101).EmergencyMode)
		require.Equal(t, mode, stored.Effective(101+46080-1).EmergencyMode)
		require.Equal(t, types.EmergencyMode_EMERGENCY_MODE_NORMAL, stored.Effective(101+46080).EmergencyMode)
	}
}
