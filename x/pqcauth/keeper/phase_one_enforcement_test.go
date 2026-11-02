package keeper

import (
	"testing"

	"github.com/DoraFactory/doravota/x/pqcauth/types"
	"github.com/stretchr/testify/require"
)

func TestPhaseOneRequiredGovernanceCannotWriteState(t *testing.T) {
	k, ctx := setupKeeper(t, 100)
	base := types.DefaultParams()
	require.NoError(t, k.SetParams(ctx, base))
	requested := base
	requested.EnforcementMode = types.EnforcementMode_ENFORCEMENT_MODE_REQUIRED
	for _, emergencyOnly := range []bool{false, true} {
		_, err := NewMsgServer(k).UpdateParams(ctx, &types.MsgUpdateParams{Authority: k.Authority(), Params: requested, EmergencyOnly: emergencyOnly})
		require.ErrorIs(t, err, types.ErrInvalidParams)
		require.Equal(t, base, k.GetParams(ctx))
	}
	require.ErrorIs(t, k.SetParams(ctx, requested), types.ErrInvalidParams)
	require.Equal(t, base, k.GetParams(ctx))
}
