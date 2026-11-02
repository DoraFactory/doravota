package pqcauth

import (
	"fmt"
	"testing"

	"github.com/DoraFactory/doravota/x/pqcauth/keeper"
	"github.com/DoraFactory/doravota/x/pqcauth/types"
	"github.com/cosmos/cosmos-sdk/codec"
	"github.com/stretchr/testify/require"
)

func TestIndependentEmergencyExportImport(t *testing.T) {
	for _, ordinary := range []bool{false, true} {
		t.Run(fmt.Sprintf("ordinary=%t", ordinary), func(t *testing.T) {
			testEmergencyExportImport(t, ordinary)
		})
	}
}

func testEmergencyExportImport(t *testing.T, ordinary bool) {
	t.Helper()
	ctx, k := setupGenesisTest(t, 100)
	p := types.DefaultParams()
	p.NetworkId = types.NetworkIDForChain(ctx.ChainID())
	p.GovernanceSafetyDelayBlocks = 10
	p.MaxEmergencyDurationBlocks = 20
	require.NoError(t, k.SetParams(ctx, p))
	queued := p
	queued.MaxPqcVerificationsPerBlock = 111
	queued.EnforcementMode = types.EnforcementMode_ENFORCEMENT_MODE_REQUIRED_FOR_REGISTERED
	s := keeper.NewMsgServer(k)
	if ordinary {
		_, err := s.UpdateParams(ctx, &types.MsgUpdateParams{Authority: k.Authority(), Params: queued})
		require.NoError(t, err)
	}
	p.EmergencyMode = types.EmergencyMode_EMERGENCY_MODE_PAUSE_PQC_TRANSACTIONS
	_, err := s.UpdateParams(ctx.WithBlockHeight(101), &types.MsgUpdateParams{Authority: k.Authority(), Params: p, EmergencyOnly: true})
	require.NoError(t, err)
	original := k.GetParams(ctx)
	require.NotNil(t, original.PendingEmergency)
	cdc, ok := k.Codec().(codec.Codec)
	require.True(t, ok)
	require.Error(t, k.ValidateZeroHeightExport(ctx.WithBlockHeight(101)))
	for _, h := range []int64{101, 102, 109, 110, 122} {
		exported := ExportGenesis(ctx.WithBlockHeight(h), k)
		require.NoError(t, types.ValidateGenesis(*exported))
		bz := cdc.MustMarshalJSON(exported)
		var decoded types.GenesisState
		require.NoError(t, cdc.UnmarshalJSON(bz, &decoded))
		restoredCtx, restored := setupGenesisTest(t, h)
		InitGenesis(restoredCtx, restored, decoded)
		require.Equal(t, original.Effective(h), restored.GetParams(restoredCtx))
		for _, future := range []int64{h, 125} {
			active, err := restored.NormalizeParams(restoredCtx.WithBlockHeight(future))
			require.NoError(t, err)
			require.Equal(t, original.Effective(future), active)
		}
	}
}
