package keeper

import (
	"testing"

	"github.com/DoraFactory/doravota/x/pqcauth/types"
	tmproto "github.com/cometbft/cometbft/proto/tendermint/types"
	"github.com/stretchr/testify/require"
)

func TestGovernanceCapacityUsesCurrentConsensusGas(t *testing.T) {
	for _, limit := range []int64{600_000_000, 640_000_001, -1, 0} {
		k, ctx := setupKeeper(t, 10)
		ctx = ctx.WithConsensusParams(tmproto.ConsensusParams{Block: &tmproto.BlockParams{MaxGas: limit}})
		p := types.DefaultParams()
		require.NoError(t, k.SetParams(ctx, p))
		requested := p
		requested.MaxPqcVerificationsPerTx = types.AbsoluteMaxPQCVerificationsPerTx
		requested.SignatureVerificationGas, requested.ProofVerificationGas = types.AbsoluteMaxVerificationGas, types.AbsoluteMaxVerificationGas
		_, err := NewMsgServer(k).UpdateParams(ctx, &types.MsgUpdateParams{Authority: k.Authority(), Params: requested})
		if limit == 600_000_000 || limit == 0 {
			require.ErrorContains(t, err, "block max_gas")
			require.Equal(t, p, k.GetParams(ctx))
		} else {
			require.NoError(t, err)
		}
	}
}

func TestCapacityPreflightPreservesEmergencyGovernance(t *testing.T) {
	k, ctx := setupKeeper(t, 10)
	ctx = ctx.WithConsensusParams(tmproto.ConsensusParams{Block: &tmproto.BlockParams{MaxGas: 600_000_000}})
	p := types.DefaultParams()
	require.NoError(t, k.SetParams(ctx, p))
	p.EmergencyMode = types.EmergencyMode_EMERGENCY_MODE_PAUSE_NEW_KEYS
	_, err := NewMsgServer(k).UpdateParams(ctx, &types.MsgUpdateParams{Authority: k.Authority(), Params: p})
	require.NoError(t, err, "handler, not the caller, assigns emergency expiration")
	// An independently lowered block cap must not make parameter normalization
	// fail and halt the chain at the next BeginBlock.
	ctx = ctx.WithBlockHeight(11).WithConsensusParams(tmproto.ConsensusParams{Block: &tmproto.BlockParams{MaxGas: 1}})
	_, err = k.NormalizeParams(ctx)
	require.NoError(t, err)
	requested := k.GetParams(ctx).Effective(ctx.BlockHeight())
	requested.EmergencyMode = types.EmergencyMode_EMERGENCY_MODE_PAUSE_PQC_TRANSACTIONS
	requested.EmergencyExpiresHeight = 0
	_, err = NewMsgServer(k).UpdateParams(ctx, &types.MsgUpdateParams{Authority: k.Authority(), Params: requested})
	require.NoError(t, err, "an emergency-only update must remain possible after a block gas reduction")

	// Also exercise exact cancellation, rather than rescheduling an emergency
	// whose expiration is set by the handler.
	k2, ctx2 := setupKeeper(t, 10)
	ctx2 = ctx2.WithConsensusParams(tmproto.ConsensusParams{Block: &tmproto.BlockParams{MaxGas: 1}})
	active := types.DefaultParams()
	require.NoError(t, k2.SetParams(ctx2, active))
	restrictive := active
	restrictive.MaxPqcSigners = 4
	_, err = NewMsgServer(k2).UpdateParams(ctx2, &types.MsgUpdateParams{Authority: k2.Authority(), Params: restrictive})
	require.NoError(t, err)
	require.NotNil(t, k2.GetParams(ctx2).Pending)
	response, err := NewMsgServer(k2).UpdateParams(ctx2, &types.MsgUpdateParams{Authority: k2.Authority(), Params: active})
	require.NoError(t, err)
	require.Zero(t, response.ActivationHeight)
	require.Nil(t, k2.GetParams(ctx2).Pending)
}
