package keeper

import (
	"fmt"
	"testing"

	"github.com/DoraFactory/doravota/x/pqcauth/types"
	"github.com/stretchr/testify/require"
)

func TestEmergencyUpdatePreservesPendingCutoffAndRestrictions(t *testing.T) {
	for _, mode := range []types.EmergencyMode{types.EmergencyMode_EMERGENCY_MODE_PAUSE_NEW_KEYS, types.EmergencyMode_EMERGENCY_MODE_PAUSE_PQC_TRANSACTIONS} {
		for _, cutoff := range []uint64{111, 1000} {
			for _, usePending := range []bool{false, true} {
				for height := int64(101); height < 110; height++ {
					t.Run(fmt.Sprintf("%s/cutoff%d/pending%t/H%d", mode, cutoff, usePending, height), func(t *testing.T) {
						k, ctx := setupKeeper(t, 100)
						base := types.DefaultParams()
						base.GovernanceSafetyDelayBlocks = 10
						require.NoError(t, k.SetParams(ctx, base))
						s := NewMsgServer(k)
						queued := base
						queued.RegistrationCutoffHeight = cutoff
						queued.EnforcementMode = types.EnforcementMode_ENFORCEMENT_MODE_REQUIRED
						queued.MaxPqcSigners = 2
						queued.MaxPqcVerificationsPerTx = 3
						response, err := s.UpdateParams(ctx, &types.MsgUpdateParams{Authority: k.Authority(), Params: queued})
						require.NoError(t, err)
						require.Equal(t, uint64(110), response.ActivationHeight)
						want := base
						if usePending {
							want = queued
						}
						want.EmergencyMode = mode
						at := ctx.WithBlockHeight(height)
						response, err = s.UpdateParams(at, &types.MsgUpdateParams{Authority: k.Authority(), Params: want})
						require.NoError(t, err)
						require.Equal(t, uint64(height+1), response.ActivationHeight)
						stored := k.GetParams(at)
						require.Equal(t, uint64(110), stored.PendingActivationHeight)
						require.Equal(t, withoutEmergency(queued.AsScheduled()), withoutEmergency(*stored.Pending))
						require.Equal(t, types.EmergencyMode_EMERGENCY_MODE_NORMAL, stored.Effective(height).EmergencyMode)
						for h := height + 1; h < 110; h++ {
							p := stored.Effective(h)
							require.Equal(t, mode, p.EmergencyMode)
							require.Equal(t, withoutEmergency(base.AsScheduled()), withoutEmergency(p.AsScheduled()))
						}
						active, err := k.NormalizeParams(ctx.WithBlockHeight(110))
						require.NoError(t, err)
						require.Equal(t, withoutEmergency(queued.AsScheduled()), withoutEmergency(active.AsScheduled()))
						require.Equal(t, mode, active.EmergencyMode)
						require.Nil(t, active.Pending)
						require.Nil(t, active.PendingEmergency)
					})
				}
			}
		}
	}
}

func TestEmergencyUpdateCannotCancelCutoffOrInjectOtherChanges(t *testing.T) {
	k, ctx := setupKeeper(t, 100)
	base := types.DefaultParams()
	base.GovernanceSafetyDelayBlocks = 10
	require.NoError(t, k.SetParams(ctx, base))
	s := NewMsgServer(k)
	queued := base
	queued.RegistrationCutoffHeight = 111
	_, err := s.UpdateParams(ctx, &types.MsgUpdateParams{Authority: k.Authority(), Params: queued})
	require.NoError(t, err)
	before := k.GetParams(ctx)
	// The pure-emergency exception never removes the queued cutoff. Ordinary
	// cancellation or a different cutoff remains forbidden.
	for _, cutoff := range []uint64{0, 112, 1000} {
		bad := base
		bad.RegistrationCutoffHeight = cutoff
		_, err = s.UpdateParams(ctx.WithBlockHeight(101), &types.MsgUpdateParams{Authority: k.Authority(), Params: bad})
		require.Error(t, err)
		require.Equal(t, before, k.GetParams(ctx))
	}
	want := base
	want.EmergencyMode = types.EmergencyMode_EMERGENCY_MODE_PAUSE_NEW_KEYS
	_, err = s.UpdateParams(ctx.WithBlockHeight(101), &types.MsgUpdateParams{Authority: "unauthorized", Params: want})
	require.ErrorIs(t, err, types.ErrInvalidAuthority)
	_, err = s.UpdateParams(ctx.WithBlockHeight(101), &types.MsgUpdateParams{Authority: k.Authority(), Params: want})
	require.NoError(t, err)
	before = k.GetParams(ctx)
	mixed := queued
	mixed.MaxPqcSigners = 2
	_, err = s.UpdateParams(ctx.WithBlockHeight(101), &types.MsgUpdateParams{Authority: k.Authority(), Params: mixed})
	require.ErrorContains(t, err, "H+1 emergency activation")
	require.Equal(t, before, k.GetParams(ctx))
	// Explicitly cancel only the emergency, retaining the original cutoff.
	_, err = s.UpdateParams(ctx.WithBlockHeight(101), &types.MsgUpdateParams{Authority: k.Authority(), Params: base})
	require.NoError(t, err)
	active, err := k.NormalizeParams(ctx.WithBlockHeight(102))
	require.NoError(t, err)
	require.Equal(t, types.EmergencyMode_EMERGENCY_MODE_NORMAL, active.EmergencyMode)
	require.Equal(t, uint64(110), active.PendingActivationHeight)
	require.Equal(t, uint64(111), active.Pending.RegistrationCutoffHeight)
}

func TestEmergencyExpiryDoesNotResurrectAtPendingActivation(t *testing.T) {
	for _, duration := range []uint64{2, 8, 20} {
		t.Run(fmt.Sprint(duration), func(t *testing.T) {
			k, ctx := setupKeeper(t, 100)
			base := types.DefaultParams()
			base.GovernanceSafetyDelayBlocks = 10
			base.MaxEmergencyDurationBlocks = duration
			require.NoError(t, k.SetParams(ctx, base))
			queued := base
			queued.RegistrationCutoffHeight = 111
			s := NewMsgServer(k)
			_, err := s.UpdateParams(ctx, &types.MsgUpdateParams{Authority: k.Authority(), Params: queued})
			require.NoError(t, err)
			pause := base
			pause.EmergencyMode = types.EmergencyMode_EMERGENCY_MODE_PAUSE_PQC_TRANSACTIONS
			_, err = s.UpdateParams(ctx.WithBlockHeight(101), &types.MsgUpdateParams{Authority: k.Authority(), Params: pause})
			require.NoError(t, err)
			stored := k.GetParams(ctx)
			// Skipping directly to a height (query/export/restart) and normalizing
			// every block must agree, including simultaneous expiry/activation.
			for h := int64(102); h <= 125; h++ {
				direct := stored.Effective(h)
				sequential, err := k.NormalizeParams(ctx.WithBlockHeight(h))
				require.NoError(t, err)
				require.Equal(t, direct, sequential)
				want := types.EmergencyMode_EMERGENCY_MODE_PAUSE_PQC_TRANSACTIONS
				if uint64(h) >= 102+duration {
					want = types.EmergencyMode_EMERGENCY_MODE_NORMAL
				}
				require.Equal(t, want, sequential.EmergencyMode)
			}
		})
	}
}
