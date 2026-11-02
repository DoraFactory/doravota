package keeper

import (
	"fmt"
	"testing"

	"github.com/DoraFactory/doravota/x/pqcauth/types"
	"github.com/stretchr/testify/require"
)

// GOV-02 regression: full updates must honor cancellation while retaining pause.
// Uses the repository's real Keeper, MsgServer, codec and mounted IAVL store.
// setupKeeper's account dependency is stubbed; no account/crypto path is used.
func TestReviewCancelOrdinaryRestrictionWhileKeepingPause(t *testing.T) {
	for _, mode := range []types.EmergencyMode{
		types.EmergencyMode_EMERGENCY_MODE_NORMAL,
		types.EmergencyMode_EMERGENCY_MODE_PAUSE_NEW_KEYS,
		types.EmergencyMode_EMERGENCY_MODE_PAUSE_PQC_TRANSACTIONS,
	} {
		for _, tightBudget := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/tightBudget=%t", mode, tightBudget), func(t *testing.T) {
				k, ctx := setupKeeper(t, 90)
				p := types.DefaultParams()
				p.GovernanceSafetyDelayBlocks = 10
				require.Equal(t, uint64(750), p.SignatureVerificationGas)
				require.Equal(t, uint64(750), p.ProofVerificationGas)
				require.NoError(t, k.SetParams(ctx, p))
				server := NewMsgServer(k)
				if mode != types.EmergencyMode_EMERGENCY_MODE_NORMAL {
					pause := p
					pause.EmergencyMode = mode
					response, err := server.UpdateParams(ctx, &types.MsgUpdateParams{Authority: k.Authority(), Params: pause})
					require.NoError(t, err)
					require.Equal(t, uint64(91), response.ActivationHeight)
				}
				active, err := k.NormalizeParams(ctx.WithBlockHeight(100))
				require.NoError(t, err)
				require.Equal(t, mode, active.EmergencyMode)
				queued := active
				queued.EmergencyExpiresHeight = 0
				queued.Pending = nil
				queued.PendingActivationHeight = 0
				queued.PendingEmergency = nil
				queued.EnforcementMode = types.EnforcementMode_ENFORCEMENT_MODE_REQUIRED_FOR_REGISTERED
				if tightBudget {
					queued.MaxPqcVerificationsPerBlock = 111
				}
				response, err := server.UpdateParams(ctx.WithBlockHeight(100), &types.MsgUpdateParams{Authority: k.Authority(), Params: queued})
				require.NoError(t, err)
				require.Equal(t, uint64(110), response.ActivationHeight)
				cancel := active
				cancel.EmergencyExpiresHeight = 0
				cancel.Pending = nil
				cancel.PendingActivationHeight = 0
				cancel.PendingEmergency = nil
				require.Zero(t, cancel.RegistrationCutoffHeight)
				response, err = server.UpdateParams(ctx.WithBlockHeight(101), &types.MsgUpdateParams{Authority: k.Authority(), Params: cancel})
				require.NoError(t, err)
				stored := k.GetParams(ctx)
				require.Zero(t, response.ActivationHeight)
				require.Equal(t, stored, response.ResultingParams)
				require.Nil(t, stored.Pending)
				require.Equal(t, active.EmergencyExpiresHeight, stored.EmergencyExpiresHeight, "full cancellation must not renew the pause")
				t.Logf("successful response activation=%d; ordinary activation=%d; independent emergency=%v", response.ActivationHeight, stored.PendingActivationHeight, stored.PendingEmergency)
				final, err := k.NormalizeParams(ctx.WithBlockHeight(110))
				require.NoError(t, err)
				t.Logf("H=110 enforcement=%s registration=%s emergency=%s", final.EnforcementMode, final.RegistrationMode, final.EmergencyMode)
				require.Equal(t, mode, final.EmergencyMode)
				require.Equal(t, p.MaxPqcVerificationsPerBlock, final.MaxPqcVerificationsPerBlock, "cancellation must also remove a queued budget restriction")
				if final.EnforcementMode != types.EnforcementMode_ENFORCEMENT_MODE_OPTIONAL {
					t.Errorf("cancellation intent violated: expected OPTIONAL, got %s", final.EnforcementMode)
				}
				if final.RegistrationMode != types.RegistrationMode_REGISTRATION_MODE_OPEN {
					t.Errorf("cancellation intent violated: expected OPEN, got %s", final.RegistrationMode)
				}
			})
		}
	}
}

func TestExplicitEmergencyRenewalPreservesOrdinaryIntent(t *testing.T) {
	for _, mode := range []types.EmergencyMode{types.EmergencyMode_EMERGENCY_MODE_PAUSE_NEW_KEYS, types.EmergencyMode_EMERGENCY_MODE_PAUSE_PQC_TRANSACTIONS} {
		t.Run(mode.String(), func(t *testing.T) {
			k, ctx := setupKeeper(t, 90)
			base := types.DefaultParams()
			base.GovernanceSafetyDelayBlocks = 10
			base.MaxEmergencyDurationBlocks = 30
			require.NoError(t, k.SetParams(ctx, base))
			s := NewMsgServer(k)
			pause := base
			pause.EmergencyMode = mode
			r, err := s.UpdateParams(ctx, &types.MsgUpdateParams{Authority: k.Authority(), Params: pause, EmergencyOnly: true})
			require.NoError(t, err)
			require.Equal(t, uint64(91), r.ActivationHeight)
			require.Equal(t, k.GetParams(ctx), r.ResultingParams)
			active, err := k.NormalizeParams(ctx.WithBlockHeight(100))
			require.NoError(t, err)
			require.Equal(t, uint64(121), active.EmergencyExpiresHeight)
			queued := pause
			queued.EnforcementMode = types.EnforcementMode_ENFORCEMENT_MODE_REQUIRED_FOR_REGISTERED
			queued.MaxPqcVerificationsPerBlock = 111
			_, err = s.UpdateParams(ctx.WithBlockHeight(100), &types.MsgUpdateParams{Authority: k.Authority(), Params: queued})
			require.NoError(t, err)
			r, err = s.UpdateParams(ctx.WithBlockHeight(101), &types.MsgUpdateParams{Authority: k.Authority(), Params: pause, EmergencyOnly: true})
			require.NoError(t, err)
			stored := k.GetParams(ctx)
			require.Equal(t, stored, r.ResultingParams)
			require.Equal(t, uint64(102), r.ActivationHeight)
			require.Equal(t, uint64(110), stored.PendingActivationHeight)
			require.Equal(t, uint64(132), stored.PendingEmergency.ExpiresHeight)
			require.Equal(t, types.EnforcementMode_ENFORCEMENT_MODE_REQUIRED_FOR_REGISTERED, stored.Effective(110).EnforcementMode)
			require.Equal(t, uint32(111), stored.Effective(110).MaxPqcVerificationsPerBlock)
			// Once the explicit renewal activates, an ordinary full cancellation
			// remains possible and preserves that exact expiry, without renewal.
			_, err = k.NormalizeParams(ctx.WithBlockHeight(102))
			require.NoError(t, err)
			r, err = s.UpdateParams(ctx.WithBlockHeight(102), &types.MsgUpdateParams{Authority: k.Authority(), Params: pause})
			require.NoError(t, err)
			require.Nil(t, r.ResultingParams.Pending)
			require.Equal(t, uint64(132), r.ResultingParams.EmergencyExpiresHeight)
			require.Equal(t, types.EnforcementMode_ENFORCEMENT_MODE_OPTIONAL, k.GetParams(ctx).Effective(110).EnforcementMode)
			require.Equal(t, types.EmergencyMode_EMERGENCY_MODE_NORMAL, k.GetParams(ctx).Effective(132).EmergencyMode)
		})
	}
}

func TestEmergencyOnlyRejectsSmuggledChangesAndPreservesOrdinaryPlan(t *testing.T) {
	k, ctx := setupKeeper(t, 100)
	base := types.DefaultParams()
	base.GovernanceSafetyDelayBlocks = 10
	require.NoError(t, k.SetParams(ctx, base))
	s := NewMsgServer(k)
	queued := base
	queued.MaxPqcVerificationsPerBlock = 111
	_, err := s.UpdateParams(ctx, &types.MsgUpdateParams{Authority: k.Authority(), Params: queued})
	require.NoError(t, err)
	before := k.GetParams(ctx)
	for _, mutate := range []func(*types.Params){
		func(p *types.Params) { p.MaxPqcSigners = 2 },
		func(p *types.Params) { p.SignatureVerificationGas = 751 },
		func(p *types.Params) { p.RegistrationCutoffHeight = 112 },
		func(p *types.Params) { p.RegistrationMode = types.RegistrationMode_REGISTRATION_MODE_CLOSED },
		func(p *types.Params) { p.NetworkId = make([]byte, 32) },
		func(p *types.Params) { p.GovernanceSafetyDelayBlocks++ },
		func(p *types.Params) { p.MaxEmergencyDurationBlocks++ },
		func(p *types.Params) { p.RecoveryDelayBlocks++ },
	} {
		bad := base
		bad.EmergencyMode = types.EmergencyMode_EMERGENCY_MODE_PAUSE_NEW_KEYS
		mutate(&bad)
		_, err = s.UpdateParams(ctx.WithBlockHeight(101), &types.MsgUpdateParams{Authority: k.Authority(), Params: bad, EmergencyOnly: true})
		require.Error(t, err)
		require.Equal(t, before, k.GetParams(ctx))
	}
	// Explicit emergency scope preserves the ordinary budget schedule.
	pause := base
	pause.EmergencyMode = types.EmergencyMode_EMERGENCY_MODE_PAUSE_NEW_KEYS
	r, err := s.UpdateParams(ctx.WithBlockHeight(101), &types.MsgUpdateParams{Authority: k.Authority(), Params: pause, EmergencyOnly: true})
	require.NoError(t, err)
	require.Equal(t, uint32(111), r.ResultingParams.Pending.MaxPqcVerificationsPerBlock)
	require.Equal(t, uint64(110), r.ResultingParams.PendingActivationHeight)
	_, err = k.NormalizeParams(ctx.WithBlockHeight(102))
	require.NoError(t, err)
	// After emergency activation, explicit full cancellation remains allowed.
	r, err = s.UpdateParams(ctx.WithBlockHeight(102), &types.MsgUpdateParams{Authority: k.Authority(), Params: pause})
	require.NoError(t, err)
	require.Nil(t, r.ResultingParams.Pending)
	require.Equal(t, types.DefaultMaxPQCVerificationsPerBlock, r.ResultingParams.MaxPqcVerificationsPerBlock)
}

func TestOrdinaryReplacementDoesNotRenewOrResurrectPause(t *testing.T) {
	for _, expiry := range []uint64{105, 111, 120} {
		t.Run(fmt.Sprint(expiry), func(t *testing.T) {
			k, ctx := setupKeeper(t, 100)
			base := types.DefaultParams()
			base.GovernanceSafetyDelayBlocks = 10
			base.EmergencyMode = types.EmergencyMode_EMERGENCY_MODE_PAUSE_NEW_KEYS
			base.EmergencyExpiresHeight = expiry
			require.NoError(t, k.SetParams(ctx, base))
			queued := base
			queued.EmergencyExpiresHeight = 0
			queued.EnforcementMode = types.EnforcementMode_ENFORCEMENT_MODE_REQUIRED_FOR_REGISTERED
			_, err := NewMsgServer(k).UpdateParams(ctx, &types.MsgUpdateParams{Authority: k.Authority(), Params: queued})
			require.NoError(t, err)
			replacement := base
			replacement.EmergencyExpiresHeight = 0
			replacement.MaxPqcSigners = 2
			r, err := NewMsgServer(k).UpdateParams(ctx.WithBlockHeight(101), &types.MsgUpdateParams{Authority: k.Authority(), Params: replacement})
			require.NoError(t, err)
			require.Equal(t, uint64(111), r.ActivationHeight, "explicit ordinary replacement still waits its own safety delay")
			stored := k.GetParams(ctx)
			for h := int64(101); h <= 125; h++ {
				p, err := k.NormalizeParams(ctx.WithBlockHeight(h))
				require.NoError(t, err)
				require.Equal(t, stored.Effective(h), p)
				require.Equal(t, types.EnforcementMode_ENFORCEMENT_MODE_OPTIONAL, p.EnforcementMode, "old REQUIRED plan must not activate")
				wantSigners := base.MaxPqcSigners
				if h >= 111 {
					wantSigners = 2
				}
				require.Equal(t, wantSigners, p.MaxPqcSigners)
				want := base.EmergencyMode
				if uint64(h) >= expiry {
					want = types.EmergencyMode_EMERGENCY_MODE_NORMAL
				}
				require.Equal(t, want, p.EmergencyMode)
			}
		})
	}
}
