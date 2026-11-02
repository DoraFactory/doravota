package keeper

import (
	"fmt"
	"testing"

	"github.com/DoraFactory/doravota/x/pqcauth/types"
	"github.com/stretchr/testify/require"
)

func TestEmergencyOnlyRejectsSameBlockFullUpdate(t *testing.T) {
	for _, mode := range []types.EmergencyMode{types.EmergencyMode_EMERGENCY_MODE_NORMAL, types.EmergencyMode_EMERGENCY_MODE_PAUSE_NEW_KEYS, types.EmergencyMode_EMERGENCY_MODE_PAUSE_PQC_TRANSACTIONS} {
		for _, ordinary := range []bool{false, true} {
			for _, tighten := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/ordinary=%t/tighten=%t", mode, ordinary, tighten), func(t *testing.T) {
					k, ctx := setupKeeper(t, 100)
					base := types.DefaultParams()
					base.GovernanceSafetyDelayBlocks = 10
					base.MaxEmergencyDurationBlocks = 30
					require.NoError(t, k.SetParams(ctx, base))
					s := NewMsgServer(k)
					if ordinary {
						queued := base
						queued.EnforcementMode = types.EnforcementMode_ENFORCEMENT_MODE_REQUIRED_FOR_REGISTERED
						_, err := s.UpdateParams(ctx, &types.MsgUpdateParams{Authority: k.Authority(), Params: queued})
						require.NoError(t, err)
					}
					pause := base
					pause.EmergencyMode = mode
					r, err := s.UpdateParams(ctx, &types.MsgUpdateParams{Authority: k.Authority(), Params: pause, EmergencyOnly: true})
					require.NoError(t, err)
					before := k.GetParams(ctx)
					require.Equal(t, before, r.ResultingParams)
					require.NoError(t, before.Validate())
					require.NotNil(t, before.PendingEmergency)
					require.Equal(t, uint64(101), before.PendingEmergency.ActivationHeight)
					wantExpiry := uint64(131)
					if mode == types.EmergencyMode_EMERGENCY_MODE_NORMAL {
						wantExpiry = 0
					}
					require.Equal(t, wantExpiry, before.PendingEmergency.ExpiresHeight)
					full := base // Prepared from state before the emergency update.
					if tighten {
						full.EnforcementMode = types.EnforcementMode_ENFORCEMENT_MODE_REQUIRED_FOR_REGISTERED
					}
					r, err = s.UpdateParams(ctx, &types.MsgUpdateParams{Authority: k.Authority(), Params: full})
					require.ErrorContains(t, err, "wait for the H+1 emergency activation")
					require.Nil(t, r)
					require.Equal(t, before, k.GetParams(ctx), "rejected update must not mutate the stored schedule")
					// Equality at H+1 clears the guard. A full update can then keep
					// the pause without renewing it, or replace ordinary restrictions.
					active, err := k.NormalizeParams(ctx.WithBlockHeight(101))
					require.NoError(t, err)
					require.Equal(t, before.Effective(101), active)
					require.Nil(t, active.PendingEmergency)
					require.Equal(t, mode, active.EmergencyMode)
					if ordinary {
						require.Equal(t, uint64(110), active.PendingActivationHeight)
					} else {
						require.Nil(t, active.Pending)
					}
					full.EmergencyMode = mode
					r, err = s.UpdateParams(ctx.WithBlockHeight(101), &types.MsgUpdateParams{Authority: k.Authority(), Params: full})
					require.NoError(t, err)
					require.Equal(t, k.GetParams(ctx), r.ResultingParams)
					stored := k.GetParams(ctx)
					for h := int64(101); h <= 132; h++ {
						p, err := k.NormalizeParams(ctx.WithBlockHeight(h))
						require.NoError(t, err)
						require.Equal(t, stored.Effective(h), p)
						wantMode := mode
						if h >= 131 {
							wantMode = types.EmergencyMode_EMERGENCY_MODE_NORMAL
						}
						require.Equal(t, wantMode, p.EmergencyMode)
						wantEnforcement := types.EnforcementMode_ENFORCEMENT_MODE_OPTIONAL
						if tighten && h >= 111 {
							wantEnforcement = types.EnforcementMode_ENFORCEMENT_MODE_REQUIRED_FOR_REGISTERED
						}
						require.Equal(t, wantEnforcement, p.EnforcementMode)
					}
				})
			}
		}
	}
}

func TestEmergencyOnlySameBlockExplicitReplacement(t *testing.T) {
	for _, ordinary := range []bool{false, true} {
		for _, mode := range []types.EmergencyMode{types.EmergencyMode_EMERGENCY_MODE_NORMAL, types.EmergencyMode_EMERGENCY_MODE_PAUSE_NEW_KEYS, types.EmergencyMode_EMERGENCY_MODE_PAUSE_PQC_TRANSACTIONS} {
			t.Run(fmt.Sprintf("ordinary=%t/%s", ordinary, mode), func(t *testing.T) {
				k, ctx := setupKeeper(t, 100)
				base := types.DefaultParams()
				base.GovernanceSafetyDelayBlocks = 10
				require.NoError(t, k.SetParams(ctx, base))
				s := NewMsgServer(k)
				if ordinary {
					queued := base
					queued.RegistrationCutoffHeight = 111
					_, err := s.UpdateParams(ctx, &types.MsgUpdateParams{Authority: k.Authority(), Params: queued})
					require.NoError(t, err)
				}
				pause := base
				pause.EmergencyMode = types.EmergencyMode_EMERGENCY_MODE_PAUSE_PQC_TRANSACTIONS
				_, err := s.UpdateParams(ctx, &types.MsgUpdateParams{Authority: k.Authority(), Params: pause, EmergencyOnly: true})
				require.NoError(t, err)
				pause.EmergencyMode = mode
				r, err := s.UpdateParams(ctx, &types.MsgUpdateParams{Authority: k.Authority(), Params: pause, EmergencyOnly: true})
				require.NoError(t, err, "explicit replacement/renewal/release remains authorized")
				require.Equal(t, mode, r.ResultingParams.PendingEmergency.Mode)
				require.Equal(t, uint64(101), r.ActivationHeight)
				if ordinary {
					require.Equal(t, uint64(110), r.ResultingParams.PendingActivationHeight)
					require.Equal(t, uint64(111), r.ResultingParams.Pending.RegistrationCutoffHeight)
				}
				active, err := k.NormalizeParams(ctx.WithBlockHeight(101))
				require.NoError(t, err)
				require.Equal(t, mode, active.EmergencyMode)
				require.Nil(t, active.PendingEmergency)
				if ordinary {
					_, err = s.UpdateParams(ctx.WithBlockHeight(101), &types.MsgUpdateParams{Authority: k.Authority(), Params: pause})
					require.ErrorContains(t, err, "irreversible")
				}
			})
		}
	}
}
