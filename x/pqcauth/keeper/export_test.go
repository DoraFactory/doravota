package keeper

import (
	"testing"

	"github.com/DoraFactory/doravota/x/pqcauth/types"
	"github.com/stretchr/testify/require"
)

func TestZeroHeightExportRequiresHeightIndependentPQCState(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*types.Params)
	}{
		{"registration cutoff", func(p *types.Params) { p.RegistrationCutoffHeight = 20 }},
		{"past registration cutoff", func(p *types.Params) { p.RegistrationCutoffHeight = 5 }},
		{"emergency expiry", func(p *types.Params) {
			p.EmergencyMode = types.EmergencyMode_EMERGENCY_MODE_PAUSE_PQC_TRANSACTIONS
			p.EmergencyExpiresHeight = 20
		}},
		{"pending governance", func(p *types.Params) {
			scheduled := p.AsScheduled()
			p.Pending = &scheduled
			p.PendingActivationHeight = 20
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			k, ctx := setupKeeper(t, 10)
			require.NoError(t, k.ValidateZeroHeightExport(ctx))
			p := k.GetParams(ctx)
			tc.change(&p)
			require.NoError(t, k.SetParams(ctx, p))
			require.ErrorContains(t, k.ValidateZeroHeightExport(ctx), "export without --for-zero-height")
		})
	}
}
