package v0_5_0

import (
	"testing"
	"time"

	sdkmath "cosmossdk.io/math"
	sdk "github.com/cosmos/cosmos-sdk/types"
	govv1 "github.com/cosmos/cosmos-sdk/x/gov/types/v1"
	"github.com/stretchr/testify/require"
)

func TestApprovedGovernanceParamsDoesNotRepairConflictingLegacyPolicy(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*govv1.Params)
		want   string
	}{
		{"ordinary deposit is already 110k", func(p *govv1.Params) {
			p.MinDeposit = sdk.NewCoins(sdk.NewCoin("peaka", sdkmath.NewInt(110_000).Mul(sdkmath.NewInt(1_000_000_000_000_000_000))))
		}, "greater than minimum deposit"},
		{"short rehearsal voting period", func(p *govv1.Params) {
			d := time.Minute
			p.VotingPeriod = &d
		}, "strictly less"},
		{"ordinary voting period equals expedited", func(p *govv1.Params) {
			d := 23 * time.Hour
			p.VotingPeriod = &d
		}, "strictly less"},
		{"higher ordinary threshold", func(p *govv1.Params) { p.Threshold = "0.75" }, "greater than the regular threshold"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := govv1.DefaultParams()
			tc.change(&p)
			before, err := p.Marshal()
			require.NoError(t, err)
			_, err = ApprovedGovernanceParams(p)
			require.ErrorContains(t, err, tc.want)
			after, err := p.Marshal()
			require.NoError(t, err)
			require.Equal(t, before, after, "must not mutate source parameter slices/pointers")
		})
	}
}
