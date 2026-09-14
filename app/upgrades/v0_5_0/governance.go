package v0_5_0

import (
	"fmt"
	"time"

	sdkmath "cosmossdk.io/math"
	sdk "github.com/cosmos/cosmos-sdk/types"
	govv1 "github.com/cosmos/cosmos-sdk/x/gov/types/v1"
)

// ApprovedGovernanceParams applies the approved policy choices after
// SDK migration. It must not replace the other parameters with defaults.
// 110,000 DORA, with 18 decimal places, is 110000000000000000000000 peaka.
func ApprovedGovernanceParams(params govv1.Params) (govv1.Params, error) {
	expeditedVotingPeriod := 23 * time.Hour
	params.ExpeditedVotingPeriod = &expeditedVotingPeriod
	params.MinDepositRatio = sdkmath.LegacyZeroDec().String()
	params.ProposalCancelRatio = sdkmath.LegacyZeroDec().String()
	params.ExpeditedMinDeposit = sdk.NewCoins(sdk.NewCoin("peaka",
		sdkmath.NewInt(110_000).Mul(sdkmath.NewInt(1_000_000_000_000_000_000))))
	if err := params.ValidateBasic(); err != nil {
		return govv1.Params{}, fmt.Errorf("approved governance parameters conflict with source chain parameters: %w", err)
	}
	return params, nil
}
