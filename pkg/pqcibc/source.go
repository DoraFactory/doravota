package pqcibc

import (
	"context"
	"fmt"
	"math"

	cmttypes "github.com/cometbft/cometbft/types"

	clienttypes "github.com/cosmos/ibc-go/v11/modules/core/02-client/types"
	ibctm "github.com/cosmos/ibc-go/v11/modules/light-clients/07-tendermint"
)

// LightBlockSource is satisfied by CometBFT light providers. Production
// relayers must supply a source that verifies the RPC responses against a
// trusted light-store root; a raw RPC client is not a trust anchor.
type LightBlockSource interface {
	LightBlock(context.Context, int64) (*cmttypes.LightBlock, error)
}

// BuildUpdateHeaderFromSource obtains both validator sets through a verified
// light provider and constructs an ML-DSA-aware 07-tendermint update. Querying
// trustedHeight+1 matches the NextValidatorsHash committed at trustedHeight.
func BuildUpdateHeaderFromSource(
	ctx context.Context,
	source LightBlockSource,
	targetHeight int64,
	trustedHeight clienttypes.Height,
	limits HeaderLimits,
) (*ibctm.Header, HeaderStats, error) {
	if source == nil {
		return nil, HeaderStats{}, fmt.Errorf("light block source is nil")
	}
	if targetHeight <= 0 {
		return nil, HeaderStats{}, fmt.Errorf("target height must be positive")
	}
	if trustedHeight.IsZero() {
		return nil, HeaderStats{}, fmt.Errorf("trusted height must be non-zero")
	}
	if trustedHeight.RevisionHeight >= uint64(math.MaxInt64) {
		return nil, HeaderStats{}, fmt.Errorf("trusted height %d exceeds CometBFT height range", trustedHeight.RevisionHeight)
	}
	latest, err := source.LightBlock(ctx, targetHeight)
	if err != nil {
		return nil, HeaderStats{}, fmt.Errorf("load verified light block at height %d: %w", targetHeight, err)
	}
	if latest == nil || latest.SignedHeader == nil || latest.Height != targetHeight {
		return nil, HeaderStats{}, fmt.Errorf("light provider returned an unexpected target height")
	}
	trustedValidatorHeight := int64(trustedHeight.RevisionHeight + 1)
	trusted, err := source.LightBlock(ctx, trustedValidatorHeight)
	if err != nil {
		return nil, HeaderStats{}, fmt.Errorf("load verified trusted validator set at height %d: %w", trustedValidatorHeight, err)
	}
	if trusted == nil || trusted.SignedHeader == nil || trusted.Height != trustedValidatorHeight {
		return nil, HeaderStats{}, fmt.Errorf("light provider returned an unexpected trusted-validator height")
	}
	header, stats, err := BuildUpdateHeader(latest, trustedHeight, trusted.ValidatorSet, limits)
	if err != nil {
		return nil, HeaderStats{}, err
	}
	return header, stats, nil
}
