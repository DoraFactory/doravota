package sdk_v053_bridge

import (
	"fmt"

	storetypes "cosmossdk.io/store/types"
	tmproto "github.com/cometbft/cometbft/proto/tendermint/types"
	"github.com/cosmos/cosmos-sdk/codec"
	sdk "github.com/cosmos/cosmos-sdk/types"
)

// v0.4.x mounted a dedicated "consensus" store, but its consensus keeper was
// accidentally constructed with the x/upgrade store key. Consequently the
// canonical consensus record lives at upgrade/Consensus on existing chains.
// This is Doravota-specific and is not covered by the SDK's baseapp x/params
// migration helper.
var legacyConsensusParamsStoreKey = []byte("Consensus")

// LoadLegacyConsensusParams reads the v0.4.x consensus record without mutating
// either the legacy or destination store. A malformed record is fatal: silently
// falling back to partial current-block parameters could make export/restart
// behavior differ after the bridge.
func LoadLegacyConsensusParams(
	ctx sdk.Context,
	legacyStoreKey storetypes.StoreKey,
	cdc codec.BinaryCodec,
) (tmproto.ConsensusParams, bool, error) {
	bz := ctx.KVStore(legacyStoreKey).Get(legacyConsensusParamsStoreKey)
	if len(bz) == 0 {
		return tmproto.ConsensusParams{}, false, nil
	}

	var params tmproto.ConsensusParams
	if err := cdc.Unmarshal(bz, &params); err != nil {
		return tmproto.ConsensusParams{}, false, fmt.Errorf("decode v0.4.x upgrade/Consensus record: %w", err)
	}
	return params, true, nil
}
