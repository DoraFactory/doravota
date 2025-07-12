package keeper

import (
	abci "github.com/cometbft/cometbft/abci/types"
	"github.com/cosmos/cosmos-sdk/codec"
	sdk "github.com/cosmos/cosmos-sdk/types"
	sdkerrors "github.com/cosmos/cosmos-sdk/types/errors"

	"github.com/DoraFactory/doravota/x/sponsor-contract-tx/types"
)

// Querier function type
type Querier func(ctx sdk.Context, path []string, req abci.RequestQuery) ([]byte, error)

// NewQuerier creates a new querier for sponsor queries
func NewQuerier(k Keeper, legacyQuerierCdc *codec.LegacyAmino) Querier {
	return func(ctx sdk.Context, path []string, req abci.RequestQuery) ([]byte, error) {
		switch path[0] {
		case "is-sponsored":
			return queryIsSponsored(ctx, path[1:], req, k, legacyQuerierCdc)
		case "all-sponsors":
			return queryAllSponsors(ctx, path[1:], req, k, legacyQuerierCdc)
		default:
			return nil, sdkerrors.Wrapf(sdkerrors.ErrUnknownRequest, "unknown %s query endpoint: %s", types.ModuleName, path[0])
		}
	}
}

func queryIsSponsored(ctx sdk.Context, path []string, req abci.RequestQuery, k Keeper, legacyQuerierCdc *codec.LegacyAmino) ([]byte, error) {
	if len(path) < 1 {
		return nil, sdkerrors.Wrap(sdkerrors.ErrInvalidRequest, "contract address is required")
	}

	contractAddr := path[0]
	isSponsored := k.IsSponsored(ctx, contractAddr)

	// Create response
	response := map[string]interface{}{
		"is_sponsored": isSponsored,
	}

	res, err := codec.MarshalJSONIndent(legacyQuerierCdc, response)
	if err != nil {
		return nil, sdkerrors.Wrap(sdkerrors.ErrJSONMarshal, err.Error())
	}

	return res, nil
}

func queryAllSponsors(ctx sdk.Context, path []string, req abci.RequestQuery, k Keeper, legacyQuerierCdc *codec.LegacyAmino) ([]byte, error) {
	sponsors := k.GetAllSponsors(ctx)

	// Create response
	response := map[string]interface{}{
		"sponsors": sponsors,
	}

	res, err := codec.MarshalJSONIndent(legacyQuerierCdc, response)
	if err != nil {
		return nil, sdkerrors.Wrap(sdkerrors.ErrJSONMarshal, err.Error())
	}

	return res, nil
}
