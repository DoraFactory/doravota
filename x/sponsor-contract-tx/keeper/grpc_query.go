package keeper

import (
	"context"

	"github.com/DoraFactory/doravota/x/sponsor-contract-tx/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
	sdkerrors "github.com/cosmos/cosmos-sdk/types/errors"
)

// Ensure QueryServer implements the protobuf QueryServer interface
var _ types.QueryServer = QueryServer{}

// QueryServer wraps the Keeper to implement the gRPC QueryServer interface
type QueryServer struct {
	Keeper
}

// NewQueryServer creates a new QueryServer instance
func NewQueryServer(keeper Keeper) types.QueryServer {
	return &QueryServer{Keeper: keeper}
}

// IsSponsored implements the gRPC IsSponsored query
func (q QueryServer) IsSponsored(goCtx context.Context, req *types.QueryIsSponsoredRequest) (*types.QueryIsSponsoredResponse, error) {
	if req == nil {
		return nil, sdkerrors.Wrap(sdkerrors.ErrInvalidRequest, "invalid request")
	}

	ctx := sdk.UnwrapSDKContext(goCtx)

	// Validate contract address
	if req.ContractAddress == "" {
		return nil, sdkerrors.Wrap(sdkerrors.ErrInvalidAddress, "contract address cannot be empty")
	}

	_, err := sdk.AccAddressFromBech32(req.ContractAddress)
	if err != nil {
		return nil, sdkerrors.Wrapf(sdkerrors.ErrInvalidAddress, "invalid contract address: %s", req.ContractAddress)
	}

	// Check if contract is sponsored using the keeper method
	isSponsored := q.Keeper.IsSponsored(ctx, req.ContractAddress)

	return &types.QueryIsSponsoredResponse{
		IsSponsored: isSponsored,
	}, nil
}

// Sponsor implements the gRPC Sponsor query
func (q QueryServer) Sponsor(goCtx context.Context, req *types.QuerySponsorRequest) (*types.QuerySponsorResponse, error) {
	if req == nil {
		return nil, sdkerrors.Wrap(sdkerrors.ErrInvalidRequest, "invalid request")
	}

	ctx := sdk.UnwrapSDKContext(goCtx)

	// Validate contract address
	if req.ContractAddress == "" {
		return nil, sdkerrors.Wrap(sdkerrors.ErrInvalidAddress, "contract address cannot be empty")
	}

	_, err := sdk.AccAddressFromBech32(req.ContractAddress)
	if err != nil {
		return nil, sdkerrors.Wrapf(sdkerrors.ErrInvalidAddress, "invalid contract address: %s", req.ContractAddress)
	}

	// Get sponsor details
	sponsor, found := q.Keeper.GetSponsor(ctx, req.ContractAddress)
	if !found {
		return &types.QuerySponsorResponse{
			Sponsor: nil,
		}, nil
	}

	return &types.QuerySponsorResponse{
		Sponsor: &sponsor,
	}, nil
}

// AllSponsors implements the gRPC AllSponsors query
func (q QueryServer) AllSponsors(goCtx context.Context, req *types.QueryAllSponsorsRequest) (*types.QueryAllSponsorsResponse, error) {
	if req == nil {
		return nil, sdkerrors.Wrap(sdkerrors.ErrInvalidRequest, "invalid request")
	}

	ctx := sdk.UnwrapSDKContext(goCtx)

	// Get all sponsors
	sponsors := q.Keeper.GetAllSponsors(ctx)

	// Convert []ContractSponsor to []*ContractSponsor
	sponsorPtrs := make([]*types.ContractSponsor, len(sponsors))
	for i := range sponsors {
		sponsorPtrs[i] = &sponsors[i]
	}

	return &types.QueryAllSponsorsResponse{
		Sponsors: sponsorPtrs,
	}, nil
}
