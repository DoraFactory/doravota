package keeper

import (
	"context"

	errorsmod "cosmossdk.io/errors"
	sdk "github.com/cosmos/cosmos-sdk/types"
	sdkerrors "github.com/cosmos/cosmos-sdk/types/errors"

	"github.com/DoraFactory/doravota/x/sponsor-contract-tx/types"
)

// Ensure Server implements the protobuf QueryServer interface
var _ types.QueryServer = QueryServer{}

// Server wraps the Keeper to implement the gRPC QueryServer interface
type QueryServer struct {
	types.UnimplementedQueryServer
	Keeper
}

// NewQueryServer creates a new QueryServer instance
func NewQueryServer(keeper Keeper) types.QueryServer {
	return &QueryServer{
		UnimplementedQueryServer: types.UnimplementedQueryServer{},
		Keeper:                   keeper,
	}
}

// Sponsor implements the gRPC Sponsor query
func (q QueryServer) Sponsor(goCtx context.Context, req *types.QuerySponsorRequest) (*types.QuerySponsorResponse, error) {
	if req == nil {
		return nil, errorsmod.Wrap(sdkerrors.ErrInvalidRequest, "invalid request")
	}

	ctx := sdk.UnwrapSDKContext(goCtx)

	// Validate contract address
	if req.ContractAddress == "" {
		return nil, errorsmod.Wrap(sdkerrors.ErrInvalidAddress, "contract address cannot be empty")
	}

	_, err := sdk.AccAddressFromBech32(req.ContractAddress)
	if err != nil {
		return nil, errorsmod.Wrapf(sdkerrors.ErrInvalidAddress, "invalid contract address: %s", req.ContractAddress)
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

// AllSponsors implements the gRPC AllSponsors query with pagination support
func (q QueryServer) AllSponsors(goCtx context.Context, req *types.QueryAllSponsorsRequest) (*types.QueryAllSponsorsResponse, error) {
	if req == nil {
		return nil, errorsmod.Wrap(sdkerrors.ErrInvalidRequest, "invalid request")
	}

	ctx := sdk.UnwrapSDKContext(goCtx)

	// Use pagination support
	sponsors, pageRes, err := q.Keeper.GetSponsorsPaginated(ctx, req.Pagination)
	if err != nil {
		return nil, err
	}

	return &types.QueryAllSponsorsResponse{
		Sponsors:   sponsors,
		Pagination: pageRes,
	}, nil
}

// Params implements the gRPC Params query
func (q QueryServer) Params(goCtx context.Context, req *types.QueryParamsRequest) (*types.QueryParamsResponse, error) {
	if req == nil {
		return nil, errorsmod.Wrap(sdkerrors.ErrInvalidRequest, "invalid request")
	}

	ctx := sdk.UnwrapSDKContext(goCtx)

	// Get module parameters
	params := q.Keeper.GetParams(ctx)

	return &types.QueryParamsResponse{
		Params: params,
	}, nil
}

// UserGrantUsage implements the gRPC UserGrantUsage query
func (q QueryServer) UserGrantUsage(goCtx context.Context, req *types.QueryUserGrantUsageRequest) (*types.QueryUserGrantUsageResponse, error) {
	if req == nil {
		return nil, errorsmod.Wrap(sdkerrors.ErrInvalidRequest, "invalid request")
	}

	ctx := sdk.UnwrapSDKContext(goCtx)

	// Validate user address
	if req.UserAddress == "" {
		return nil, errorsmod.Wrap(sdkerrors.ErrInvalidAddress, "user address cannot be empty")
	}

	_, err := sdk.AccAddressFromBech32(req.UserAddress)
	if err != nil {
		return nil, errorsmod.Wrapf(sdkerrors.ErrInvalidAddress, "invalid user address: %s", req.UserAddress)
	}

	// Validate contract address
	if req.ContractAddress == "" {
		return nil, errorsmod.Wrap(sdkerrors.ErrInvalidAddress, "contract address cannot be empty")
	}

	_, err = sdk.AccAddressFromBech32(req.ContractAddress)
	if err != nil {
		return nil, errorsmod.Wrapf(sdkerrors.ErrInvalidAddress, "invalid contract address: %s", req.ContractAddress)
	}

	// Get user grant usage
	usage := q.Keeper.GetUserGrantUsage(ctx, req.UserAddress, req.ContractAddress)

	return &types.QueryUserGrantUsageResponse{
		Usage: &usage,
	}, nil
}
