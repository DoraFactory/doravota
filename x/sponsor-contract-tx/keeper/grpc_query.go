package keeper

import (
	"bytes"
	"context"

	errorsmod "cosmossdk.io/errors"
	"github.com/cosmos/cosmos-sdk/store/prefix"
	sdk "github.com/cosmos/cosmos-sdk/types"
	sdkerrors "github.com/cosmos/cosmos-sdk/types/errors"
	qtypes "github.com/cosmos/cosmos-sdk/types/query"

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

// BlockedStatus implements the gRPC BlockedStatus query
func (q QueryServer) BlockedStatus(goCtx context.Context, req *types.QueryBlockedStatusRequest) (*types.QueryBlockedStatusResponse, error) {
	if req == nil {
		return nil, errorsmod.Wrap(sdkerrors.ErrInvalidRequest, "invalid request")
	}

	ctx := sdk.UnwrapSDKContext(goCtx)

	if req.ContractAddress == "" {
		return nil, errorsmod.Wrap(sdkerrors.ErrInvalidAddress, "contract address cannot be empty")
	}
	if req.UserAddress == "" {
		return nil, errorsmod.Wrap(sdkerrors.ErrInvalidAddress, "user address cannot be empty")
	}
	if _, err := sdk.AccAddressFromBech32(req.ContractAddress); err != nil {
		return nil, errorsmod.Wrapf(sdkerrors.ErrInvalidAddress, "invalid contract address: %s", req.ContractAddress)
	}
	if _, err := sdk.AccAddressFromBech32(req.UserAddress); err != nil {
		return nil, errorsmod.Wrapf(sdkerrors.ErrInvalidAddress, "invalid user address: %s", req.UserAddress)
	}

	rec, found := q.Keeper.GetFailedAttempts(ctx, req.ContractAddress, req.UserAddress)
	if !found {
		return &types.QueryBlockedStatusResponse{Blocked: false, RemainingBlocks: 0, Count: 0, UntilHeight: 0}, nil
	}

	curH := ctx.BlockHeight()
	var remaining uint32
	var blocked bool
	if rec.UntilHeight > curH {
		blocked = true
		remaining = uint32(rec.UntilHeight - curH)
	}
	return &types.QueryBlockedStatusResponse{
		Blocked:         blocked,
		RemainingBlocks: remaining,
		Count:           rec.Count,
		UntilHeight:     rec.UntilHeight,
	}, nil
}

// AllBlockedStatuses implements the gRPC AllBlockedStatuses query with optional filtering and pagination
func (q QueryServer) AllBlockedStatuses(goCtx context.Context, req *types.QueryAllBlockedStatusesRequest) (*types.QueryAllBlockedStatusesResponse, error) {
	if req == nil {
		return nil, errorsmod.Wrap(sdkerrors.ErrInvalidRequest, "invalid request")
	}

	ctx := sdk.UnwrapSDKContext(goCtx)

	// Optional filter validation
	if req.ContractAddress != "" {
		if _, err := sdk.AccAddressFromBech32(req.ContractAddress); err != nil {
			return nil, errorsmod.Wrapf(sdkerrors.ErrInvalidAddress, "invalid contract address: %s", req.ContractAddress)
		}
	}

	curH := ctx.BlockHeight()
	params := q.Keeper.GetParams(ctx)

	store := prefix.NewStore(ctx.KVStore(q.Keeper.storeKey), types.FailedAttemptsKeyPrefix)

	var entries []*types.BlockedStatusEntry
	pageRes, err := qtypes.FilteredPaginate(store, req.Pagination, func(key []byte, value []byte, accumulate bool) (bool, error) {
		// Key format within prefix store: contract + "/" + user
		parts := bytes.SplitN(key, []byte("/"), 2)
		if len(parts) != 2 {
			return false, nil
		}
		contract := string(parts[0])
		user := string(parts[1])

		// Filter by contract if provided
		if req.ContractAddress != "" && contract != req.ContractAddress {
			return false, nil
		}

		var rec types.FailedAttempts
		if err := q.Keeper.cdc.Unmarshal(value, &rec); err != nil {
			return false, nil
		}

		// Skip expired entries (not blocked and window expired)
		if rec.UntilHeight < curH {
			if rec.WindowStartHeight == 0 || (curH-rec.WindowStartHeight) > int64(params.GlobalWindowBlocks) {
				return false, nil
			}
		}

		blocked := rec.UntilHeight > curH
		if req.OnlyBlocked && !blocked {
			return false, nil
		}

		if accumulate {
			var remain uint32
			if blocked {
				remain = uint32(rec.UntilHeight - curH)
			}
			entries = append(entries, &types.BlockedStatusEntry{
				ContractAddress: contract,
				UserAddress:     user,
				Blocked:         blocked,
				RemainingBlocks: remain,
				Count:           rec.Count,
				UntilHeight:     rec.UntilHeight,
			})
		}
		return true, nil
	})
	if err != nil {
		return nil, err
	}

	return &types.QueryAllBlockedStatusesResponse{
		Statuses:   entries,
		Pagination: pageRes,
	}, nil
}
