package keeper

import (
    "context"

    errorsmod "cosmossdk.io/errors"
    sdk "github.com/cosmos/cosmos-sdk/types"
    sdkerrors "github.com/cosmos/cosmos-sdk/types/errors"
    "github.com/cosmos/cosmos-sdk/types/address"

    "github.com/DoraFactory/doravota/x/sponsor-contract-tx/types"
)

// Ensure Server implements the protobuf QueryServer interface
var _ types.QueryServer = QueryServer{}

// Server wraps the Keeper to implement the gRPC QueryServer interface
type QueryServer struct {
    types.UnimplementedQueryServer
    Keeper
    bankKeeper types.BankKeeper
}

// NewQueryServer creates a new QueryServer instance
func NewQueryServer(keeper Keeper) types.QueryServer {
    return &QueryServer{UnimplementedQueryServer: types.UnimplementedQueryServer{}, Keeper: keeper}
}

// NewQueryServerWithDeps allows wiring optional external keepers (e.g., bank)
func NewQueryServerWithDeps(keeper Keeper, bk types.BankKeeper) types.QueryServer {
    return &QueryServer{UnimplementedQueryServer: types.UnimplementedQueryServer{}, Keeper: keeper, bankKeeper: bk}
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
		return nil, errorsmod.Wrap(sdkerrors.ErrInvalidAddress, "invalid contract address")
	}

	// Get sponsor details
    sponsor, found := q.Keeper.GetSponsor(ctx, req.ContractAddress)
    if !found {
        return &types.QuerySponsorResponse{
            Sponsor: nil,
            EffectiveTicketTtlBlocks: q.Keeper.EffectiveTicketTTLForContract(ctx, req.ContractAddress),
        }, nil
    }

    return &types.QuerySponsorResponse{
        Sponsor: &sponsor,
        EffectiveTicketTtlBlocks: q.Keeper.EffectiveTicketTTLForContract(ctx, req.ContractAddress),
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
		return nil, errorsmod.Wrap(sdkerrors.ErrInvalidAddress, "invalid user address")
	}

	// Validate contract address
	if req.ContractAddress == "" {
		return nil, errorsmod.Wrap(sdkerrors.ErrInvalidAddress, "contract address cannot be empty")
	}

	_, err = sdk.AccAddressFromBech32(req.ContractAddress)
	if err != nil {
		return nil, errorsmod.Wrap(sdkerrors.ErrInvalidAddress, "invalid contract address")
	}

	// Get user grant usage
	usage := q.Keeper.GetUserGrantUsage(ctx, req.UserAddress, req.ContractAddress)

	return &types.QueryUserGrantUsageResponse{
		Usage: &usage,
	}, nil
}

// PolicyTicket implements the gRPC PolicyTicket query
func (q QueryServer) PolicyTicket(goCtx context.Context, req *types.QueryPolicyTicketRequest) (*types.QueryPolicyTicketResponse, error) {
    if req == nil {
        return nil, errorsmod.Wrap(sdkerrors.ErrInvalidRequest, "invalid request")
    }
    ctx := sdk.UnwrapSDKContext(goCtx)
    if err := types.ValidateContractAddress(req.ContractAddress); err != nil {
        return nil, err
    }
    if _, err := sdk.AccAddressFromBech32(req.UserAddress); err != nil {
        return nil, errorsmod.Wrap(sdkerrors.ErrInvalidAddress, "invalid user address")
    }
    if req.Digest == "" {
        return nil, errorsmod.Wrap(sdkerrors.ErrInvalidRequest, "digest required")
    }
    t, found := q.Keeper.GetPolicyTicket(ctx, req.ContractAddress, req.UserAddress, req.Digest)
    if !found {
        return &types.QueryPolicyTicketResponse{Ticket: nil, TtlLeft: 0}, nil
    }
    var ttlLeft uint64
    if uint64(ctx.BlockHeight()) <= t.ExpiryHeight {
        ttlLeft = t.ExpiryHeight - uint64(ctx.BlockHeight())
    } else {
        ttlLeft = 0
    }
    return &types.QueryPolicyTicketResponse{Ticket: &t, TtlLeft: ttlLeft}, nil
}

// PolicyTicketByMethod implements the gRPC PolicyTicketByMethod query
func (q QueryServer) PolicyTicketByMethod(goCtx context.Context, req *types.QueryPolicyTicketByMethodRequest) (*types.QueryPolicyTicketResponse, error) {
    if req == nil {
        return nil, errorsmod.Wrap(sdkerrors.ErrInvalidRequest, "invalid request")
    }
    ctx := sdk.UnwrapSDKContext(goCtx)
    if err := types.ValidateContractAddress(req.ContractAddress); err != nil {
        return nil, err
    }
    if _, err := sdk.AccAddressFromBech32(req.UserAddress); err != nil {
        return nil, errorsmod.Wrap(sdkerrors.ErrInvalidAddress, "invalid user address")
    }
    if req.Method == "" {
        return nil, errorsmod.Wrap(sdkerrors.ErrInvalidRequest, "method required")
    }
    // Enforce method name size limit similar to issuance path
    if lim := q.Keeper.GetParams(ctx).MaxMethodNameBytes; lim != 0 && uint32(len(req.Method)) > lim {
        return nil, errorsmod.Wrap(sdkerrors.ErrInvalidRequest, "method name too long")
    }
    digest := q.Keeper.ComputeMethodDigest(req.ContractAddress, []string{req.Method})
    t, found := q.Keeper.GetPolicyTicket(ctx, req.ContractAddress, req.UserAddress, digest)
    if !found {
        return &types.QueryPolicyTicketResponse{Ticket: nil, TtlLeft: 0}, nil
    }
    var ttlLeft uint64
    if uint64(ctx.BlockHeight()) <= t.ExpiryHeight {
        ttlLeft = t.ExpiryHeight - uint64(ctx.BlockHeight())
    } else {
        ttlLeft = 0
    }
    return &types.QueryPolicyTicketResponse{Ticket: &t, TtlLeft: ttlLeft}, nil
}

// PolicyTickets implements the gRPC PolicyTickets list query with pagination
func (q QueryServer) PolicyTickets(goCtx context.Context, req *types.QueryPolicyTicketsRequest) (*types.QueryPolicyTicketsResponse, error) {
    if req == nil {
        return nil, errorsmod.Wrap(sdkerrors.ErrInvalidRequest, "invalid request")
    }
    ctx := sdk.UnwrapSDKContext(goCtx)
    if err := types.ValidateContractAddress(req.ContractAddress); err != nil {
        return nil, err
    }
    if req.UserAddress != "" {
        if _, err := sdk.AccAddressFromBech32(req.UserAddress); err != nil {
            return nil, errorsmod.Wrap(sdkerrors.ErrInvalidAddress, "invalid user address")
        }
    }
    tickets, pageRes, err := q.Keeper.GetPolicyTicketsPaginated(ctx, req.ContractAddress, req.UserAddress, req.Pagination)
    if err != nil {
        return nil, err
    }
    return &types.QueryPolicyTicketsResponse{Tickets: tickets, Pagination: pageRes}, nil
}

// SponsorBalance returns the derived sponsor address and its spendable peaka balance
func (q QueryServer) SponsorBalance(goCtx context.Context, req *types.QuerySponsorBalanceRequest) (*types.QuerySponsorBalanceResponse, error) {
    if req == nil {
        return nil, errorsmod.Wrap(sdkerrors.ErrInvalidRequest, "invalid request")
    }
    ctx := sdk.UnwrapSDKContext(goCtx)
    if err := types.ValidateContractAddress(req.ContractAddress); err != nil {
        return nil, err
    }
    // Find sponsor address: prefer stored sponsor, otherwise derive
    sponsorAddrStr := ""
    if s, found := q.Keeper.GetSponsor(ctx, req.ContractAddress); found && s.SponsorAddress != "" {
        sponsorAddrStr = s.SponsorAddress
    } else {
        ca, _ := sdk.AccAddressFromBech32(req.ContractAddress)
        sponsorAddrStr = sdk.AccAddress(address.Derive(ca, []byte("sponsor"))).String()
    }
    // If bankKeeper not wired, return zero balance gracefully
    amount := sdk.NewInt(0)
    if q.bankKeeper != nil {
        sAddr, err := sdk.AccAddressFromBech32(sponsorAddrStr)
        if err != nil {
            return nil, errorsmod.Wrap(sdkerrors.ErrInvalidAddress, "invalid sponsor address")
        }
        sc := q.bankKeeper.SpendableCoins(ctx, sAddr)
        amount = sc.AmountOfNoDenomValidation(types.SponsorshipDenom)
    }
    spend := sdk.NewCoin(types.SponsorshipDenom, amount)
    return &types.QuerySponsorBalanceResponse{SponsorAddress: sponsorAddrStr, Spendable: &spend}, nil
}

// Future query extensions can be added here.
