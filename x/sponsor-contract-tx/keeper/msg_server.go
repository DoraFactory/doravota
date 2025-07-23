package keeper

import (
	"context"
	"fmt"

	sdk "github.com/cosmos/cosmos-sdk/types"
	sdkerrors "github.com/cosmos/cosmos-sdk/types/errors"

	"github.com/DoraFactory/doravota/x/sponsor-contract-tx/types"
)

// msgServer implements the MsgServer interface
type msgServer struct {
	types.UnimplementedMsgServer
	Keeper
}

// NewMsgServerImpl returns an implementation of the MsgServer interface
func NewMsgServerImpl(keeper Keeper) types.MsgServer {
	return &msgServer{Keeper: keeper}
}

var _ types.MsgServer = msgServer{}

// SetSponsor handles MsgSetSponsor
func (k msgServer) SetSponsor(goCtx context.Context, msg *types.MsgSetSponsor) (*types.MsgSetSponsorResponse, error) {
	ctx := sdk.UnwrapSDKContext(goCtx)

	// Check if sponsor already exists
	if k.HasSponsor(ctx, msg.ContractAddress) {
		return nil, sdkerrors.Wrap(sdkerrors.ErrInvalidRequest, "sponsor already exists")
	}

	// Verify that the creator is the admin of the contract
	creatorAddr, err := sdk.AccAddressFromBech32(msg.Creator)
	if err != nil {
		return nil, sdkerrors.Wrap(sdkerrors.ErrInvalidAddress, "invalid creator address")
	}

	isAdmin, err := k.Keeper.IsContractAdmin(ctx, msg.ContractAddress, creatorAddr)
	if err != nil {
		return nil, sdkerrors.Wrap(sdkerrors.ErrInvalidRequest, fmt.Sprintf("failed to verify contract admin: %s", err.Error()))
	}

	if !isAdmin {
		return nil, sdkerrors.Wrap(sdkerrors.ErrUnauthorized, "only contract admin can set sponsor")
	}

	// Create and set the sponsor
	sponsor := types.ContractSponsor{
		ContractAddress: msg.ContractAddress,
		IsSponsored:     msg.IsSponsored,
	}

	k.Keeper.SetSponsor(ctx, sponsor)

	// Emit event
	ctx.EventManager().EmitEvent(
		sdk.NewEvent(
			"set_sponsor",
			sdk.NewAttribute("creator", msg.Creator),
			sdk.NewAttribute("contract_address", msg.ContractAddress),
			sdk.NewAttribute("is_sponsored", fmt.Sprintf("%t", msg.IsSponsored)),
		),
	)

	return &types.MsgSetSponsorResponse{}, nil
}

// UpdateSponsor handles MsgUpdateSponsor
func (k msgServer) UpdateSponsor(goCtx context.Context, msg *types.MsgUpdateSponsor) (*types.MsgUpdateSponsorResponse, error) {
	ctx := sdk.UnwrapSDKContext(goCtx)

	// Check if sponsor exists
	if !k.HasSponsor(ctx, msg.ContractAddress) {
		return nil, sdkerrors.Wrap(sdkerrors.ErrInvalidRequest, "sponsor not found")
	}

	// Verify that the creator is the admin of the contract
	creatorAddr, err := sdk.AccAddressFromBech32(msg.Creator)
	if err != nil {
		return nil, sdkerrors.Wrap(sdkerrors.ErrInvalidAddress, "invalid creator address")
	}

	isAdmin, err := k.Keeper.IsContractAdmin(ctx, msg.ContractAddress, creatorAddr)
	if err != nil {
		return nil, sdkerrors.Wrap(sdkerrors.ErrInvalidRequest, fmt.Sprintf("failed to verify contract admin: %s", err.Error()))
	}

	if !isAdmin {
		return nil, sdkerrors.Wrap(sdkerrors.ErrUnauthorized, "only contract admin can update sponsor")
	}

	// Update the sponsor
	sponsor := types.ContractSponsor{
		ContractAddress: msg.ContractAddress,
		IsSponsored:     msg.IsSponsored,
	}

	k.Keeper.SetSponsor(ctx, sponsor)

	// Emit event
	ctx.EventManager().EmitEvent(
		sdk.NewEvent(
			"update_sponsor",
			sdk.NewAttribute("creator", msg.Creator),
			sdk.NewAttribute("contract_address", msg.ContractAddress),
			sdk.NewAttribute("is_sponsored", fmt.Sprintf("%t", msg.IsSponsored)),
		),
	)

	return &types.MsgUpdateSponsorResponse{}, nil
}

// DeleteSponsor handles MsgDeleteSponsor
func (k msgServer) DeleteSponsor(goCtx context.Context, msg *types.MsgDeleteSponsor) (*types.MsgDeleteSponsorResponse, error) {
	ctx := sdk.UnwrapSDKContext(goCtx)

	// Check if sponsor exists
	if !k.HasSponsor(ctx, msg.ContractAddress) {
		return nil, sdkerrors.Wrap(sdkerrors.ErrInvalidRequest, "sponsor not found")
	}

	// Verify that the creator is the admin of the contract
	creatorAddr, err := sdk.AccAddressFromBech32(msg.Creator)
	if err != nil {
		return nil, sdkerrors.Wrap(sdkerrors.ErrInvalidAddress, "invalid creator address")
	}

	isAdmin, err := k.Keeper.IsContractAdmin(ctx, msg.ContractAddress, creatorAddr)
	if err != nil {
		return nil, sdkerrors.Wrap(sdkerrors.ErrInvalidRequest, fmt.Sprintf("failed to verify contract admin: %s", err.Error()))
	}

	if !isAdmin {
		return nil, sdkerrors.Wrap(sdkerrors.ErrUnauthorized, "only contract admin can delete sponsor")
	}

	// Delete the sponsor
	k.Keeper.DeleteSponsor(ctx, msg.ContractAddress)

	// Emit event
	ctx.EventManager().EmitEvent(
		sdk.NewEvent(
			"delete_sponsor",
			sdk.NewAttribute("creator", msg.Creator),
			sdk.NewAttribute("contract_address", msg.ContractAddress),
		),
	)

	return &types.MsgDeleteSponsorResponse{}, nil
}
