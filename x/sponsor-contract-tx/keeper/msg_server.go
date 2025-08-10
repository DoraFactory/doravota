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

	// Check if sponsorship is globally enabled
	params := k.Keeper.GetParams(ctx)
	if !params.SponsorshipEnabled {
		return nil, sdkerrors.Wrap(types.ErrSponsorshipDisabled, "sponsorship is globally disabled")
	}

	// Validate that the contract exists and is valid
	if err := k.Keeper.ValidateContractExists(ctx, msg.ContractAddress); err != nil {
		return nil, err
	}

	// Check if sponsor already exists
	if k.HasSponsor(ctx, msg.ContractAddress) {
		return nil, sdkerrors.Wrap(types.ErrSponsorAlreadyExists, "sponsor already exists")
	}

	// Verify that the creator is the admin of the contract
	creatorAddr, err := sdk.AccAddressFromBech32(msg.Creator)
	if err != nil {
		return nil, sdkerrors.Wrap(types.ErrInvalidCreator, "invalid creator address")
	}

	isAdmin, err := k.Keeper.IsContractAdmin(ctx, msg.ContractAddress, creatorAddr)
	if err != nil {
		return nil, sdkerrors.Wrap(types.ErrContractNotFound, fmt.Sprintf("failed to verify contract admin: %s", err.Error()))
	}

	if !isAdmin {
		return nil, sdkerrors.Wrap(types.ErrContractNotAdmin, "only contract admin can set sponsor")
	}

	// Create and set the sponsor
	now := ctx.BlockTime().Unix()
	sponsor := types.ContractSponsor{
		ContractAddress: msg.ContractAddress,
		CreatorAddress:  msg.Creator, // The address that created this sponsor configuration
		IsSponsored:     msg.IsSponsored,
		CreatedAt:       now,
		UpdatedAt:       now,
		MaxGrantPerUser: msg.MaxGrantPerUser,
	}

	if err := k.Keeper.SetSponsor(ctx, sponsor); err != nil {
		return nil, sdkerrors.Wrap(err, "failed to set sponsor")
	}

	// Emit event using constants
	ctx.EventManager().EmitEvent(
		sdk.NewEvent(
			types.EventTypeSetSponsor,
			sdk.NewAttribute(types.AttributeKeyCreator, msg.Creator),
			sdk.NewAttribute(types.AttributeKeyContractAddress, msg.ContractAddress),
			sdk.NewAttribute(types.AttributeKeyIsSponsored, fmt.Sprintf("%t", msg.IsSponsored)),
		),
	)

	return &types.MsgSetSponsorResponse{}, nil
}

// UpdateSponsor handles MsgUpdateSponsor
func (k msgServer) UpdateSponsor(goCtx context.Context, msg *types.MsgUpdateSponsor) (*types.MsgUpdateSponsorResponse, error) {
	ctx := sdk.UnwrapSDKContext(goCtx)

	// Check if sponsorship is globally enabled
	params := k.Keeper.GetParams(ctx)
	if !params.SponsorshipEnabled {
		return nil, sdkerrors.Wrap(types.ErrSponsorshipDisabled, "sponsorship is globally disabled")
	}

	// Validate that the contract exists and is valid
	if err := k.Keeper.ValidateContractExists(ctx, msg.ContractAddress); err != nil {
		return nil, err
	}

	// Check if sponsor exists
	if !k.HasSponsor(ctx, msg.ContractAddress) {
		return nil, sdkerrors.Wrap(types.ErrSponsorNotFound, "sponsor not found")
	}

	// Verify that the creator is the admin of the contract
	creatorAddr, err := sdk.AccAddressFromBech32(msg.Creator)
	if err != nil {
		return nil, sdkerrors.Wrap(types.ErrInvalidCreator, "invalid creator address")
	}

	isAdmin, err := k.Keeper.IsContractAdmin(ctx, msg.ContractAddress, creatorAddr)
	if err != nil {
		return nil, sdkerrors.Wrap(types.ErrContractNotFound, fmt.Sprintf("failed to verify contract admin: %s", err.Error()))
	}

	if !isAdmin {
		return nil, sdkerrors.Wrap(types.ErrContractNotAdmin, "only contract admin can update sponsor")
	}

	// Get existing sponsor to preserve CreatedAt timestamp
	existingSponsor, found := k.Keeper.GetSponsor(ctx, msg.ContractAddress)
	if !found {
		// This shouldn't happen since we checked above, but handle gracefully
		existingSponsor.CreatedAt = ctx.BlockTime().Unix()
	}

	// Update the sponsor
	sponsor := types.ContractSponsor{
		ContractAddress: msg.ContractAddress,
		CreatorAddress:  existingSponsor.CreatorAddress, // Preserve original creator address
		IsSponsored:     msg.IsSponsored,
		CreatedAt:       existingSponsor.CreatedAt,
		UpdatedAt:       ctx.BlockTime().Unix(),
		MaxGrantPerUser: msg.MaxGrantPerUser,
	}

	if err := k.Keeper.SetSponsor(ctx, sponsor); err != nil {
		return nil, sdkerrors.Wrap(err, "failed to update sponsor")
	}

	// Emit event using constants
	ctx.EventManager().EmitEvent(
		sdk.NewEvent(
			types.EventTypeUpdateSponsor,
			sdk.NewAttribute(types.AttributeKeyCreator, msg.Creator),
			sdk.NewAttribute(types.AttributeKeyContractAddress, msg.ContractAddress),
			sdk.NewAttribute(types.AttributeKeyIsSponsored, fmt.Sprintf("%t", msg.IsSponsored)),
		),
	)

	return &types.MsgUpdateSponsorResponse{}, nil
}

// DeleteSponsor handles MsgDeleteSponsor
func (k msgServer) DeleteSponsor(goCtx context.Context, msg *types.MsgDeleteSponsor) (*types.MsgDeleteSponsorResponse, error) {
	ctx := sdk.UnwrapSDKContext(goCtx)

	// Check if sponsorship is globally enabled
	params := k.Keeper.GetParams(ctx)
	if !params.SponsorshipEnabled {
		return nil, sdkerrors.Wrap(types.ErrSponsorshipDisabled, "sponsorship is globally disabled")
	}

	// Validate that the contract exists and is valid
	if err := k.Keeper.ValidateContractExists(ctx, msg.ContractAddress); err != nil {
		return nil, err
	}

	// Check if sponsor exists
	if !k.HasSponsor(ctx, msg.ContractAddress) {
		return nil, sdkerrors.Wrap(types.ErrSponsorNotFound, "sponsor not found")
	}

	// Verify that the creator is the admin of the contract
	creatorAddr, err := sdk.AccAddressFromBech32(msg.Creator)
	if err != nil {
		return nil, sdkerrors.Wrap(types.ErrInvalidCreator, "invalid creator address")
	}

	isAdmin, err := k.Keeper.IsContractAdmin(ctx, msg.ContractAddress, creatorAddr)
	if err != nil {
		return nil, sdkerrors.Wrap(types.ErrContractNotFound, fmt.Sprintf("failed to verify contract admin: %s", err.Error()))
	}

	if !isAdmin {
		return nil, sdkerrors.Wrap(types.ErrContractNotAdmin, "only contract admin can delete sponsor")
	}

	// Delete the sponsor
	if err := k.Keeper.DeleteSponsor(ctx, msg.ContractAddress); err != nil {
		return nil, sdkerrors.Wrap(err, "failed to delete sponsor")
	}

	// Emit event using constants
	ctx.EventManager().EmitEvent(
		sdk.NewEvent(
			types.EventTypeDeleteSponsor,
			sdk.NewAttribute(types.AttributeKeyCreator, msg.Creator),
			sdk.NewAttribute(types.AttributeKeyContractAddress, msg.ContractAddress),
		),
	)

	return &types.MsgDeleteSponsorResponse{}, nil
}
