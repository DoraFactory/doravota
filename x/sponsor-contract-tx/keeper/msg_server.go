package keeper

import (
	"context"
	"fmt"

	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/cosmos/cosmos-sdk/types/address"
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

	// Additional validation for MaxGrantPerUser - server-side safety check
	if err := types.ValidateMaxGrantPerUserConditional(msg.MaxGrantPerUser, msg.IsSponsored); err != nil {
		return nil, sdkerrors.Wrap(err, "invalid max_grant_per_user in server validation")
	}

	// Generate sponsor address from contract address
	contractAddr, err := sdk.AccAddressFromBech32(msg.ContractAddress)
	if err != nil {
		return nil, sdkerrors.Wrap(types.ErrInvalidContractAddress, "invalid contract address")
	}
	sponsorAddr := sdk.AccAddress(address.Derive(contractAddr, []byte("sponsor")))

	// Create and set the sponsor
	now := ctx.BlockTime().Unix()
	sponsor := types.ContractSponsor{
		ContractAddress: msg.ContractAddress,
		CreatorAddress:  msg.Creator, // The address that created this sponsor configuration
		SponsorAddress:  sponsorAddr.String(), // The derived address that actually pays for sponsorship fees
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
			sdk.NewAttribute(types.AttributeKeySponsorAddress, sponsorAddr.String()),
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

	// Additional validation for MaxGrantPerUser - server-side safety check
	if err := types.ValidateMaxGrantPerUserConditional(msg.MaxGrantPerUser, msg.IsSponsored); err != nil {
		return nil, sdkerrors.Wrap(err, "invalid max_grant_per_user in server validation")
	}

	// Generate sponsor address from contract address (preserve existing sponsor address)
	var sponsorAddr string
	if existingSponsor.SponsorAddress != "" {
		sponsorAddr = existingSponsor.SponsorAddress // Preserve existing sponsor address
	} else {
		// Generate new sponsor address for backward compatibility
		contractAddr, err := sdk.AccAddressFromBech32(msg.ContractAddress)
		if err != nil {
			return nil, sdkerrors.Wrap(types.ErrInvalidContractAddress, "invalid contract address")
		}
		sponsorAddr = sdk.AccAddress(address.Derive(contractAddr, []byte("sponsor"))).String()
	}

	// Update the sponsor
	sponsor := types.ContractSponsor{
		ContractAddress: msg.ContractAddress,
		CreatorAddress:  existingSponsor.CreatorAddress, // Preserve original creator address
		SponsorAddress:  sponsorAddr, // Preserve or generate sponsor address
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
			sdk.NewAttribute(types.AttributeKeySponsorAddress, sponsorAddr),
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

	// Get sponsor info before deletion for event
	sponsor, found := k.Keeper.GetSponsor(ctx, msg.ContractAddress)
	if !found {
		return nil, sdkerrors.Wrap(types.ErrSponsorNotFound, "sponsor not found")
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
			sdk.NewAttribute(types.AttributeKeySponsorAddress, sponsor.SponsorAddress),
		),
	)

	return &types.MsgDeleteSponsorResponse{}, nil
}

// UpdateParams handles MsgUpdateParams for governance
func (k msgServer) UpdateParams(goCtx context.Context, msg *types.MsgUpdateParams) (*types.MsgUpdateParamsResponse, error) {
	ctx := sdk.UnwrapSDKContext(goCtx)

	// Validate authority
	if k.Keeper.authority != msg.Authority {
		return nil, sdkerrors.Wrapf(types.ErrInvalidAuthority, "invalid authority; expected %s, got %s", k.Keeper.authority, msg.Authority)
	}

	// Validate the new parameters
	if err := msg.Params.Validate(); err != nil {
		return nil, sdkerrors.Wrap(types.ErrInvalidParams, err.Error())
	}

	// Update the parameters
	if err := k.Keeper.SetParams(ctx, msg.Params); err != nil {
		return nil, sdkerrors.Wrap(err, "failed to set parameters")
	}

	// Emit event
	ctx.EventManager().EmitEvent(
		sdk.NewEvent(
			types.EventTypeUpdateParams,
			sdk.NewAttribute(types.AttributeKeyAuthority, msg.Authority),
			sdk.NewAttribute(types.AttributeKeySponsorshipEnabled, fmt.Sprintf("%t", msg.Params.SponsorshipEnabled)),
			sdk.NewAttribute(types.AttributeKeyMaxGasPerSponsorship, fmt.Sprintf("%d", msg.Params.MaxGasPerSponsorship)),
		),
	)

	return &types.MsgUpdateParamsResponse{}, nil
}
