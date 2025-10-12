package keeper

import (
	"context"
	"fmt"

	errorsmod "cosmossdk.io/errors"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/cosmos/cosmos-sdk/types/address"
	sdkerrors "github.com/cosmos/cosmos-sdk/types/errors"

	"github.com/DoraFactory/doravota/x/sponsor-contract-tx/types"
)

// msgServer implements the MsgServer interface
type msgServer struct {
	types.UnimplementedMsgServer
	Keeper
	bankKeeper types.BankKeeper
}

// NewMsgServerImplWithDeps returns a MsgServer with explicit dependencies
func NewMsgServerImplWithDeps(keeper Keeper, bk types.BankKeeper) types.MsgServer {
	return &msgServer{Keeper: keeper, bankKeeper: bk}
}

var _ types.MsgServer = msgServer{}

// SetSponsor handles MsgSetSponsor
func (k msgServer) SetSponsor(goCtx context.Context, msg *types.MsgSetSponsor) (*types.MsgSetSponsorResponse, error) {
	ctx := sdk.UnwrapSDKContext(goCtx)

	// Check if sponsorship is globally enabled
	params := k.Keeper.GetParams(ctx)
	if !params.SponsorshipEnabled {
		return nil, errorsmod.Wrap(types.ErrSponsorshipDisabled, "sponsorship is globally disabled")
	}

	// Validate that the contract exists and is valid
	if err := k.Keeper.ValidateContractExists(ctx, msg.ContractAddress); err != nil {
		return nil, err
	}

	// Check if sponsor already exists
	if k.HasSponsor(ctx, msg.ContractAddress) {
		return nil, errorsmod.Wrap(types.ErrSponsorAlreadyExists, "sponsor already exists")
	}

	// Verify that the creator is the admin of the contract
	creatorAddr, err := sdk.AccAddressFromBech32(msg.Creator)
	if err != nil {
		return nil, errorsmod.Wrap(types.ErrInvalidCreator, "invalid creator address")
	}

	isAdmin, err := k.Keeper.IsContractAdmin(ctx, msg.ContractAddress, creatorAddr)
	if err != nil {
		return nil, errorsmod.Wrap(types.ErrContractNotFound, fmt.Sprintf("failed to verify contract admin: %s", err.Error()))
	}

	if !isAdmin {
		return nil, errorsmod.Wrap(types.ErrContractNotAdmin, "only contract admin can set sponsor")
	}

	// Additional validation for MaxGrantPerUser - server-side safety check
	if err := types.ValidateMaxGrantPerUserConditional(msg.MaxGrantPerUser, msg.IsSponsored); err != nil {
		return nil, errorsmod.Wrap(err, "invalid max_grant_per_user in server validation")
	}

	// Generate sponsor address from contract address
	contractAddr, err := sdk.AccAddressFromBech32(msg.ContractAddress)
	if err != nil {
		return nil, errorsmod.Wrap(types.ErrInvalidContractAddress, "invalid contract address")
	}
	sponsorAddr := sdk.AccAddress(address.Derive(contractAddr, []byte("sponsor")))

	// Create and set the sponsor
	now := ctx.BlockTime().Unix()
	sponsor := types.ContractSponsor{
		ContractAddress: msg.ContractAddress,
		CreatorAddress:  msg.Creator,          // The address that created this sponsor configuration
		SponsorAddress:  sponsorAddr.String(), // The derived address that actually pays for sponsorship fees
		IsSponsored:     msg.IsSponsored,
		CreatedAt:       now,
		UpdatedAt:       now,
		MaxGrantPerUser: msg.MaxGrantPerUser,
	}

	if err := k.Keeper.SetSponsor(ctx, sponsor); err != nil {
		return nil, errorsmod.Wrap(err, "failed to set sponsor")
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
		return nil, errorsmod.Wrap(types.ErrSponsorshipDisabled, "sponsorship is globally disabled")
	}

	// Validate that the contract exists and is valid
	if err := k.Keeper.ValidateContractExists(ctx, msg.ContractAddress); err != nil {
		return nil, err
	}

	// Check if sponsor exists
	if !k.HasSponsor(ctx, msg.ContractAddress) {
		return nil, errorsmod.Wrap(types.ErrSponsorNotFound, "sponsor not found")
	}

	// Verify authorization: current admin OR (admin cleared AND creator matches original sponsor creator)
	creatorAddr, err := sdk.AccAddressFromBech32(msg.Creator)
	if err != nil {
		return nil, errorsmod.Wrap(types.ErrInvalidCreator, "invalid creator address")
	}

	ok, err := k.Keeper.IsSponsorManager(ctx, msg.ContractAddress, creatorAddr)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, errorsmod.Wrap(types.ErrContractNotAdmin, "not contract admin: only contract admin (or original creator when admin is cleared) can update sponsor")
	}

	// Get existing sponsor to preserve CreatedAt timestamp
	existingSponsor, found := k.Keeper.GetSponsor(ctx, msg.ContractAddress)
	if !found {
		// This shouldn't happen since we checked above, but handle gracefully
		existingSponsor.CreatedAt = ctx.BlockTime().Unix()
	}

	// Additional validation for MaxGrantPerUser - server-side safety check
	if err := types.ValidateMaxGrantPerUserConditional(msg.MaxGrantPerUser, msg.IsSponsored); err != nil {
		return nil, errorsmod.Wrap(err, "invalid max_grant_per_user in server validation")
	}

	// Generate sponsor address from contract address (preserve existing sponsor address)
	var sponsorAddr string
	if existingSponsor.SponsorAddress != "" {
		sponsorAddr = existingSponsor.SponsorAddress // Preserve existing sponsor address
	} else {
		// Generate new sponsor address for backward compatibility
		contractAddr, err := sdk.AccAddressFromBech32(msg.ContractAddress)
		if err != nil {
			return nil, errorsmod.Wrap(types.ErrInvalidContractAddress, "invalid contract address")
		}
		sponsorAddr = sdk.AccAddress(address.Derive(contractAddr, []byte("sponsor"))).String()
	}

	// Update the sponsor
	sponsor := types.ContractSponsor{
		ContractAddress: msg.ContractAddress,
		CreatorAddress:  existingSponsor.CreatorAddress, // Preserve original creator address
		SponsorAddress:  sponsorAddr,                    // Preserve or generate sponsor address
		IsSponsored:     msg.IsSponsored,
		CreatedAt:       existingSponsor.CreatedAt,
		UpdatedAt:       ctx.BlockTime().Unix(),
		MaxGrantPerUser: msg.MaxGrantPerUser,
	}

	if err := k.Keeper.SetSponsor(ctx, sponsor); err != nil {
		return nil, errorsmod.Wrap(err, "failed to update sponsor")
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
		return nil, errorsmod.Wrap(types.ErrSponsorshipDisabled, "sponsorship is globally disabled")
	}

	// Validate that the contract exists and is valid
	if err := k.Keeper.ValidateContractExists(ctx, msg.ContractAddress); err != nil {
		return nil, err
	}

	// Check if sponsor exists
	if !k.HasSponsor(ctx, msg.ContractAddress) {
		return nil, errorsmod.Wrap(types.ErrSponsorNotFound, "sponsor not found")
	}

	// Verify that the caller is authorized: current admin OR (admin cleared AND creator is original)
	creatorAddr, err := sdk.AccAddressFromBech32(msg.Creator)
	if err != nil {
		return nil, errorsmod.Wrap(types.ErrInvalidCreator, "invalid creator address")
	}
	ok, err := k.Keeper.IsSponsorManager(ctx, msg.ContractAddress, creatorAddr)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, errorsmod.Wrap(types.ErrContractNotAdmin, "only contract admin (or original creator when admin is cleared) can delete sponsor")
	}

	// Get sponsor info before deletion for event
	sponsor, found := k.Keeper.GetSponsor(ctx, msg.ContractAddress)
	if !found {
		return nil, errorsmod.Wrap(types.ErrSponsorNotFound, "sponsor not found")
	}

	sponsorAddr, err := sdk.AccAddressFromBech32(sponsor.SponsorAddress)
	if err != nil {
		return nil, errorsmod.Wrap(sdkerrors.ErrInvalidAddress, "invalid sponsor address")
	}

	balance := k.bankKeeper.SpendableCoins(ctx, sponsorAddr)
	if !balance.IsZero() {
		return nil, errorsmod.Wrapf(types.ErrSponsorBalanceNotEmpty, "sponsor address %s holds %s", sponsor.SponsorAddress, balance.String())
	}

	// Delete the sponsor
	if err := k.Keeper.DeleteSponsor(ctx, msg.ContractAddress); err != nil {
		return nil, errorsmod.Wrap(err, "failed to delete sponsor")
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

// WithdrawSponsorFunds handles MsgWithdrawSponsorFunds
func (k msgServer) WithdrawSponsorFunds(goCtx context.Context, msg *types.MsgWithdrawSponsorFunds) (*types.MsgWithdrawSponsorFundsResponse, error) {
	ctx := sdk.UnwrapSDKContext(goCtx)

	// Validate contract exists (also required for admin check)
	if err := k.Keeper.ValidateContractExists(ctx, msg.ContractAddress); err != nil {
		return nil, err
	}

	// Check sponsor exists for contract
	sponsor, found := k.Keeper.GetSponsor(ctx, msg.ContractAddress)
	if !found {
		return nil, errorsmod.Wrap(types.ErrSponsorNotFound, "sponsor not found")
	}

	// Verify authorization: current admin OR (admin cleared AND creator equals sponsor creator)
	creatorAddr, err := sdk.AccAddressFromBech32(msg.Creator)
	if err != nil {
		return nil, errorsmod.Wrap(types.ErrInvalidCreator, "invalid creator address")
	}
	ok, err := k.Keeper.IsSponsorManager(ctx, msg.ContractAddress, creatorAddr)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, errorsmod.Wrap(types.ErrContractNotAdmin, "not contract admin: only contract admin (or original creator when admin is cleared) can withdraw sponsor funds")
	}

	// Parse sponsor address first (required to check balances)
	sponsorAddr, err := sdk.AccAddressFromBech32(sponsor.SponsorAddress)
	if err != nil {
		return nil, errorsmod.Wrap(types.ErrInvalidContractAddress, "invalid sponsor address")
	}

	amt := msg.NormalizedAmount()

	// Ensure bank keeper is available
	if k.bankKeeper == nil {
		return nil, errorsmod.Wrap(sdkerrors.ErrLogic, "bank keeper is not configured for sponsor withdraw")
	}

	// Check sponsor balance (used in both branches)
	spendable := k.bankKeeper.SpendableCoins(ctx, sponsorAddr)

	if len(msg.Amount) == 0 {
		// Withdraw entire balance path: decide based on sponsor's spendable balance first
		amt = spendable
		if amt.Empty() {
			return nil, errorsmod.Wrap(types.ErrSponsorBalanceEmpty, "no funds available to withdraw")
		}
		// Validate recipient now that we know there are funds
		recipientAddr, err := sdk.AccAddressFromBech32(msg.Recipient)
		if err != nil {
			return nil, errorsmod.Wrap(sdkerrors.ErrInvalidAddress, "invalid recipient address")
		}
		// Transfer funds
		if err := k.bankKeeper.SendCoins(ctx, sponsorAddr, recipientAddr, amt); err != nil {
			return nil, errorsmod.Wrap(err, "failed to transfer sponsor funds")
		}
	} else {
		// Explicit amount path: validate amount semantics first
		if amt.Empty() {
			return nil, errorsmod.Wrap(sdkerrors.ErrInvalidCoins, "invalid withdraw amount")
		}
		if !amt.IsValid() {
			return nil, errorsmod.Wrap(sdkerrors.ErrInvalidCoins, "invalid withdraw amount")
		}
		// Validate recipient before checking balances (tests expect address validation first)
		recipientAddr, err := sdk.AccAddressFromBech32(msg.Recipient)
		if err != nil {
			return nil, errorsmod.Wrap(sdkerrors.ErrInvalidAddress, "invalid recipient address")
		}
		// Then check balances
		if !spendable.IsAllGTE(amt) {
			return nil, errorsmod.Wrapf(sdkerrors.ErrInsufficientFunds, "insufficient sponsor funds: required %s, available %s", amt.String(), spendable.String())
		}
		// Transfer funds
		if err := k.bankKeeper.SendCoins(ctx, sponsorAddr, recipientAddr, amt); err != nil {
			return nil, errorsmod.Wrap(err, "failed to transfer sponsor funds")
		}
	}

	// Emit event
	ctx.EventManager().EmitEvent(
		sdk.NewEvent(
			types.EventTypeSponsorWithdrawal,
			sdk.NewAttribute(types.AttributeKeyCreator, msg.Creator),
			sdk.NewAttribute(types.AttributeKeyContractAddress, msg.ContractAddress),
			sdk.NewAttribute(types.AttributeKeySponsorAddress, sponsor.SponsorAddress),
			sdk.NewAttribute(types.AttributeKeyRecipient, msg.Recipient),
			sdk.NewAttribute(types.AttributeKeySponsorAmount, amt.String()),
		),
	)

	return &types.MsgWithdrawSponsorFundsResponse{}, nil
}

// UpdateParams handles MsgUpdateParams for governance
func (k msgServer) UpdateParams(goCtx context.Context, msg *types.MsgUpdateParams) (*types.MsgUpdateParamsResponse, error) {
	ctx := sdk.UnwrapSDKContext(goCtx)

	// Validate authority
	if k.Keeper.authority != msg.Authority {
		return nil, errorsmod.Wrapf(types.ErrInvalidAuthority, "invalid authority; expected %s, got %s", k.Keeper.authority, msg.Authority)
	}

	// Validate the new parameters
	if err := msg.Params.Validate(); err != nil {
		return nil, errorsmod.Wrap(types.ErrInvalidParams, err.Error())
	}

	// Update the parameters
	if err := k.Keeper.SetParams(ctx, msg.Params); err != nil {
		return nil, errorsmod.Wrap(err, "failed to set parameters")
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
