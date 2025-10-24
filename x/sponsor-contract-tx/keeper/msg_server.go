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
	authKeeper types.AuthKeeper
}

// NewMsgServerImplWithDeps returns a MsgServer with explicit dependencies
func NewMsgServerImplWithDeps(keeper Keeper, bk types.BankKeeper, ak types.AuthKeeper) types.MsgServer {
	return &msgServer{Keeper: keeper, bankKeeper: bk, authKeeper: ak}
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

    // Validate optional ticket issuer address when provided
    if msg.TicketIssuerAddress != "" {
        if _, err := sdk.AccAddressFromBech32(msg.TicketIssuerAddress); err != nil {
            return nil, errorsmod.Wrap(sdkerrors.ErrInvalidAddress, "invalid ticket issuer address")
        }
    }

	// Create and set the sponsor
	now := ctx.BlockTime().Unix()
	sponsor := types.ContractSponsor{
        ContractAddress:        msg.ContractAddress,
        CreatorAddress:         msg.Creator,          // The address that created this sponsor configuration
        SponsorAddress:         sponsorAddr.String(), // The derived address that actually pays for sponsorship fees
        TicketIssuerAddress:    msg.TicketIssuerAddress,
        IsSponsored:            msg.IsSponsored,
        CreatedAt:              now,
        UpdatedAt:              now,
        MaxGrantPerUser:        msg.MaxGrantPerUser,
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
	// Allow partial updates: only validate when field is explicitly provided
	if len(msg.MaxGrantPerUser) > 0 {
		if err := types.ValidateMaxGrantPerUserConditional(msg.MaxGrantPerUser, msg.IsSponsored); err != nil {
			return nil, errorsmod.Wrap(err, "invalid max_grant_per_user in server validation")
		}
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

	// Determine effective MaxGrantPerUser (preserve existing when omitted)
	effectiveMaxGrant := existingSponsor.MaxGrantPerUser
	if len(msg.MaxGrantPerUser) > 0 {
		effectiveMaxGrant = msg.MaxGrantPerUser
	}

	// Enforce: whenever sponsorship is enabled after this update, there must be a non-empty max_grant_per_user
	if msg.IsSponsored && len(effectiveMaxGrant) == 0 {
		return nil, errorsmod.Wrap(sdkerrors.ErrInvalidRequest, "max_grant_per_user is required when enabling sponsorship")
	}

    // Update the sponsor
    // Determine ticket issuer address
    issuer := existingSponsor.TicketIssuerAddress
    if msg.TicketIssuerAddress != "" {
        // Validate provided issuer address
        if _, err := sdk.AccAddressFromBech32(msg.TicketIssuerAddress); err != nil {
            return nil, errorsmod.Wrap(sdkerrors.ErrInvalidAddress, "invalid ticket issuer address")
        }
        issuer = msg.TicketIssuerAddress
    }
    sponsor := types.ContractSponsor{
        ContractAddress:        msg.ContractAddress,
        CreatorAddress:         existingSponsor.CreatorAddress, // Preserve original creator address
        SponsorAddress:         sponsorAddr,                    // Preserve or generate sponsor address
        TicketIssuerAddress:    issuer,
        IsSponsored:            msg.IsSponsored,
        CreatedAt:              existingSponsor.CreatedAt,
        UpdatedAt:              ctx.BlockTime().Unix(),
        MaxGrantPerUser:        effectiveMaxGrant,
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

    // Emit event with key parameters for observability
    ctx.EventManager().EmitEvent(
        sdk.NewEvent(
            types.EventTypeUpdateParams,
            sdk.NewAttribute(types.AttributeKeyAuthority, msg.Authority),
            sdk.NewAttribute(types.AttributeKeySponsorshipEnabled, fmt.Sprintf("%t", msg.Params.SponsorshipEnabled)),
            sdk.NewAttribute(types.AttributeKeyPolicyTicketTtlBlocks, fmt.Sprintf("%d", msg.Params.PolicyTicketTtlBlocks)),
            sdk.NewAttribute(types.AttributeKeyMaxExecMsgsPerTxForSponsor, fmt.Sprintf("%d", msg.Params.MaxExecMsgsPerTxForSponsor)),
            sdk.NewAttribute(types.AttributeKeyMaxPolicyExecMsgBytes, fmt.Sprintf("%d", msg.Params.MaxPolicyExecMsgBytes)),
            sdk.NewAttribute(types.AttributeKeyMaxMethodTicketUsesPerIssue, fmt.Sprintf("%d", msg.Params.MaxMethodTicketUsesPerIssue)),
            sdk.NewAttribute(types.AttributeKeyTicketGcPerBlock, fmt.Sprintf("%d", msg.Params.TicketGcPerBlock)),
            sdk.NewAttribute(types.AttributeKeyMaxMethodNameBytes, fmt.Sprintf("%d", msg.Params.MaxMethodNameBytes)),
            sdk.NewAttribute(types.AttributeKeyMaxMethodJSONDepth, fmt.Sprintf("%d", msg.Params.MaxMethodJsonDepth)),
        ),
    )

	return &types.MsgUpdateParamsResponse{}, nil
}

// IssuePolicyTicket allows sponsor manager (admin/creator fallback) or ticket issuer
// to proactively issue a ticket for whitelist
func (k msgServer) IssuePolicyTicket(goCtx context.Context, msg *types.MsgIssuePolicyTicket) (*types.MsgIssuePolicyTicketResponse, error) {
    ctx := sdk.UnwrapSDKContext(goCtx)
    if msg == nil {
        return nil, errorsmod.Wrap(sdkerrors.ErrInvalidRequest, "nil request")
    }
    if err := types.ValidateContractAddress(msg.ContractAddress); err != nil {
        return nil, err
    }
    // Require sponsor exists for this contract (both for manager and issuer flows)
    if _, found := k.Keeper.GetSponsor(ctx, msg.ContractAddress); !found {
        return nil, errorsmod.Wrap(types.ErrSponsorNotFound, "sponsor not found")
    }
    // Verify authorization: contract admin or ticket_issuer_address
    creator, err := sdk.AccAddressFromBech32(msg.Creator)
    if err != nil {
        return nil, errorsmod.Wrap(sdkerrors.ErrInvalidAddress, "invalid creator")
    }
	isManager, err := k.Keeper.IsSponsorManager(ctx, msg.ContractAddress, creator)
	if err != nil {
		return nil, err
	}
	if !isManager {
		sponsor, found := k.Keeper.GetSponsor(ctx, msg.ContractAddress)
		if !found {
			return nil, errorsmod.Wrap(types.ErrSponsorNotFound, "sponsor not found")
		}
		if sponsor.TicketIssuerAddress == "" || sponsor.TicketIssuerAddress != creator.String() {
			return nil, errorsmod.Wrap(types.ErrUnauthorized, "not authorized to issue tickets")
		}
	}
	// Validate user
	if msg.UserAddress == "" {
		return nil, errorsmod.Wrap(sdkerrors.ErrInvalidAddress, "user address required")
	}
	userAddr, err := sdk.AccAddressFromBech32(msg.UserAddress)
	if err != nil {
		return nil, errorsmod.Wrap(sdkerrors.ErrInvalidAddress, "invalid user address")
	}

	// Create the account if it does not exist in account state
	userAcc := k.authKeeper.GetAccount(ctx, userAddr)
	if userAcc == nil {
		if k.bankKeeper.BlockedAddr(userAddr) {
			return nil, errorsmod.Wrapf(sdkerrors.ErrUnauthorized, "%s is blocked and not allowed to receive tickets", userAddr)
		}

		userAcc = k.authKeeper.NewAccountWithAddress(ctx, userAddr)
		k.authKeeper.SetAccount(ctx, userAcc)
	}
    // Validate method name and compute digest (single-method tickets only)
    if msg.Method == "" {
        return nil, errorsmod.Wrap(sdkerrors.ErrInvalidRequest, "method is required")
    }
    // Enforce method name size limit from params
    if lim := k.Keeper.GetParams(ctx).MaxMethodNameBytes; lim != 0 && uint32(len(msg.Method)) > lim {
        return nil, errorsmod.Wrap(sdkerrors.ErrInvalidRequest, "method name too long")
    }
    digest := k.Keeper.ComputeMethodDigest(msg.ContractAddress, []string{msg.Method})

    // Conflict: if an active, unconsumed ticket already exists for this digest, reject re-issue.
    // Tickets expiring strictly after the current height are considered active for issuance purposes
    // (tickets at the current height are treated as stale and can be replaced).
    if t, found := k.Keeper.GetPolicyTicket(ctx, msg.ContractAddress, msg.UserAddress, digest); found {
        now := uint64(ctx.BlockHeight())
        if !t.Consumed && now < t.ExpiryHeight {
            // Enrich method for display if missing
            method := t.Method
            if method == "" && msg.Method != "" {
                method = msg.Method
            }
            // Emit a conflict event to aid operators
            ctx.EventManager().EmitEvent(
                sdk.NewEvent(
                    types.EventTypePolicyTicketIssueConflict,
                    sdk.NewAttribute(types.AttributeKeyContractAddress, msg.ContractAddress),
                    sdk.NewAttribute(types.AttributeKeyUser, msg.UserAddress),
                    sdk.NewAttribute(types.AttributeKeyDigest, t.Digest),
                    sdk.NewAttribute(types.AttributeKeyMethod, method),
                    sdk.NewAttribute(types.AttributeKeyExpiryHeight, fmt.Sprintf("%d", t.ExpiryHeight)),
                    sdk.NewAttribute("uses_remaining", fmt.Sprintf("%d", t.UsesRemaining)),
                ),
            )
            // Log informational message with existing ticket details
            ctx.Logger().With("module", types.ModuleName).Info(
                "issue ticket rejected: active ticket already exists",
                "contract", msg.ContractAddress,
                "user", msg.UserAddress,
                "digest", t.Digest,
                "method", method,
                "expiry", t.ExpiryHeight,
                "uses_remaining", t.UsesRemaining,
            )
            return nil, errorsmod.Wrapf(types.ErrPolicyTicketAlreadyExists,
                "active ticket exists for user %s on contract %s (digest=%s, method=%s, expiry=%d, uses_remaining=%d)",
                msg.UserAddress, msg.ContractAddress, t.Digest, method, t.ExpiryHeight, t.UsesRemaining,
            )
        }
        // If consumed or at/after expiry, replace by deleting stale ticket first
        k.Keeper.DeletePolicyTicket(ctx, msg.ContractAddress, msg.UserAddress, digest)
    }

    // No capacity limits enforced (whitelist controls issuance)
    // Create new ticket
    ttl := msg.TtlBlocks
    if ttl == 0 {
        ttl = k.Keeper.EffectiveTicketTTLForContract(ctx, msg.ContractAddress)
    }
    ticket := types.PolicyTicket{
        ContractAddress: msg.ContractAddress,
        UserAddress:     msg.UserAddress,
        Digest:          digest,
        ExpiryHeight:    uint64(ctx.BlockHeight()) + uint64(ttl),
        Consumed:        false,
        IssuedHeight:    uint64(ctx.BlockHeight()),
    }
    // Set method for display when issuing a single-method ticket
    ticket.Method = msg.Method
    // Clamp requested uses: 0/omitted => 1; clamp to params.MaxMethodTicketUsesPerIssue
    params := k.Keeper.GetParams(ctx)
    requested := msg.Uses
    if requested == 0 {
        requested = 1
    }
    maxPerIssue := params.MaxMethodTicketUsesPerIssue
    if maxPerIssue == 0 {
        maxPerIssue = 1
    }
    if requested > maxPerIssue {
        ticket.UsesRemaining = maxPerIssue
        // Emit clamping event for observability
        ctx.EventManager().EmitEvent(
            sdk.NewEvent(
                types.EventTypeTicketUsesClamped,
                sdk.NewAttribute(types.AttributeKeyRequestedUses, fmt.Sprintf("%d", requested)),
                sdk.NewAttribute(types.AttributeKeyClampedTo, fmt.Sprintf("%d", maxPerIssue)),
                sdk.NewAttribute(types.AttributeKeyContractAddress, ticket.ContractAddress),
                sdk.NewAttribute(types.AttributeKeyUser, ticket.UserAddress),
                sdk.NewAttribute(types.AttributeKeyDigest, ticket.Digest),
            ),
        )
    } else {
        ticket.UsesRemaining = requested
    }
    if err := k.Keeper.SetPolicyTicket(ctx, ticket); err != nil {
        return nil, errorsmod.Wrap(err, "store ticket failed")
    }
    // Emit issue event for observability (DeliverTx and CheckTx both emit; lightweight attributes only)
    ctx.EventManager().EmitEvent(
        sdk.NewEvent(
            types.EventTypePolicyTicketIssued,
            sdk.NewAttribute(types.AttributeKeyContractAddress, ticket.ContractAddress),
            sdk.NewAttribute(types.AttributeKeyUser, ticket.UserAddress),
            sdk.NewAttribute(types.AttributeKeyDigest, ticket.Digest),
            sdk.NewAttribute(types.AttributeKeyExpiryHeight, fmt.Sprintf("%d", ticket.ExpiryHeight)),
            sdk.NewAttribute(types.AttributeKeyMethod, ticket.Method),
        ),
    )
    return &types.MsgIssuePolicyTicketResponse{Created: true, Ticket: &ticket}, nil
}

// RevokePolicyTicket allows sponsor manager or ticket issuer to revoke a ticket (unconsumed only)
func (k msgServer) RevokePolicyTicket(goCtx context.Context, msg *types.MsgRevokePolicyTicket) (*types.MsgRevokePolicyTicketResponse, error) {
    ctx := sdk.UnwrapSDKContext(goCtx)
    if msg == nil {
        return nil, errorsmod.Wrap(sdkerrors.ErrInvalidRequest, "nil request")
    }
    // Validate addresses
    if err := types.ValidateContractAddress(msg.ContractAddress); err != nil {
        return nil, err
    }
    if _, err := sdk.AccAddressFromBech32(msg.UserAddress); err != nil {
        return nil, errorsmod.Wrap(sdkerrors.ErrInvalidAddress, "invalid user address")
    }
    // Require sponsor exists for this contract
    if _, found := k.Keeper.GetSponsor(ctx, msg.ContractAddress); !found {
        return nil, errorsmod.Wrap(types.ErrSponsorNotFound, "sponsor not found")
    }
    // Auth: contract manager (admin or creator fallback when admin cleared) OR ticket_issuer_address
    creator, err := sdk.AccAddressFromBech32(msg.Creator)
    if err != nil {
        return nil, errorsmod.Wrap(sdkerrors.ErrInvalidAddress, "invalid creator")
    }
    ok, err := k.Keeper.IsSponsorManager(ctx, msg.ContractAddress, creator)
    if err != nil {
        return nil, err
    }
    if !ok {
        sponsor, found := k.Keeper.GetSponsor(ctx, msg.ContractAddress)
        if !found {
            return nil, errorsmod.Wrap(types.ErrSponsorNotFound, "sponsor not found")
        }
        if sponsor.TicketIssuerAddress == "" || sponsor.TicketIssuerAddress != creator.String() {
            return nil, errorsmod.Wrap(types.ErrContractNotAdmin, "not authorized to revoke tickets")
        }
    }
    // Revoke ticket (must exist and be unconsumed). Fetch method for event display first.
    method := ""
    if tPrev, ok := k.Keeper.GetPolicyTicket(ctx, msg.ContractAddress, msg.UserAddress, msg.Digest); ok {
        method = tPrev.Method
    }
    if err := k.Keeper.RevokePolicyTicket(ctx, msg.ContractAddress, msg.UserAddress, msg.Digest); err != nil {
        return nil, err
    }
    // Emit event
    ctx.EventManager().EmitEvent(
        sdk.NewEvent(
            types.EventTypePolicyTicketRevoked,
            sdk.NewAttribute(types.AttributeKeyContractAddress, msg.ContractAddress),
            sdk.NewAttribute(types.AttributeKeyUser, msg.UserAddress),
            sdk.NewAttribute(types.AttributeKeyDigest, msg.Digest),
            sdk.NewAttribute(types.AttributeKeyMethod, method),
        ),
    )
    return &types.MsgRevokePolicyTicketResponse{}, nil
}
