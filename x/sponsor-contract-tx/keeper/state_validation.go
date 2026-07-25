package keeper

import (
	errorsmod "cosmossdk.io/errors"
	sdk "github.com/cosmos/cosmos-sdk/types"
	sdkerrors "github.com/cosmos/cosmos-sdk/types/errors"

	"github.com/DoraFactory/doravota/x/sponsor-contract-tx/types"
)

func stateUnixTime(ctx sdk.Context) int64 {
	now := ctx.BlockTime().Unix()
	if now < 0 {
		return 1
	}
	return now
}

// SetActiveSponsor stores runtime Sponsor state after validating both its
// self-contained fields and its O(1) dependencies. Authorization remains a
// MsgServer responsibility.
func (k Keeper) SetActiveSponsor(ctx sdk.Context, sponsor types.ContractSponsor) error {
	normalized, err := types.NormalizeMaxGrantPerUser(sponsor.MaxGrantPerUser)
	if err != nil {
		return errorsmod.Wrap(err, "failed to normalize max grant per user")
	}
	sponsor.MaxGrantPerUser = normalized

	if err := types.ValidateContractSponsorState(sponsor, false); err != nil {
		return errorsmod.Wrap(err, "invalid sponsor state")
	}
	hasAdmin, err := k.HasContractAdmin(ctx, sponsor.ContractAddress)
	if err != nil {
		return errorsmod.Wrap(err, "failed to validate sponsor contract")
	}
	if !hasAdmin {
		return errorsmod.Wrap(types.ErrContractNotAdmin, "active sponsor contract has no wasm admin")
	}

	expectedGeneration := k.GetSponsorGeneration(ctx, sponsor.ContractAddress)
	if existing, found := k.GetSponsor(ctx, sponsor.ContractAddress); found {
		expectedGeneration = existing.Generation
	}
	if expectedGeneration == 0 {
		expectedGeneration = 1
	}
	if sponsor.Generation != 0 && sponsor.Generation != expectedGeneration {
		return errorsmod.Wrapf(
			sdkerrors.ErrInvalidRequest,
			"sponsor generation %d does not match runtime generation %d",
			sponsor.Generation,
			expectedGeneration,
		)
	}

	if err := k.bindSponsorGeneration(ctx, &sponsor); err != nil {
		return errorsmod.Wrap(err, "failed to bind sponsor generation")
	}
	if err := types.ValidateContractSponsorState(sponsor, true); err != nil {
		return errorsmod.Wrap(err, "invalid sponsor state")
	}
	return k.SetSponsor(ctx, sponsor)
}

// SetSponsorForGenesis imports an active Sponsor after lifecycle generations
// have been restored. Genesis may bypass message authorization, but it may not
// create a Sponsor for a missing contract or a contract without an admin.
func (k Keeper) SetSponsorForGenesis(ctx sdk.Context, sponsor types.ContractSponsor) error {
	if sponsor.Generation == 0 {
		return errorsmod.Wrap(sdkerrors.ErrInvalidRequest, "genesis sponsor generation must be positive")
	}
	return k.SetActiveSponsor(ctx, sponsor)
}

// SetActivePolicyTicket stores a ticket for the current Sponsor lifecycle.
// It never accepts historical generations.
func (k Keeper) SetActivePolicyTicket(ctx sdk.Context, ticket types.PolicyTicket) error {
	maxMethodBytes := k.GetParams(ctx).EffectiveMaxMethodBytes()
	if err := types.ValidatePolicyTicketState(ticket, maxMethodBytes, false); err != nil {
		return errorsmod.Wrap(err, "invalid active policy ticket")
	}
	sponsor, found := k.GetSponsor(ctx, ticket.ContractAddress)
	if !found {
		return errorsmod.Wrap(types.ErrSponsorNotFound, "cannot store ticket without an active sponsor")
	}
	current := k.GetSponsorGeneration(ctx, ticket.ContractAddress)
	if sponsor.Generation == 0 || current != sponsor.Generation {
		return errorsmod.Wrap(
			sdkerrors.ErrInvalidRequest,
			"active sponsor generation state is inconsistent",
		)
	}
	if ticket.Generation == 0 {
		ticket.Generation = sponsor.Generation
	}
	if ticket.Generation != sponsor.Generation {
		return errorsmod.Wrapf(
			sdkerrors.ErrInvalidRequest,
			"ticket generation %d does not match active sponsor generation %d",
			ticket.Generation,
			sponsor.Generation,
		)
	}
	if err := types.ValidatePolicyTicketState(ticket, maxMethodBytes, true); err != nil {
		return errorsmod.Wrap(err, "invalid active policy ticket")
	}
	return k.SetPolicyTicket(ctx, ticket)
}

// setCurrentOrLegacyPolicyTicket preserves the pre-lifecycle unit-level API
// only for contracts that have never had a Sponsor. Once a generation exists,
// all mutations must pass active lifecycle validation.
func (k Keeper) setCurrentOrLegacyPolicyTicket(ctx sdk.Context, ticket types.PolicyTicket) error {
	if _, active := k.GetSponsor(ctx, ticket.ContractAddress); active {
		return k.SetActivePolicyTicket(ctx, ticket)
	}
	if k.GetSponsorGeneration(ctx, ticket.ContractAddress) == 0 && ticket.Generation == 0 {
		return k.SetPolicyTicket(ctx, ticket)
	}
	return errorsmod.Wrap(types.ErrSponsorNotFound, "cannot mutate ticket outside an active sponsor lifecycle")
}

// SetPolicyTicketForGenesis imports either a current or historical ticket.
// A historical ticket for a deleted Sponsor must be older than the persistent
// generation tombstone, so it can never become active after recreation.
func (k Keeper) SetPolicyTicketForGenesis(ctx sdk.Context, ticket types.PolicyTicket) error {
	if err := types.ValidatePolicyTicketState(
		ticket,
		k.GetParams(ctx).EffectiveMaxMethodBytes(),
		true,
	); err != nil {
		return errorsmod.Wrap(err, "invalid genesis policy ticket")
	}

	current := k.GetSponsorGeneration(ctx, ticket.ContractAddress)
	if current == 0 {
		return errorsmod.Wrap(
			sdkerrors.ErrInvalidRequest,
			"genesis ticket has no sponsor lifecycle generation",
		)
	}
	if sponsor, active := k.GetSponsor(ctx, ticket.ContractAddress); active {
		if sponsor.Generation != current {
			return errorsmod.Wrap(
				sdkerrors.ErrInvalidRequest,
				"active sponsor generation state is inconsistent",
			)
		}
		if ticket.Generation > sponsor.Generation {
			return errorsmod.Wrapf(
				sdkerrors.ErrInvalidRequest,
				"ticket generation %d exceeds active sponsor generation %d",
				ticket.Generation,
				sponsor.Generation,
			)
		}
	} else if ticket.Generation >= current {
		return errorsmod.Wrapf(
			sdkerrors.ErrInvalidRequest,
			"historical ticket generation %d is not older than tombstone %d",
			ticket.Generation,
			current,
		)
	}
	return k.SetPolicyTicket(ctx, ticket)
}

// SetActiveUserGrantUsage stores cumulative usage for the current Sponsor
// lifecycle. Current grant limits are intentionally not applied to historical
// totals.
func (k Keeper) SetActiveUserGrantUsage(ctx sdk.Context, usage types.UserGrantUsage) error {
	if err := types.ValidateUserGrantUsageState(usage, false); err != nil {
		return errorsmod.Wrap(err, "invalid active user grant usage")
	}
	sponsor, found := k.GetSponsor(ctx, usage.ContractAddress)
	if !found {
		return errorsmod.Wrap(types.ErrSponsorNotFound, "cannot store usage without an active sponsor")
	}
	current := k.GetSponsorGeneration(ctx, usage.ContractAddress)
	if sponsor.Generation == 0 || current != sponsor.Generation {
		return errorsmod.Wrap(
			sdkerrors.ErrInvalidRequest,
			"active sponsor generation state is inconsistent",
		)
	}
	if usage.Generation == 0 {
		usage.Generation = sponsor.Generation
	}
	if usage.Generation != sponsor.Generation {
		return errorsmod.Wrapf(
			sdkerrors.ErrInvalidRequest,
			"usage generation %d does not match active sponsor generation %d",
			usage.Generation,
			sponsor.Generation,
		)
	}
	if err := types.ValidateUserGrantUsageState(usage, true); err != nil {
		return errorsmod.Wrap(err, "invalid active user grant usage")
	}
	return k.SetUserGrantUsage(ctx, usage)
}

// SetUserGrantUsageForGenesis imports current or historical usage using the
// same lifecycle isolation rules as policy tickets.
func (k Keeper) SetUserGrantUsageForGenesis(ctx sdk.Context, usage types.UserGrantUsage) error {
	if err := types.ValidateUserGrantUsageState(usage, true); err != nil {
		return errorsmod.Wrap(err, "invalid genesis user grant usage")
	}

	current := k.GetSponsorGeneration(ctx, usage.ContractAddress)
	if current == 0 {
		return errorsmod.Wrap(
			sdkerrors.ErrInvalidRequest,
			"genesis usage has no sponsor lifecycle generation",
		)
	}
	if sponsor, active := k.GetSponsor(ctx, usage.ContractAddress); active {
		if sponsor.Generation != current {
			return errorsmod.Wrap(
				sdkerrors.ErrInvalidRequest,
				"active sponsor generation state is inconsistent",
			)
		}
		if usage.Generation > sponsor.Generation {
			return errorsmod.Wrapf(
				sdkerrors.ErrInvalidRequest,
				"usage generation %d exceeds active sponsor generation %d",
				usage.Generation,
				sponsor.Generation,
			)
		}
	} else if usage.Generation >= current {
		return errorsmod.Wrapf(
			sdkerrors.ErrInvalidRequest,
			"historical usage generation %d is not older than tombstone %d",
			usage.Generation,
			current,
		)
	}
	return k.SetUserGrantUsage(ctx, usage)
}
