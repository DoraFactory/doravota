package keeper

import (
	"fmt"
	"strings"

	sdk "github.com/cosmos/cosmos-sdk/types"

	"github.com/DoraFactory/doravota/x/sponsor-contract-tx/types"
)

const (
	LifecycleInvariantRoute = "lifecycle"
	ParamsInvariantRoute    = "params"
)

// RegisterInvariants registers Sponsor state checks with the application
// invariant registry.
func RegisterInvariants(ir sdk.InvariantRegistry, k Keeper) {
	ir.RegisterRoute(types.ModuleName, LifecycleInvariantRoute, LifecycleInvariant(k))
	ir.RegisterRoute(types.ModuleName, ParamsInvariantRoute, ParamsInvariant(k))
}

// LifecycleInvariant verifies generation isolation and the canonical expiry
// index without mutating state.
func LifecycleInvariant(k Keeper) sdk.Invariant {
	return func(ctx sdk.Context) (string, bool) {
		var violations strings.Builder
		store := ctx.KVStore(k.storeKey)

		k.IterateSponsors(ctx, func(sponsor types.ContractSponsor) bool {
			current := k.GetSponsorGeneration(ctx, sponsor.ContractAddress)
			if sponsor.Generation == 0 || current != sponsor.Generation {
				fmt.Fprintf(
					&violations,
					"sponsor %s generation mismatch: sponsor=%d current=%d\n",
					sponsor.ContractAddress,
					sponsor.Generation,
					current,
				)
			}
			return false
		})

		k.IteratePolicyTickets(ctx, func(_ []byte, ticket types.PolicyTicket) bool {
			current := k.GetSponsorGeneration(ctx, ticket.ContractAddress)
			sponsor, active := k.GetSponsor(ctx, ticket.ContractAddress)
			switch {
			case ticket.Generation == 0:
				fmt.Fprintf(&violations, "ticket %s has zero generation\n", ticket.Digest)
			case active && ticket.Generation > sponsor.Generation:
				fmt.Fprintf(
					&violations,
					"ticket %s generation %d exceeds active sponsor generation %d\n",
					ticket.Digest,
					ticket.Generation,
					sponsor.Generation,
				)
			case !active && (current == 0 || ticket.Generation >= current):
				fmt.Fprintf(
					&violations,
					"historical ticket %s generation %d is not older than tombstone %d\n",
					ticket.Digest,
					ticket.Generation,
					current,
				)
			}

			expiryIndex := types.GetExpiryIndexKey(
				ticket.ExpiryHeight,
				ticket.ContractAddress,
				ticket.UserAddress,
				ticket.Digest,
			)
			if !store.Has(expiryIndex) {
				fmt.Fprintf(&violations, "ticket %s is missing its expiry index\n", ticket.Digest)
			}
			return false
		})

		k.IterateUserGrantUsages(ctx, func(usage types.UserGrantUsage) bool {
			current := k.GetSponsorGeneration(ctx, usage.ContractAddress)
			sponsor, active := k.GetSponsor(ctx, usage.ContractAddress)
			switch {
			case usage.Generation == 0:
				fmt.Fprintf(
					&violations,
					"usage for %s/%s has zero generation\n",
					usage.ContractAddress,
					usage.UserAddress,
				)
			case active && usage.Generation > sponsor.Generation:
				fmt.Fprintf(
					&violations,
					"usage for %s/%s generation %d exceeds active sponsor generation %d\n",
					usage.ContractAddress,
					usage.UserAddress,
					usage.Generation,
					sponsor.Generation,
				)
			case !active && (current == 0 || usage.Generation >= current):
				fmt.Fprintf(
					&violations,
					"historical usage for %s/%s generation %d is not older than tombstone %d\n",
					usage.ContractAddress,
					usage.UserAddress,
					usage.Generation,
					current,
				)
			}
			return false
		})

		message := violations.String()
		return sdk.FormatInvariant(types.ModuleName, LifecycleInvariantRoute, message), message != ""
	}
}

// ParamsInvariant verifies that governance cannot leave unsafe resource limits
// in module state.
func ParamsInvariant(k Keeper) sdk.Invariant {
	return func(ctx sdk.Context) (string, bool) {
		if err := k.GetParams(ctx).Validate(); err != nil {
			message := fmt.Sprintf("invalid params: %v\n", err)
			return sdk.FormatInvariant(types.ModuleName, ParamsInvariantRoute, message), true
		}
		return sdk.FormatInvariant(types.ModuleName, ParamsInvariantRoute, ""), false
	}
}
