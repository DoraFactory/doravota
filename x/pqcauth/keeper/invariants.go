package keeper

import (
	"fmt"

	sdk "github.com/cosmos/cosmos-sdk/types"

	"github.com/DoraFactory/doravota/x/pqcauth/types"
)

const stateInvariantRoute = "state-consistency"

func RegisterInvariants(registry sdk.InvariantRegistry, moduleKeeper Keeper) {
	registry.RegisterRoute(types.ModuleName, stateInvariantRoute, StateInvariant(moduleKeeper))
}

func StateInvariant(moduleKeeper Keeper) sdk.Invariant {
	return func(ctx sdk.Context) (string, bool) {
		genesis := types.GenesisState{Params: moduleKeeper.GetParams(ctx)}
		owners := make(map[string]struct{})
		moduleKeeper.IterateAllKeys(ctx, func(key types.PQCKeyRecord) bool {
			genesis.Keys = append(genesis.Keys, key)
			owners[key.Owner] = struct{}{}
			return false
		})
		moduleKeeper.IterateAllPolicies(ctx, func(policy types.AccountPolicy) bool {
			genesis.Policies = append(genesis.Policies, policy)
			owners[policy.Owner] = struct{}{}
			return false
		})
		moduleKeeper.IterateAllSequences(ctx, func(sequence types.AccountKeySequence) bool {
			genesis.KeySequences = append(genesis.KeySequences, sequence)
			owners[sequence.Owner] = struct{}{}
			return false
		})
		moduleKeeper.IterateAllKeyHistories(ctx, func(history types.AccountKeyHistory) bool {
			genesis.KeyHistories = append(genesis.KeyHistories, history)
			owners[history.Owner] = struct{}{}
			return false
		})
		if err := types.ValidateGenesis(genesis); err != nil {
			return sdk.FormatInvariant(
				types.ModuleName,
				stateInvariantRoute,
				fmt.Sprintf("invalid pqcauth state: %v", err),
			), true
		}
		for owner := range owners {
			address, err := sdk.AccAddressFromBech32(owner)
			if err != nil {
				return sdk.FormatInvariant(
					types.ModuleName,
					stateInvariantRoute,
					fmt.Sprintf("invalid pqcauth state owner %s: %v", owner, err),
				), true
			}
			if err := moduleKeeper.RequireClassicAccount(ctx, address); err != nil {
				return sdk.FormatInvariant(
					types.ModuleName,
					stateInvariantRoute,
					fmt.Sprintf("ineligible pqcauth state owner %s: %v", owner, err),
				), true
			}
		}
		return sdk.FormatInvariant(types.ModuleName, stateInvariantRoute, "state is consistent"), false
	}
}
