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
		moduleKeeper.IterateAllKeys(ctx, func(key types.PQCKeyRecord) bool {
			genesis.Keys = append(genesis.Keys, key)
			return false
		})
		moduleKeeper.IterateAllPolicies(ctx, func(policy types.AccountPolicy) bool {
			genesis.Policies = append(genesis.Policies, policy)
			return false
		})
		moduleKeeper.IterateAllSequences(ctx, func(sequence types.AccountKeySequence) bool {
			genesis.KeySequences = append(genesis.KeySequences, sequence)
			return false
		})
		if err := types.ValidateGenesis(genesis); err != nil {
			return sdk.FormatInvariant(
				types.ModuleName,
				stateInvariantRoute,
				fmt.Sprintf("invalid pqcauth state: %v", err),
			), true
		}
		return sdk.FormatInvariant(types.ModuleName, stateInvariantRoute, "state is consistent"), false
	}
}
