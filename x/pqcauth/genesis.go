package pqcauth

import (
	"fmt"
	"math"

	sdk "github.com/cosmos/cosmos-sdk/types"

	"github.com/DoraFactory/doravota/x/pqcauth/keeper"
	"github.com/DoraFactory/doravota/x/pqcauth/types"
)

func InitGenesis(ctx sdk.Context, moduleKeeper keeper.Keeper, genesis types.GenesisState) {
	if err := types.ValidateGenesis(genesis); err != nil {
		panic(fmt.Errorf("invalid pqcauth genesis: %w", err))
	}
	if types.UsesLegacyDefaultNetworkID(genesis.Params.NetworkId) {
		if ctx.ChainID() == "" {
			panic("initialize pqcauth genesis: chain ID is required to derive network ID")
		}
		genesis.Params.NetworkId = types.NetworkIDForChain(ctx.ChainID())
	}
	if err := moduleKeeper.SetParams(ctx, genesis.Params); err != nil {
		panic(fmt.Errorf("set pqcauth genesis params: %w", err))
	}

	maxKnownKeyID := make(map[string]uint64)
	for _, key := range genesis.Keys {
		owner := sdk.MustAccAddressFromBech32(key.Owner)
		if err := moduleKeeper.SetKey(ctx, owner, key); err != nil {
			panic(fmt.Errorf("set pqcauth genesis key: %w", err))
		}
		if key.KeyId > maxKnownKeyID[key.Owner] {
			maxKnownKeyID[key.Owner] = key.KeyId
		}
	}
	for _, history := range genesis.KeyHistories {
		owner := sdk.MustAccAddressFromBech32(history.Owner)
		if err := moduleKeeper.SetKeyHistory(ctx, owner, history); err != nil {
			panic(fmt.Errorf("set pqcauth genesis key history: %w", err))
		}
		if history.LastCompactedKeyId > maxKnownKeyID[history.Owner] {
			maxKnownKeyID[history.Owner] = history.LastCompactedKeyId
		}
	}
	for _, policy := range genesis.Policies {
		owner := sdk.MustAccAddressFromBech32(policy.Owner)
		if err := moduleKeeper.SetAccountPolicy(ctx, owner, policy); err != nil {
			panic(fmt.Errorf("set pqcauth genesis policy: %w", err))
		}
	}
	sequenceOwners := make(map[string]struct{}, len(genesis.KeySequences))
	for _, sequence := range genesis.KeySequences {
		owner := sdk.MustAccAddressFromBech32(sequence.Owner)
		if err := moduleKeeper.SetKeySequence(ctx, owner, sequence); err != nil {
			panic(fmt.Errorf("set pqcauth genesis key sequence: %w", err))
		}
		sequenceOwners[sequence.Owner] = struct{}{}
	}
	for owner, keyID := range maxKnownKeyID {
		if _, exists := sequenceOwners[owner]; exists {
			continue
		}
		address := sdk.MustAccAddressFromBech32(owner)
		if keyID == math.MaxUint64 {
			panic(fmt.Errorf("derive pqcauth genesis key sequence: %w", types.ErrKeyLimit))
		}
		if err := moduleKeeper.SetKeySequence(ctx, address, types.AccountKeySequence{
			Owner:     owner,
			NextKeyId: keyID + 1,
		}); err != nil {
			panic(fmt.Errorf("derive pqcauth genesis key sequence: %w", err))
		}
	}
}

func ExportGenesis(ctx sdk.Context, moduleKeeper keeper.Keeper) *types.GenesisState {
	genesis := types.DefaultGenesisState()
	genesis.Params = moduleKeeper.GetParams(ctx).Effective(ctx.BlockHeight())
	moduleKeeper.IterateAllKeys(ctx, func(key types.PQCKeyRecord) bool {
		genesis.Keys = append(genesis.Keys, key)
		return false
	})
	moduleKeeper.IterateAllPolicies(ctx, func(policy types.AccountPolicy) bool {
		genesis.Policies = append(genesis.Policies, policy.Effective(ctx.BlockHeight()))
		return false
	})
	moduleKeeper.IterateAllSequences(ctx, func(sequence types.AccountKeySequence) bool {
		genesis.KeySequences = append(genesis.KeySequences, sequence)
		return false
	})
	moduleKeeper.IterateAllKeyHistories(ctx, func(history types.AccountKeyHistory) bool {
		genesis.KeyHistories = append(genesis.KeyHistories, history)
		return false
	})
	return genesis
}
