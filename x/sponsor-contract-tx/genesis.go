package sponsor

import (
	"fmt"

	"github.com/DoraFactory/doravota/x/sponsor-contract-tx/keeper"
	"github.com/DoraFactory/doravota/x/sponsor-contract-tx/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
)

// InitGenesis initializes the capability module's state from a provided genesis state
func InitGenesis(ctx sdk.Context, k keeper.Keeper, genState types.GenesisState) {
	// Set module parameters
	if genState.Params != nil {
		k.SetParams(ctx, *genState.Params)
	}

	// Set all sponsors
	for _, sponsor := range genState.Sponsors {
		// Convert pointer to value type
		if err := k.SetSponsor(ctx, *sponsor); err != nil {
			panic(fmt.Errorf("failed to set sponsor during genesis initialization: %w", err))
		}
	}

	// Set user grant usage state
	for _, usage := range genState.UserGrantUsages {
		if usage == nil {
			continue
		}

		if err := k.SetUserGrantUsage(ctx, *usage); err != nil {
			panic(fmt.Errorf("failed to set user grant usage during genesis initialization: %w", err))
		}
	}

	// Set failed attempts (global cooldown) state
	for _, fa := range genState.FailedAttempts {
		if fa == nil || fa.Record == nil {
			continue
		}
		// Validate addresses
		if err := types.ValidateContractAddress(fa.ContractAddress); err != nil {
			panic(fmt.Errorf("invalid failed-attempts contract address in genesis: %w", err))
		}
		if fa.UserAddress == "" {
			panic(fmt.Errorf("invalid failed-attempts user address in genesis: empty"))
		}
		if _, err := sdk.AccAddressFromBech32(fa.UserAddress); err != nil {
			panic(fmt.Errorf("invalid failed-attempts user address in genesis: %w", err))
		}
		k.SetFailedAttempts(ctx, fa.ContractAddress, fa.UserAddress, *fa.Record)
	}
}

// ExportGenesis returns the capability module's exported genesis
func ExportGenesis(ctx sdk.Context, k keeper.Keeper) *types.GenesisState {
	genesis := types.DefaultGenesisState()

	// Export module parameters
	params := k.GetParams(ctx)
	genesis.Params = &params

	// Convert []ContractSponsor to []*ContractSponsor
	sponsors := k.GetAllSponsors(ctx)
	sponsorPtrs := make([]*types.ContractSponsor, len(sponsors))
	for i := range sponsors {
		sponsorPtrs[i] = &sponsors[i]
	}
	genesis.Sponsors = sponsorPtrs

	// Export user grant usage records
	usages := k.GetAllUserGrantUsages(ctx)
	usagePtrs := make([]*types.UserGrantUsage, len(usages))
	for i := range usages {
		usagePtrs[i] = &usages[i]
	}
	genesis.UserGrantUsages = usagePtrs

	// Export failed attempts (global cooldown) records via keeper helper
	genesis.FailedAttempts = k.GetAllFailedAttemptsEntries(ctx)

	return genesis
}
