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

	return genesis
}
