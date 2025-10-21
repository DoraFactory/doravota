package sponsor

import (
	"fmt"

	"github.com/DoraFactory/doravota/x/sponsor-contract-tx/keeper"
	"github.com/DoraFactory/doravota/x/sponsor-contract-tx/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/cosmos/cosmos-sdk/types/address"
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
		// Defensive validations that require keepers/state
		// 1) Ensure the contract exists in wasm keeper
		if err := k.ValidateContractExists(ctx, sponsor.ContractAddress); err != nil {
			panic(fmt.Errorf("invalid sponsor contract in genesis: %w", err))
		}
		// 2) Ensure sponsor address is the expected derived address
		contractAccAddr, err := sdk.AccAddressFromBech32(sponsor.ContractAddress)
		if err != nil {
			panic(fmt.Errorf("invalid sponsor contract address in genesis: %w", err))
		}
		expectedSponsor := sdk.AccAddress(address.Derive(contractAccAddr, []byte("sponsor")))
		sponsorAccAddr, err := sdk.AccAddressFromBech32(sponsor.SponsorAddress)
		if err != nil {
			panic(fmt.Errorf("invalid sponsor address in genesis: %w", err))
		}
		if !expectedSponsor.Equals(sponsorAccAddr) {
			panic(fmt.Errorf("sponsor address mismatch in genesis: expected %s, got %s for contract %s", expectedSponsor.String(), sponsor.SponsorAddress, sponsor.ContractAddress))
		}
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


	return genesis
}
