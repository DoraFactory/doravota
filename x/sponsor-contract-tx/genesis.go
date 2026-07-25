package sponsor

import (
	"fmt"
	"math"
	"sort"

	"github.com/DoraFactory/doravota/x/sponsor-contract-tx/keeper"
	"github.com/DoraFactory/doravota/x/sponsor-contract-tx/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/cosmos/cosmos-sdk/types/address"
)

// InitGenesis initializes the capability module's state from a provided genesis state
func InitGenesis(ctx sdk.Context, k keeper.Keeper, genState types.GenesisState) {
	if err := types.ValidateGenesis(genState); err != nil {
		panic(fmt.Errorf("invalid sponsor genesis state: %w", err))
	}

	// Set module parameters
	if genState.Params != nil {
		if err := k.SetParams(ctx, *genState.Params); err != nil {
			panic(fmt.Errorf("failed to set sponsor params during genesis initialization: %w", err))
		}
	}

	// Restore lifecycle generations before importing state. A contract without
	// an active Sponsor uses its explicitly exported tombstone. For legacy
	// genesis files without that field, derive the generation after the newest
	// historical ticket/usage.
	declaredGenerations := make(map[string]uint64, len(genState.ContractGenerations))
	for _, contractGeneration := range genState.ContractGenerations {
		declaredGenerations[contractGeneration.ContractAddress] = contractGeneration.Generation
	}
	activeGenerations := make(map[string]uint64, len(genState.Sponsors))
	maxHistoricalGeneration := make(map[string]uint64)
	normalizedSponsors := make([]*types.ContractSponsor, len(genState.Sponsors))
	for i, sponsor := range genState.Sponsors {
		normalizedSponsor := *sponsor
		if normalizedSponsor.Generation == 0 {
			normalizedSponsor.Generation = declaredGenerations[normalizedSponsor.ContractAddress]
			if normalizedSponsor.Generation == 0 {
				normalizedSponsor.Generation = 1
			}
		}
		normalizedSponsors[i] = &normalizedSponsor
		activeGenerations[normalizedSponsor.ContractAddress] = normalizedSponsor.Generation
	}
	genState.Sponsors = normalizedSponsors

	normalizedUsages := make([]*types.UserGrantUsage, len(genState.UserGrantUsages))
	for i, usage := range genState.UserGrantUsages {
		normalizedUsage := *usage
		if normalizedUsage.Generation == 0 {
			normalizedUsage.Generation = activeGenerations[normalizedUsage.ContractAddress]
			if normalizedUsage.Generation == 0 {
				normalizedUsage.Generation = 1
			}
		}
		normalizedUsages[i] = &normalizedUsage
		if normalizedUsage.Generation > maxHistoricalGeneration[normalizedUsage.ContractAddress] {
			maxHistoricalGeneration[normalizedUsage.ContractAddress] = normalizedUsage.Generation
		}
	}
	genState.UserGrantUsages = normalizedUsages

	normalizedTickets := make([]*types.PolicyTicket, len(genState.PolicyTickets))
	for i, ticket := range genState.PolicyTickets {
		normalizedTicket := *ticket
		if normalizedTicket.Generation == 0 {
			normalizedTicket.Generation = activeGenerations[normalizedTicket.ContractAddress]
			if normalizedTicket.Generation == 0 {
				normalizedTicket.Generation = 1
			}
		}
		normalizedTickets[i] = &normalizedTicket
		if normalizedTicket.Generation > maxHistoricalGeneration[normalizedTicket.ContractAddress] {
			maxHistoricalGeneration[normalizedTicket.ContractAddress] = normalizedTicket.Generation
		}
	}
	genState.PolicyTickets = normalizedTickets

	for _, contractAddr := range sortedGenerationContracts(declaredGenerations) {
		if err := k.SetSponsorGenerationForGenesis(
			ctx,
			contractAddr,
			declaredGenerations[contractAddr],
		); err != nil {
			panic(fmt.Errorf("failed to restore exported sponsor generation: %w", err))
		}
	}
	for _, contractAddr := range sortedGenerationContracts(activeGenerations) {
		generation := activeGenerations[contractAddr]
		if historical := maxHistoricalGeneration[contractAddr]; historical > generation {
			panic(fmt.Errorf(
				"historical generation %d exceeds active sponsor generation %d for contract %s",
				historical,
				generation,
				contractAddr,
			))
		}
		if declared := declaredGenerations[contractAddr]; declared != 0 {
			if declared != generation {
				panic(fmt.Errorf(
					"active sponsor generation %d does not match exported generation %d for contract %s",
					generation,
					declared,
					contractAddr,
				))
			}
			continue
		}
		if err := k.SetSponsorGenerationForGenesis(ctx, contractAddr, generation); err != nil {
			panic(fmt.Errorf("failed to restore sponsor generation: %w", err))
		}
	}
	for _, contractAddr := range sortedGenerationContracts(maxHistoricalGeneration) {
		historical := maxHistoricalGeneration[contractAddr]
		if _, active := activeGenerations[contractAddr]; active {
			continue
		}
		if declared := declaredGenerations[contractAddr]; declared != 0 {
			if historical >= declared {
				panic(fmt.Errorf(
					"historical generation %d is not older than exported tombstone %d for contract %s",
					historical,
					declared,
					contractAddr,
				))
			}
			continue
		}
		if historical == math.MaxUint64 {
			panic(fmt.Errorf("historical sponsor generation exhausted for contract %s", contractAddr))
		}
		if err := k.SetSponsorGenerationForGenesis(ctx, contractAddr, historical+1); err != nil {
			panic(fmt.Errorf("failed to restore deleted sponsor generation: %w", err))
		}
	}

	// Set all sponsors
	for _, sponsor := range genState.Sponsors {
		// Convert pointer to value type
		// Defensive validations that require keepers/state
		// 1) Ensure the contract exists in wasm keeper
		if err := k.ValidateContractExists(ctx, sponsor.ContractAddress); err != nil {
			panic(fmt.Errorf("invalid sponsor contract in genesis: %w", err))
		}
		// 2) Active Sponsor state requires a live Wasm admin. A contract with
		// cleared admin cannot be recovered or safely manage Sponsor funds.
		hasAdmin, err := k.HasContractAdmin(ctx, sponsor.ContractAddress)
		if err != nil {
			panic(fmt.Errorf("failed to inspect sponsor contract admin in genesis: %w", err))
		}
		if !hasAdmin {
			panic(fmt.Errorf("active sponsor contract %s has no wasm admin", sponsor.ContractAddress))
		}
		// 3) Ensure sponsor address is the expected derived address
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
		if err := k.SetSponsorForGenesis(ctx, *sponsor); err != nil {
			panic(fmt.Errorf("failed to set sponsor during genesis initialization: %w", err))
		}
	}

	// Set user grant usage state
	for _, usage := range genState.UserGrantUsages {
		if usage == nil {
			continue
		}
		if err := k.SetUserGrantUsageForGenesis(ctx, *usage); err != nil {
			panic(fmt.Errorf("failed to set user grant usage during genesis initialization: %w", err))
		}
	}

	// Set outstanding policy tickets (including near-expiry tickets). These may be
	// garbage-collected later by the per-block GC routine.
	// Enforce method length limit using current module params
	mLimit := k.GetParams(ctx).EffectiveMaxMethodBytes()
	for _, t := range genState.PolicyTickets {
		if t == nil {
			continue
		}
		// Basic defensive checks
		if err := types.ValidateContractAddress(t.ContractAddress); err != nil {
			panic(fmt.Errorf("invalid policy ticket contract in genesis: %w", err))
		}
		if _, err := sdk.AccAddressFromBech32(t.UserAddress); err != nil {
			panic(fmt.Errorf("invalid policy ticket user address in genesis: %w", err))
		}
		if t.Digest == "" {
			panic(fmt.Errorf("invalid policy ticket digest in genesis: empty"))
		}
		if t.Method != "" && mLimit != 0 && uint32(len(t.Method)) > mLimit {
			panic(fmt.Errorf("invalid policy ticket method in genesis: too long"))
		}
		if err := k.SetPolicyTicketForGenesis(ctx, *t); err != nil {
			panic(fmt.Errorf("failed to set policy ticket during genesis initialization: %w", err))
		}
	}

}

func sortedGenerationContracts(generations map[string]uint64) []string {
	contracts := make([]string, 0, len(generations))
	for contract := range generations {
		contracts = append(contracts, contract)
	}
	sort.Strings(contracts)
	return contracts
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

	// Export policy tickets
	var tickets []*types.PolicyTicket
	k.IteratePolicyTickets(ctx, func(_ []byte, t types.PolicyTicket) (stop bool) {
		tt := t
		tickets = append(tickets, &tt)
		return false
	})
	genesis.PolicyTickets = tickets

	// Export lifecycle generations independently of Sponsor/ticket/usage state.
	// This preserves a deletion tombstone even after all historical rows are GC'd.
	var generations []*types.ContractGeneration
	if err := k.IterateSponsorGenerations(ctx, func(contractAddr string, generation uint64) bool {
		generations = append(generations, &types.ContractGeneration{
			ContractAddress: contractAddr,
			Generation:      generation,
		})
		return false
	}); err != nil {
		panic(fmt.Errorf("failed to export sponsor lifecycle generations: %w", err))
	}
	genesis.ContractGenerations = generations

	return genesis
}
