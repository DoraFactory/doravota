package simulation

import (
	"encoding/json"
	"fmt"
	"math/rand"

	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/cosmos/cosmos-sdk/types/module"
	simtypes "github.com/cosmos/cosmos-sdk/types/simulation"

	"github.com/DoraFactory/doravota/x/sponsor-contract-tx/types"
)

const (
	SponsorshipEnabled    = "sponsorship_enabled"
	MaxGasPerSponsorship  = "max_gas_per_sponsorship"
	NumInitialSponsors    = "num_initial_sponsors"
)

// RandomizedGenState generates a random GenesisState for the sponsor module
func RandomizedGenState(simState *module.SimulationState) {
	var sponsorshipEnabled bool
	simState.AppParams.GetOrGenerate(
		simState.Cdc, SponsorshipEnabled, &sponsorshipEnabled, simState.Rand,
		func(r *rand.Rand) { sponsorshipEnabled = r.Intn(2) == 1 },
	)

	var maxGasPerSponsorship uint64
	simState.AppParams.GetOrGenerate(
		simState.Cdc, MaxGasPerSponsorship, &maxGasPerSponsorship, simState.Rand,
		func(r *rand.Rand) { 
			// Random value between 100,000 and 10,000,000 gas
			maxGasPerSponsorship = uint64(r.Intn(9900000) + 100000)
		},
	)

	var numInitialSponsors int
	simState.AppParams.GetOrGenerate(
		simState.Cdc, NumInitialSponsors, &numInitialSponsors, simState.Rand,
		func(r *rand.Rand) { 
			// Random number of initial sponsors (0-20)
			numInitialSponsors = r.Intn(21)
		},
	)

	// Generate random sponsors
	sponsors := generateRandomSponsors(simState.Rand, simState.Accounts, numInitialSponsors)

	// Create genesis parameters
	params := types.Params{
		SponsorshipEnabled:   sponsorshipEnabled,
		MaxGasPerSponsorship: maxGasPerSponsorship,
	}

	// Validate parameters
	if err := params.Validate(); err != nil {
		panic(fmt.Sprintf("invalid genesis params: %v", err))
	}

	// Create genesis state
	sponsorGenesis := types.GenesisState{
		Params:   &params,
		Sponsors: sponsors,
	}

	// Validate genesis state
	if err := types.ValidateGenesis(sponsorGenesis); err != nil {
		panic(fmt.Sprintf("invalid genesis state: %v", err))
	}

	bz, err := json.MarshalIndent(&sponsorGenesis, "", " ")
	if err != nil {
		panic(err)
	}
	fmt.Printf("Selected randomly generated sponsor parameters:\n%s\n", bz)

	simState.GenState[types.ModuleName] = simState.Cdc.MustMarshalJSON(&sponsorGenesis)
}

// generateRandomSponsors creates random sponsor entries for genesis
func generateRandomSponsors(r *rand.Rand, accounts []simtypes.Account, numSponsors int) []*types.ContractSponsor {
	if numSponsors == 0 || len(accounts) == 0 {
		return []*types.ContractSponsor{}
	}

	sponsors := make([]*types.ContractSponsor, 0, numSponsors)
	usedContracts := make(map[string]bool)

	for i := 0; i < numSponsors; i++ {
		// Generate unique contract address
		var contractAddr string
		for {
			// Use account addresses as mock contract addresses
			acc := accounts[r.Intn(len(accounts))]
			contractAddr = acc.Address.String()
			if !usedContracts[contractAddr] {
				usedContracts[contractAddr] = true
				break
			}
			// If we've used all accounts as contracts, break to avoid infinite loop
			if len(usedContracts) >= len(accounts) {
				goto done
			}
		}

		// Select random creator (admin)
		creator := accounts[r.Intn(len(accounts))]

		// Random sponsorship settings
		isSponsored := r.Intn(2) == 1

		var maxGrantPerUser []*sdk.Coin
		if isSponsored || r.Intn(3) == 0 { // 1/3 chance for non-sponsored to have max grant
			// Generate random grant amount in peaka
			amount := sdk.NewInt(int64(r.Intn(10000000) + 1000)) // 1000 to 10,001,000
			coin := sdk.NewCoin("peaka", amount)
			maxGrantPerUser = []*sdk.Coin{&coin}
		}

		sponsor := &types.ContractSponsor{
			ContractAddress: contractAddr,
			CreatorAddress:  creator.Address.String(),
			IsSponsored:     isSponsored,
			MaxGrantPerUser: maxGrantPerUser,
		}

		sponsors = append(sponsors, sponsor)
	}

done:
	return sponsors
}

// RandomParams returns random parameters for the sponsor module
func RandomParams(r *rand.Rand) types.Params {
	return types.Params{
		SponsorshipEnabled:   r.Intn(2) == 1,
		MaxGasPerSponsorship: uint64(r.Intn(9900000) + 100000), // 100K to 10M gas
	}
}

// RandomGenesisSponsors generates random sponsors for testing
func RandomGenesisSponsors(r *rand.Rand, accounts []simtypes.Account, numSponsors int) []types.ContractSponsor {
	if numSponsors == 0 {
		return nil
	}

	sponsors := make([]types.ContractSponsor, numSponsors)
	for i := 0; i < numSponsors; i++ {
		// Use different accounts to avoid conflicts
		creatorIdx := i % len(accounts)
		contractIdx := (i + 1) % len(accounts)

		// Ensure we don't use the same account for creator and contract
		if creatorIdx == contractIdx && len(accounts) > 1 {
			contractIdx = (contractIdx + 1) % len(accounts)
		}

		creator := accounts[creatorIdx]
		contractAddr := accounts[contractIdx].Address.String()

		isSponsored := r.Intn(2) == 1
		var maxGrantPerUser []*sdk.Coin

		if isSponsored {
			amount := sdk.NewInt(int64(r.Intn(5000000) + 1000))
			coin := sdk.NewCoin("peaka", amount)
			maxGrantPerUser = []*sdk.Coin{&coin}
		} else if r.Intn(4) == 0 { // 25% chance for non-sponsored to have max grant
			amount := sdk.NewInt(int64(r.Intn(1000000) + 500))
			coin := sdk.NewCoin("peaka", amount)
			maxGrantPerUser = []*sdk.Coin{&coin}
		}

		sponsors[i] = types.ContractSponsor{
			ContractAddress: contractAddr,
			CreatorAddress:  creator.Address.String(),
			IsSponsored:     isSponsored,
			MaxGrantPerUser: maxGrantPerUser,
		}
	}

	return sponsors
}

// RandomGenesisState generates a random genesis state for testing purposes
func RandomGenesisState(r *rand.Rand, accounts []simtypes.Account) *types.GenesisState {
	params := RandomParams(r)
	numSponsors := r.Intn(min(len(accounts), 10)) // Max 10 sponsors or number of accounts
	sponsors := RandomGenesisSponsors(r, accounts, numSponsors)

	// Convert to pointer slice
	sponsorPtrs := make([]*types.ContractSponsor, len(sponsors))
	for i := range sponsors {
		sponsorPtrs[i] = &sponsors[i]
	}

	return &types.GenesisState{
		Params:   &params,
		Sponsors: sponsorPtrs,
	}
}

// ValidateGenesisState validates the generated genesis state
func ValidateGenesisState(genesisState *types.GenesisState) error {
	// Validate using the module's validation function
	if err := types.ValidateGenesis(*genesisState); err != nil {
		return fmt.Errorf("genesis validation failed: %w", err)
	}

	// Additional simulation-specific validations
	if genesisState.Params == nil {
		return fmt.Errorf("params cannot be nil")
	}

	// Check for reasonable parameter values
	if genesisState.Params.MaxGasPerSponsorship > 50000000 {
		return fmt.Errorf("MaxGasPerSponsorship too high: %d", genesisState.Params.MaxGasPerSponsorship)
	}

	if genesisState.Params.MaxGasPerSponsorship < 10000 {
		return fmt.Errorf("MaxGasPerSponsorship too low: %d", genesisState.Params.MaxGasPerSponsorship)
	}

	// Validate sponsors
	contractAddrs := make(map[string]bool)
	for _, sponsor := range genesisState.Sponsors {
		if sponsor == nil {
			return fmt.Errorf("sponsor cannot be nil")
		}

		// Check for duplicates
		if contractAddrs[sponsor.ContractAddress] {
			return fmt.Errorf("duplicate contract address in genesis: %s", sponsor.ContractAddress)
		}
		contractAddrs[sponsor.ContractAddress] = true

		// Validate sponsor fields
		if sponsor.ContractAddress == "" {
			return fmt.Errorf("sponsor contract address cannot be empty")
		}

		if sponsor.CreatorAddress == "" {
			return fmt.Errorf("sponsor creator address cannot be empty")
		}

		// Validate MaxGrantPerUser if sponsored
		if sponsor.IsSponsored {
			if len(sponsor.MaxGrantPerUser) == 0 {
				return fmt.Errorf("sponsored contract %s must have MaxGrantPerUser", sponsor.ContractAddress)
			}

			for _, coin := range sponsor.MaxGrantPerUser {
				if coin == nil {
					return fmt.Errorf("coin in MaxGrantPerUser cannot be nil for contract %s", sponsor.ContractAddress)
				}
				if coin.Denom != "peaka" {
					return fmt.Errorf("invalid denom in MaxGrantPerUser for contract %s: %s", sponsor.ContractAddress, coin.Denom)
				}
				if !coin.Amount.IsPositive() {
					return fmt.Errorf("non-positive amount in MaxGrantPerUser for contract %s: %s", sponsor.ContractAddress, coin.Amount.String())
				}
			}
		}
	}

	return nil
}

// Helper function to get minimum of two integers
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}