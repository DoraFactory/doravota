package simulation

import (
	"fmt"
	"math/rand"

	simtypes "github.com/cosmos/cosmos-sdk/types/simulation"
	"github.com/cosmos/cosmos-sdk/x/simulation"

	"github.com/DoraFactory/doravota/x/sponsor-contract-tx/types"
)

const (
	keyEnableSponsor        = "EnableSponsor"
	keyMaxGasPerSponsorship = "MaxGasPerSponsorship"
)

// ParamChanges defines the parameters that can be modified by governance proposals
// during the simulation
func ParamChanges(r *rand.Rand) []simtypes.LegacyParamChange {
	return []simtypes.LegacyParamChange{
		simulation.NewSimLegacyParamChange(types.ModuleName, keyEnableSponsor,
			func(r *rand.Rand) string {
				return fmt.Sprintf(`%t`, GenEnableSponsor(r))
			},
		),
		simulation.NewSimLegacyParamChange(types.ModuleName, keyMaxGasPerSponsorship,
			func(r *rand.Rand) string {
				return fmt.Sprintf(`"%d"`, GenMaxGasPerSponsorship(r))
			},
		),
	}
}

// GenEnableSponsor returns a randomized EnableSponsor parameter for simulation
func GenEnableSponsor(r *rand.Rand) bool {
	// 80% chance to enable sponsorship (more interesting for simulation)
	return r.Intn(10) < 8
}

// GenMaxGasPerSponsorship returns a randomized MaxGasPerSponsorship parameter for simulation
func GenMaxGasPerSponsorship(r *rand.Rand) uint64 {
	// Generate reasonable gas limits for sponsorship
	// Range from 100,000 to 10,000,000 gas
	return uint64(r.Intn(9900000) + 100000)
}

// RandomizedParams generates random parameters for the sponsor module
func RandomizedParams(r *rand.Rand) types.Params {
	return types.Params{
		SponsorshipEnabled:   GenEnableSponsor(r),
		MaxGasPerSponsorship: GenMaxGasPerSponsorship(r),
	}
}

// ParamChangeProposals defines parameter changes that can be tested during simulation
// These will be used to test governance proposals that modify module parameters
type ParamChangeProposals struct {
	// EnableSponsorshipProposal tests enabling/disabling sponsorship
	EnableSponsorshipProposal simtypes.LegacyParamChange
	// MaxGasProposal tests changing max gas limits
	MaxGasProposal simtypes.LegacyParamChange
	// CombinedProposal tests changing multiple parameters at once
	CombinedProposal []simtypes.LegacyParamChange
}

// NewParamChangeProposals creates new parameter change proposals for simulation
func NewParamChangeProposals(r *rand.Rand) ParamChangeProposals {
	return ParamChangeProposals{
		EnableSponsorshipProposal: simulation.NewSimLegacyParamChange(
			types.ModuleName,
			string(types.KeySponsorshipEnabled),
			func(r *rand.Rand) string {
				enabled := GenEnableSponsor(r)
				return fmt.Sprintf(`%t`, enabled)
			},
		),
		MaxGasProposal: simulation.NewSimLegacyParamChange(
			types.ModuleName,
			string(types.KeyMaxGasPerSponsorship),
			func(r *rand.Rand) string {
				maxGas := GenMaxGasPerSponsorship(r)
				return fmt.Sprintf(`"%d"`, maxGas)
			},
		),
		CombinedProposal: []simtypes.LegacyParamChange{
			simulation.NewSimLegacyParamChange(
				types.ModuleName,
				string(types.KeySponsorshipEnabled),
				func(r *rand.Rand) string {
					return fmt.Sprintf(`%t`, GenEnableSponsor(r))
				},
			),
			simulation.NewSimLegacyParamChange(
				types.ModuleName,
				string(types.KeyMaxGasPerSponsorship),
				func(r *rand.Rand) string {
					return fmt.Sprintf(`"%d"`, GenMaxGasPerSponsorship(r))
				},
			),
		},
	}
}

// ValidateParams validates the generated parameters
func ValidateParams(params types.Params) error {
	// Use the module's built-in validation
	if err := params.Validate(); err != nil {
		return fmt.Errorf("parameter validation failed: %w", err)
	}

	// Additional simulation-specific validation
	if params.MaxGasPerSponsorship > 50000000 {
		return fmt.Errorf("MaxGasPerSponsorship is too high for simulation: %d", params.MaxGasPerSponsorship)
	}

	if params.MaxGasPerSponsorship < 1000 {
		return fmt.Errorf("MaxGasPerSponsorship is too low for simulation: %d", params.MaxGasPerSponsorship)
	}

	return nil
}

// RandomParamsWithConstraints generates parameters within specific constraints for testing edge cases
func RandomParamsWithConstraints(r *rand.Rand, enabledWeight int, maxGasMin uint64, maxGasMax uint64) types.Params {
	// enabledWeight: higher number means more likely to be enabled (0-100)
	enabled := r.Intn(100) < enabledWeight

	// Constrain max gas within bounds
	var maxGas uint64
	if maxGasMax <= maxGasMin {
		maxGas = maxGasMin
	} else {
		maxGas = uint64(r.Intn(int(maxGasMax-maxGasMin))) + maxGasMin
	}

	return types.Params{
		SponsorshipEnabled:   enabled,
		MaxGasPerSponsorship: maxGas,
	}
}

// TestScenarioParams generates parameters for specific test scenarios
func TestScenarioParams() []types.Params {
	return []types.Params{
		// Scenario 1: Disabled sponsorship
		{
			SponsorshipEnabled:   false,
			MaxGasPerSponsorship: 1000000,
		},
		// Scenario 2: Very low gas limit
		{
			SponsorshipEnabled:   true,
			MaxGasPerSponsorship: 1000,
		},
		// Scenario 3: Very high gas limit
		{
			SponsorshipEnabled:   true,
			MaxGasPerSponsorship: 50000000,
		},
		// Scenario 4: Standard configuration
		{
			SponsorshipEnabled:   true,
			MaxGasPerSponsorship: 1000000,
		},
		// Scenario 5: Edge case - minimum valid gas
		{
			SponsorshipEnabled:   true,
			MaxGasPerSponsorship: 1,
		},
	}
}

// GetRandomTestScenario selects a random test scenario
func GetRandomTestScenario(r *rand.Rand) types.Params {
	scenarios := TestScenarioParams()
	return scenarios[r.Intn(len(scenarios))]
}
