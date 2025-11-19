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
    }
}

// GenEnableSponsor returns a randomized EnableSponsor parameter for simulation
func GenEnableSponsor(r *rand.Rand) bool {
	// 80% chance to enable sponsorship (more interesting for simulation)
	return r.Intn(10) < 8
}

// removed legacy gas limit generator (MaxGasPerSponsorship no longer used)

// RandomizedParams generates random parameters for the sponsor module
func RandomizedParams(r *rand.Rand) types.Params {
    return types.Params{
        SponsorshipEnabled:     GenEnableSponsor(r),
        PolicyTicketTtlBlocks:  30,
    }
}

// ParamChangeProposals defines parameter changes that can be tested during simulation
// These will be used to test governance proposals that modify module parameters
type ParamChangeProposals struct {
	// EnableSponsorshipProposal tests enabling/disabling sponsorship
	EnableSponsorshipProposal simtypes.LegacyParamChange
    // MaxGasProposal removed
	// CombinedProposal tests changing multiple parameters at once
	CombinedProposal []simtypes.LegacyParamChange
}


// ValidateParams validates the generated parameters
func ValidateParams(params types.Params) error {
    // Merge with defaults to fill required fields
    base := types.DefaultParams()
    base.SponsorshipEnabled = params.SponsorshipEnabled
    // removed gas limit param
    if params.PolicyTicketTtlBlocks != 0 {
        base.PolicyTicketTtlBlocks = params.PolicyTicketTtlBlocks
    }
    if params.MaxExecMsgsPerTxForSponsor != 0 {
        base.MaxExecMsgsPerTxForSponsor = params.MaxExecMsgsPerTxForSponsor
    }
    if params.MaxPolicyExecMsgBytes != 0 {
        base.MaxPolicyExecMsgBytes = params.MaxPolicyExecMsgBytes
    }

    // Use the module's built-in validation
    if err := base.Validate(); err != nil {
        return fmt.Errorf("parameter validation failed: %w", err)
    }

    // No additional simulation-specific validation required
    return nil
}

// RandomParamsWithConstraints generates parameters within specific constraints for testing edge cases
func RandomParamsWithConstraints(r *rand.Rand, enabledWeight int, maxGasMin uint64, maxGasMax uint64) types.Params {
	// enabledWeight: higher number means more likely to be enabled (0-100)
	enabled := r.Intn(100) < enabledWeight

    return types.Params{
        SponsorshipEnabled:   enabled,
    }
}

// TestScenarioParams generates parameters for specific test scenarios
func TestScenarioParams() []types.Params {
	return []types.Params{
		// Scenario 1: Disabled sponsorship
        { SponsorshipEnabled: false },
        { SponsorshipEnabled: true  },
    }
}

// GetRandomTestScenario selects a random test scenario
func GetRandomTestScenario(r *rand.Rand) types.Params {
	scenarios := TestScenarioParams()
	return scenarios[r.Intn(len(scenarios))]
}
