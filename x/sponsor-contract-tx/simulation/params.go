package simulation

import (
	"fmt"
	"math/rand"

	simtypes "github.com/cosmos/cosmos-sdk/types/simulation"

	"github.com/DoraFactory/doravota/x/sponsor-contract-tx/types"
)

// ParamChanges is intentionally empty. Sponsor params are stored by the module
// keeper and updated through MsgUpdateParams; they are not backed by an x/params
// Subspace, so generating legacy parameter-change proposals would only exercise
// an invalid route.
func ParamChanges(_ *rand.Rand) []simtypes.LegacyParamChange {
	return nil
}

// GenEnableSponsor returns a randomized EnableSponsor parameter for simulation
func GenEnableSponsor(r *rand.Rand) bool {
	// 80% chance to enable sponsorship (more interesting for simulation)
	return r.Intn(10) < 8
}

// removed legacy gas limit generator (MaxGasPerSponsorship no longer used)

// RandomizedParams generates random parameters for the sponsor module
func RandomizedParams(r *rand.Rand) types.Params {
	params := types.DefaultParams()
	params.SponsorshipEnabled = GenEnableSponsor(r)
	return params
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

	params := types.DefaultParams()
	params.SponsorshipEnabled = enabled
	return params
}

// TestScenarioParams generates parameters for specific test scenarios
func TestScenarioParams() []types.Params {
	disabled := types.DefaultParams()
	disabled.SponsorshipEnabled = false
	enabled := types.DefaultParams()
	enabled.SponsorshipEnabled = true
	return []types.Params{
		disabled,
		enabled,
	}
}

// GetRandomTestScenario selects a random test scenario
func GetRandomTestScenario(r *rand.Rand) types.Params {
	scenarios := TestScenarioParams()
	return scenarios[r.Intn(len(scenarios))]
}
