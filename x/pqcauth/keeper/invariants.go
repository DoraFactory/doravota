package keeper

import (
	"fmt"

	sdk "github.com/cosmos/cosmos-sdk/types"

	"github.com/DoraFactory/doravota/x/pqcauth/types"
)

const stateInvariantRoute = "state-consistency"

func RegisterInvariants(
	registry sdk.InvariantRegistry,
	moduleKeeper Keeper,
	feegrantSource FeegrantAllowanceSource,
) {
	registry.RegisterRoute(
		types.ModuleName,
		stateInvariantRoute,
		StateInvariant(moduleKeeper, feegrantSource),
	)
}

func StateInvariant(moduleKeeper Keeper, feegrantSource FeegrantAllowanceSource) sdk.Invariant {
	return func(ctx sdk.Context) (string, bool) {
		report := moduleKeeper.AuditStateWithFeegrant(
			ctx,
			feegrantSource,
			types.DefaultStateAuditMaxIssues,
		)
		if err := report.Error(); err != nil {
			return sdk.FormatInvariant(
				types.ModuleName,
				stateInvariantRoute,
				fmt.Sprintf("invalid pqcauth state (%d issues): %v", report.TotalIssues, err),
			), true
		}
		return sdk.FormatInvariant(types.ModuleName, stateInvariantRoute, "state is consistent"), false
	}
}
