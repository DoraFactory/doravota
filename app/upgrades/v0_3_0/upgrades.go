package v0_3_0

import (
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/cosmos/cosmos-sdk/types/module"

	upgradetypes "github.com/cosmos/cosmos-sdk/x/upgrade/types"
)

func CreateUpgradeHandler(
    mm *module.Manager,
    configurator module.Configurator,
) upgradetypes.UpgradeHandler {
    return func(ctx sdk.Context, plan upgradetypes.Plan, vm module.VersionMap) (module.VersionMap, error) {
/* 		logger := ctx.Logger().With("upgrade", UpgradeName)
		// we just upgrade the wasm version, so we do nothing in module
		logger.Debug("running module migrations ...") */

		migrations, err := mm.RunMigrations(ctx, configurator, vm)
		if err != nil {
			return nil, err
		}

		return migrations, nil
        // return mm.RunMigrations(ctx, configurator, vm)
    }
}