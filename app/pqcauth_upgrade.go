package app

import (
	"context"
	"crypto/sha256"
	"fmt"

	aminoUpgrade "github.com/DoraFactory/doravota/app/upgrades/amino"
	"github.com/DoraFactory/doravota/app/wasmarchive"
	pqctypes "github.com/DoraFactory/doravota/x/pqcauth/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/cosmos/cosmos-sdk/types/module"
	upgradetypes "github.com/cosmos/cosmos-sdk/x/upgrade/types"
)

// PQCAuthUpgradeName is a candidate plan for a separate post-v1.0.1 upgrade.
// It is not a published release tag or an approved mainnet schedule.
const PQCAuthUpgradeName = "v1.1.0"

func (app *App) registerPQCAuthUpgrade() {
	app.UpgradeKeeper.SetUpgradeHandler(PQCAuthUpgradeName, func(goCtx context.Context, _ upgradetypes.Plan, from module.VersionMap) (module.VersionMap, error) {
		ctx := sdk.UnwrapSDKContext(goCtx)
		active, err := aminoUpgrade.IsActive(ctx, app.keys[upgradetypes.StoreKey])
		if err != nil || !active {
			return nil, fmt.Errorf("PQC Auth requires activated %s signing rules: %v", aminoUpgrade.UpgradeName, err)
		}
		if from[wasmarchive.GenesisKey] != 1 {
			return nil, fmt.Errorf("PQC Auth requires completed v1.0.0 Wasm retirement")
		}
		if _, exists := from[pqctypes.ModuleName]; exists {
			return nil, fmt.Errorf("PQC Auth is already initialized")
		}
		for name, version := range app.mm.GetVersionMap() {
			if name != pqctypes.ModuleName && from[name] != version {
				return nil, fmt.Errorf("PQC Auth source version mismatch for %s: have %d want %d", name, from[name], version)
			}
		}
		updated, err := app.mm.RunMigrations(goCtx, app.configurator, from)
		if err != nil {
			return nil, err
		}
		params := app.PQCAuthKeeper.GetParams(ctx)
		if params.EnforcementMode != pqctypes.EnforcementMode_ENFORCEMENT_MODE_OPTIONAL {
			return nil, fmt.Errorf("initial PQC enforcement must be optional")
		}
		domain := sha256.Sum256([]byte("doravota/pqcauth/upgrade/" + PQCAuthUpgradeName + "/" + ctx.ChainID()))
		params.NetworkId = domain[:]
		if err := app.PQCAuthKeeper.SetParams(ctx, params); err != nil {
			return nil, err
		}
		// InitGenesis only initializes PQC state. Phase one never scans or
		// rewrites existing accounts, Authz grants or Feegrant allowances.
		return updated, nil
	})
}
