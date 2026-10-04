package app

import (
	wasmkeeper "github.com/CosmWasm/wasmd/x/wasm/keeper"
	wasmtypes "github.com/CosmWasm/wasmd/x/wasm/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
)

// applyWasmDeploymentRestrictions keeps query-visible permissions aligned with
// the application-wide deployment guard. It does not change contract storage,
// bytecode, bank balances or IBC state. Called at InitChain and upgrade only.
func (app *App) applyWasmDeploymentRestrictions(ctx sdk.Context) error {
	params := app.WasmKeeper.GetParams(ctx)
	params.CodeUploadAccess = wasmtypes.AllowNobody
	params.InstantiateDefaultPermission = wasmtypes.AccessTypeNobody
	if err := app.WasmKeeper.SetParams(ctx, params); err != nil {
		return err
	}
	var ids []uint64
	app.WasmKeeper.IterateCodeInfos(ctx, func(id uint64, info wasmtypes.CodeInfo) bool {
		if info.InstantiateConfig.Permission != wasmtypes.AccessTypeNobody {
			ids = append(ids, id)
		}
		return false
	})
	// Do not write through a live store iterator.
	keeper := wasmkeeper.NewGovPermissionKeeper(app.WasmKeeper)
	for _, id := range ids {
		if err := keeper.SetAccessConfig(ctx, id, nil, wasmtypes.AllowNobody); err != nil {
			return err
		}
	}
	return nil
}
