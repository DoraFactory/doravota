package app

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"

	wasmtypes "github.com/CosmWasm/wasmd/x/wasm/types"
	"github.com/cosmos/cosmos-sdk/baseapp"
	sdk "github.com/cosmos/cosmos-sdk/types"
	upgradetypes "github.com/cosmos/cosmos-sdk/x/upgrade/types"
)

// These values are embedded into the shared binary with -ldflags, never read
// from a validator's runtime flags or environment. An unconfigured build must
// not start an application. Choose the height only after operator coordination.
var EmergencyWasmHeight = "UNCONFIGURED"
var EmergencyWasmChainID = "UNCONFIGURED"

const EmergencyWasmVersion = "0.4.5"

// Use a separate namespace in the existing upgrade store, without creating a
// new module/store or touching the upgrade plan, done markers or version map.
// This raw backup survives an in-place upgrade and a physical DB snapshot.
// Standard SDK JSON genesis export does NOT include these auxiliary keys.
const emergencyWasmPrefix = "vota/maint/v1/"

type emergencyWasmGuard struct {
	height  int64
	chainID string
}

var _ baseapp.CircuitBreaker = emergencyWasmGuard{}

func newEmergencyWasmGuard() emergencyWasmGuard {
	height, err := strconv.ParseInt(EmergencyWasmHeight, 10, 64)
	if err != nil || height <= 0 || strconv.FormatInt(height, 10) != EmergencyWasmHeight {
		panic("maintenance activation height must be explicitly embedded as a positive integer")
	}
	if EmergencyWasmChainID == "" || EmergencyWasmChainID == "UNCONFIGURED" {
		panic("release chain ID must be explicitly embedded")
	}
	return emergencyWasmGuard{height: height, chainID: EmergencyWasmChainID}
}

// IsAllowed runs in the SDK message execution router, not just CheckTx.
// Authz, group, gov, ICA and Wasm submessages also use this router in 0.4.4.
// Block permission changes too, so a governance-authorized message cannot
// reopen a route during the emergency. Existing Execute/Query/IBC remain
// available, but their attempts to deploy or migrate contracts are rejected.
func (g emergencyWasmGuard) IsAllowed(goCtx context.Context, typeURL string) (bool, error) {
	ctx := sdk.UnwrapSDKContext(goCtx)
	if ctx.ChainID() != g.chainID {
		return false, fmt.Errorf("release is for chain %q, not %q", g.chainID, ctx.ChainID())
	}
	if ctx.BlockHeight() < g.height {
		return true, nil
	}
	switch typeURL {
	case "/cosmwasm.wasm.v1.MsgStoreCode",
		"/cosmwasm.wasm.v1.MsgInstantiateContract",
		"/cosmwasm.wasm.v1.MsgInstantiateContract2",
		"/cosmwasm.wasm.v1.MsgMigrateContract",
		"/cosmwasm.wasm.v1.MsgStoreAndInstantiateContract",
		"/cosmwasm.wasm.v1.MsgStoreAndMigrateContract",
		"/cosmwasm.wasm.v1.MsgUpdateInstantiateConfig",
		"/cosmwasm.wasm.v1.MsgUpdateParams",
		"/cosmwasm.wasm.v1.MsgAddCodeUploadParamsAddresses",
		"/cosmwasm.wasm.v1.MsgRemoveCodeUploadParamsAddresses":
		return false, nil
	default:
		return true, nil
	}
}

type emergencyWasmRecord struct {
	Version   string `json:"version"`
	ChainID   string `json:"chain_id"`
	Height    int64  `json:"height"`
	CodeCount int    `json:"code_count"`
}

type emergencyWasmCode struct {
	key      []byte
	original []byte
	info     wasmtypes.CodeInfo
}

// Read and close the iterator before writing any code records. Keep original
// protobuf bytes for an exact per-code permission recovery, not a blanket
// Everybody reset that would expose previously restricted code.
func (app *App) collectEmergencyWasmCodes(ctx sdk.Context) ([]emergencyWasmCode, error) {
	store := ctx.KVStore(app.keys[wasmtypes.StoreKey])
	it := sdk.KVStorePrefixIterator(store, wasmtypes.CodeKeyPrefix)
	defer it.Close()
	var codes []emergencyWasmCode
	for ; it.Valid(); it.Next() {
		if len(it.Key()) != len(wasmtypes.CodeKeyPrefix)+8 {
			return nil, fmt.Errorf("invalid Wasm code key length %d", len(it.Key()))
		}
		var info wasmtypes.CodeInfo
		if err := app.appCodec.Unmarshal(it.Value(), &info); err != nil {
			return nil, fmt.Errorf("decode Wasm code info: %w", err)
		}
		codes = append(codes, emergencyWasmCode{
			key: append([]byte(nil), it.Key()...), original: append([]byte(nil), it.Value()...), info: info,
		})
	}
	return codes, nil
}

// Called before any module BeginBlocker. Writes are committed together with
// block X. Replaying from X-1 repeats the same transition; restarting after X
// checks the saved activation record and never overwrites the original backup.
func (app *App) applyEmergencyWasmGuard(ctx sdk.Context) error {
	g := app.emergencyWasm
	if ctx.ChainID() != g.chainID {
		return fmt.Errorf("release is for chain %q, not %q", g.chainID, ctx.ChainID())
	}
	if ctx.BlockHeight() < g.height {
		return nil
	}
	key := []byte(emergencyWasmPrefix + "activation")
	backupStore := ctx.KVStore(app.keys[upgradetypes.StoreKey])
	if bz := backupStore.Get(key); bz != nil {
		var record emergencyWasmRecord
		if err := json.Unmarshal(bz, &record); err != nil {
			return fmt.Errorf("decode maintenance activation record: %w", err)
		}
		if record.Height != g.height || record.ChainID != g.chainID || record.Version != EmergencyWasmVersion {
			return fmt.Errorf("release configuration does not match committed activation record")
		}
		return nil
	}
	if ctx.BlockHeight() != g.height {
		return fmt.Errorf("missing maintenance activation at height %d: restore/replay from before activation; refusing a late state change at %d", g.height, ctx.BlockHeight())
	}

	cacheCtx, write := ctx.CacheContext()
	codes, err := app.collectEmergencyWasmCodes(cacheCtx)
	if err != nil {
		return err
	}
	wasmStore := cacheCtx.KVStore(app.keys[wasmtypes.StoreKey])
	backup := cacheCtx.KVStore(app.keys[upgradetypes.StoreKey])
	paramsBytes := wasmStore.Get(wasmtypes.ParamsKey)
	if len(paramsBytes) == 0 {
		return fmt.Errorf("missing Wasm parameters before emergency activation")
	}
	backup.Set([]byte(emergencyWasmPrefix+"original-params"), paramsBytes)
	params := app.WasmKeeper.GetParams(cacheCtx)
	params.CodeUploadAccess = wasmtypes.AccessConfig{Permission: wasmtypes.AccessTypeNobody}
	params.InstantiateDefaultPermission = wasmtypes.AccessTypeNobody
	if err := app.WasmKeeper.SetParams(cacheCtx, params); err != nil {
		return err
	}
	for _, code := range codes {
		backup.Set(append([]byte(emergencyWasmPrefix+"original-code/"), code.key...), code.original)
		code.info.InstantiateConfig = wasmtypes.AccessConfig{Permission: wasmtypes.AccessTypeNobody}
		bz, err := app.appCodec.Marshal(&code.info)
		if err != nil {
			return fmt.Errorf("encode restricted Wasm code info: %w", err)
		}
		wasmStore.Set(code.key, bz)
	}
	record, err := json.Marshal(emergencyWasmRecord{
		Version: EmergencyWasmVersion, ChainID: g.chainID, Height: g.height, CodeCount: len(codes),
	})
	if err != nil {
		return err
	}
	backup.Set(key, record)
	write()
	ctx.EventManager().EmitEvent(sdk.NewEvent("vota_maintenance_applied",
		sdk.NewAttribute("height", strconv.FormatInt(g.height, 10)),
		sdk.NewAttribute("code_count", strconv.Itoa(len(codes))),
	))
	ctx.Logger().Info("maintenance parameters applied", "height", g.height, "code_count", len(codes))
	return nil
}
