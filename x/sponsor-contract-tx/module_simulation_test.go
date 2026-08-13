package sponsor_test

import (
	"encoding/json"
	"math/rand"
	"testing"

	"github.com/cosmos/cosmos-sdk/codec"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/cosmos/cosmos-sdk/types/kv"
	"github.com/cosmos/cosmos-sdk/types/module"
	simtypes "github.com/cosmos/cosmos-sdk/types/simulation"
	"github.com/stretchr/testify/require"

	sponsor "github.com/DoraFactory/doravota/x/sponsor-contract-tx"
	"github.com/DoraFactory/doravota/x/sponsor-contract-tx/keeper"
	"github.com/DoraFactory/doravota/x/sponsor-contract-tx/types"
)

type moduleInvariantRegistry struct {
	routes map[string]sdk.Invariant
}

func (r *moduleInvariantRegistry) RegisterRoute(moduleName, route string, invariant sdk.Invariant) {
	if r.routes == nil {
		r.routes = make(map[string]sdk.Invariant)
	}
	r.routes[moduleName+"/"+route] = invariant
}

func TestAppModuleProductionWiring(t *testing.T) {
	k, _ := setupKeeper(t)
	appCodec, ok := k.Cdc().(codec.Codec)
	require.True(t, ok)
	am := sponsor.NewAppModule(appCodec, k, minimalBankKeeper{}, minimalAuthKeeper{})

	invariants := &moduleInvariantRegistry{}
	am.RegisterInvariants(invariants)
	require.Contains(t, invariants.routes, types.ModuleName+"/"+keeper.LifecycleInvariantRoute)
	require.Contains(t, invariants.routes, types.ModuleName+"/"+keeper.ParamsInvariantRoute)

	storeDecoders := make(simtypes.StoreDecoderRegistry)
	am.RegisterStoreDecoder(storeDecoders)
	require.Contains(t, storeDecoders, types.StoreKey)
	params := types.DefaultParams()
	paramsBz := k.Cdc().MustMarshal(&params)
	decoded := storeDecoders[types.StoreKey](
		kv.Pair{Key: types.ParamsKey, Value: paramsBz},
		kv.Pair{Key: types.ParamsKey, Value: paramsBz},
	)
	require.Contains(t, decoded, "PolicyTicketTtlBlocks:30")

	simState := module.SimulationState{
		AppParams: make(simtypes.AppParams),
		Cdc:       appCodec,
		Rand:      rand.New(rand.NewSource(1)),
		GenState:  make(map[string]json.RawMessage),
	}
	am.GenerateGenesisState(&simState)
	require.Contains(t, simState.GenState, types.ModuleName)
	require.Len(t, am.WeightedOperations(simState), 6)
	require.Empty(t, am.RandomizedParams(rand.New(rand.NewSource(1))))
}
