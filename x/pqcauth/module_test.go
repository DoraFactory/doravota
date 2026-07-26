package pqcauth

import (
	"encoding/json"
	"math/rand"
	"testing"

	abci "github.com/cometbft/cometbft/abci/types"
	"github.com/cosmos/cosmos-sdk/client"
	"github.com/cosmos/cosmos-sdk/codec"
	codectypes "github.com/cosmos/cosmos-sdk/codec/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/cosmos/cosmos-sdk/types/module"
	"github.com/stretchr/testify/require"

	"github.com/DoraFactory/doravota/x/pqcauth/types"
)

type moduleInvariantRegistryStub struct {
	moduleName string
	route      string
	invariant  sdk.Invariant
}

func (r *moduleInvariantRegistryStub) RegisterRoute(
	moduleName string,
	route string,
	invariant sdk.Invariant,
) {
	r.moduleName = moduleName
	r.route = route
	r.invariant = invariant
}

func TestAppModuleBasicWiringAndGenesisValidation(t *testing.T) {
	basic := AppModuleBasic{}
	require.Equal(t, types.ModuleName, basic.Name())

	amino := codec.NewLegacyAmino()
	basic.RegisterLegacyAminoCodec(amino)
	registry := codectypes.NewInterfaceRegistry()
	basic.RegisterInterfaces(registry)

	ctx, moduleKeeper := setupGenesisTest(t, 1)
	cdc := moduleKeeper.Codec().(*codec.ProtoCodec)
	defaultGenesis := basic.DefaultGenesis(cdc)
	require.NoError(t, basic.ValidateGenesis(cdc, nil, defaultGenesis))

	var decoded types.GenesisState
	require.NoError(t, cdc.UnmarshalJSON(defaultGenesis, &decoded))
	require.Equal(t, types.DefaultParams(), decoded.Params)

	require.Error(t, basic.ValidateGenesis(cdc, nil, json.RawMessage("{")))
	invalid := decoded
	invalid.Params.NetworkId = nil
	invalidJSON := cdc.MustMarshalJSON(&invalid)
	require.Error(t, basic.ValidateGenesis(cdc, nil, invalidJSON))

	require.Equal(t, types.ModuleName, basic.GetTxCmd().Use)
	require.Equal(t, types.ModuleName, basic.GetQueryCmd().Use)
	basic.RegisterRESTRoutes(client.Context{}, nil)
	_ = ctx
}

func TestAppModuleLifecycleAndSimulationNoops(t *testing.T) {
	ctx, moduleKeeper := setupGenesisTest(t, 10)
	appModule := NewAppModule(moduleKeeper)
	require.Equal(t, uint64(1), appModule.ConsensusVersion())

	cdc := moduleKeeper.Codec().(*codec.ProtoCodec)
	genesis := types.DefaultGenesisState()
	updates := appModule.InitGenesis(
		ctx,
		cdc,
		cdc.MustMarshalJSON(genesis),
	)
	require.Empty(t, updates)
	exportedJSON := appModule.ExportGenesis(ctx, cdc)
	var exported types.GenesisState
	require.NoError(t, cdc.UnmarshalJSON(exportedJSON, &exported))
	expectedParams := genesis.Params
	expectedParams.NetworkId = types.NetworkIDForChain(ctx.ChainID())
	require.Equal(t, expectedParams, exported.Params)

	params := moduleKeeper.GetParams(ctx)
	pending := params.AsScheduled()
	pending.EnforcementMode = types.EnforcementMode_ENFORCEMENT_MODE_REQUIRED
	params.Pending = &pending
	params.PendingActivationHeight = uint64(ctx.BlockHeight())
	require.NoError(t, moduleKeeper.SetParams(ctx, params))
	appModule.BeginBlock(ctx, abci.RequestBeginBlock{})
	require.Nil(t, moduleKeeper.GetParams(ctx).Pending)
	require.Empty(t, appModule.EndBlock(ctx, abci.RequestEndBlock{}))

	invariants := &moduleInvariantRegistryStub{}
	appModule.RegisterInvariants(invariants)
	require.Equal(t, types.ModuleName, invariants.moduleName)
	require.NotEmpty(t, invariants.route)
	require.NotNil(t, invariants.invariant)

	simulationState := module.SimulationState{}
	appModule.GenerateGenesisState(&simulationState)
	require.Nil(t, appModule.ProposalContents(simulationState))
	require.Nil(t, appModule.RandomizedParams(rand.New(rand.NewSource(1))))
	appModule.RegisterStoreDecoder(nil)
	require.Nil(t, appModule.WeightedOperations(simulationState))
}
