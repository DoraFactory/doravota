package pqcauth

import (
	"context"
	"encoding/json"
	"math/rand"

	abci "github.com/cometbft/cometbft/abci/types"
	"github.com/cosmos/cosmos-sdk/client"
	"github.com/cosmos/cosmos-sdk/codec"
	codectypes "github.com/cosmos/cosmos-sdk/codec/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/cosmos/cosmos-sdk/types/module"
	simtypes "github.com/cosmos/cosmos-sdk/types/simulation"
	"github.com/gorilla/mux"
	"github.com/grpc-ecosystem/grpc-gateway/runtime"
	"github.com/spf13/cobra"

	"github.com/DoraFactory/doravota/x/pqcauth/client/cli"
	"github.com/DoraFactory/doravota/x/pqcauth/keeper"
	"github.com/DoraFactory/doravota/x/pqcauth/types"
)

var (
	_ module.AppModule      = AppModule{}
	_ module.AppModuleBasic = AppModuleBasic{}
)

type AppModuleBasic struct{}

func (AppModuleBasic) Name() string { return types.ModuleName }

func (AppModuleBasic) RegisterLegacyAminoCodec(cdc *codec.LegacyAmino) {
	types.RegisterLegacyAminoCodec(cdc)
}

func (AppModuleBasic) RegisterInterfaces(registry codectypes.InterfaceRegistry) {
	types.RegisterInterfaces(registry)
}

func (AppModuleBasic) DefaultGenesis(cdc codec.JSONCodec) json.RawMessage {
	return cdc.MustMarshalJSON(types.DefaultGenesisState())
}

func (AppModuleBasic) ValidateGenesis(
	cdc codec.JSONCodec,
	_ client.TxEncodingConfig,
	bz json.RawMessage,
) error {
	var genesis types.GenesisState
	if err := cdc.UnmarshalJSON(bz, &genesis); err != nil {
		return err
	}
	return types.ValidateGenesis(genesis)
}

func (AppModuleBasic) RegisterRESTRoutes(client.Context, *mux.Router) {}

func (AppModuleBasic) RegisterGRPCGatewayRoutes(clientCtx client.Context, serveMux *runtime.ServeMux) {
	if err := types.RegisterQueryHandlerClient(
		context.Background(),
		serveMux,
		types.NewQueryClient(clientCtx),
	); err != nil {
		panic(err)
	}
}

func (AppModuleBasic) GetTxCmd() *cobra.Command    { return cli.GetTxCmd() }
func (AppModuleBasic) GetQueryCmd() *cobra.Command { return cli.GetQueryCmd() }

type AppModule struct {
	AppModuleBasic
	keeper         keeper.Keeper
	feegrantSource keeper.FeegrantAllowanceSource
}

func NewAppModule(
	moduleKeeper keeper.Keeper,
	feegrantSource keeper.FeegrantAllowanceSource,
) AppModule {
	if feegrantSource == nil {
		panic("pqcauth feegrant allowance source is required")
	}
	return AppModule{keeper: moduleKeeper, feegrantSource: feegrantSource}
}

func (AppModule) IsOnePerModuleType() {}
func (AppModule) IsAppModule()        {}

func (am AppModule) RegisterServices(configurator module.Configurator) {
	types.RegisterMsgServer(configurator.MsgServer(), keeper.NewMsgServer(am.keeper))
	types.RegisterQueryServer(configurator.QueryServer(), keeper.NewQueryServer(am.keeper))
	if err := configurator.RegisterMigration(
		types.ModuleName,
		1,
		func(ctx sdk.Context) error {
			return am.keeper.RebuildFeegrantIndex(ctx, am.feegrantSource)
		},
	); err != nil {
		panic(err)
	}
}

func (am AppModule) RegisterInvariants(registry sdk.InvariantRegistry) {
	keeper.RegisterInvariants(registry, am.keeper, am.feegrantSource)
}

func (am AppModule) InitGenesis(
	ctx sdk.Context,
	cdc codec.JSONCodec,
	bz json.RawMessage,
) []abci.ValidatorUpdate {
	var genesis types.GenesisState
	if err := cdc.UnmarshalJSON(bz, &genesis); err != nil {
		panic(err)
	}
	InitGenesis(ctx, am.keeper, genesis)
	if err := am.keeper.RebuildFeegrantIndex(ctx, am.feegrantSource); err != nil {
		panic(err)
	}
	return nil
}

func (am AppModule) ExportGenesis(ctx sdk.Context, cdc codec.JSONCodec) json.RawMessage {
	return cdc.MustMarshalJSON(ExportGenesis(ctx, am.keeper))
}

func (AppModule) ConsensusVersion() uint64 { return 2 }
func (am AppModule) BeginBlock(ctx context.Context) error {
	_, err := am.keeper.NormalizeParams(sdk.UnwrapSDKContext(ctx))
	return err
}
func (AppModule) GenerateGenesisState(*module.SimulationState) {}
func (AppModule) ProposalContents(module.SimulationState) []simtypes.WeightedProposalContent {
	return nil
}
func (AppModule) RandomizedParams(*rand.Rand) []simtypes.LegacyParamChange { return nil }
func (AppModule) RegisterStoreDecoder(simtypes.StoreDecoderRegistry)       {}
func (AppModule) WeightedOperations(module.SimulationState) []simtypes.WeightedOperation {
	return nil
}
