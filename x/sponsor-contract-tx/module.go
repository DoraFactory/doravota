package sponsor

import (
	"context"
	"encoding/json"
	"fmt"
	"math/rand"

	abci "github.com/cometbft/cometbft/abci/types"
	"github.com/cosmos/cosmos-sdk/client"
	"github.com/cosmos/cosmos-sdk/codec"
	cdctypes "github.com/cosmos/cosmos-sdk/codec/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/cosmos/cosmos-sdk/types/module"
	simtypes "github.com/cosmos/cosmos-sdk/types/simulation"
	"github.com/gorilla/mux"
	"github.com/grpc-ecosystem/grpc-gateway/runtime"
	"github.com/spf13/cobra"

	"github.com/DoraFactory/doravota/x/sponsor-contract-tx/client/cli"
	"github.com/DoraFactory/doravota/x/sponsor-contract-tx/keeper"
	sponsorsimulation "github.com/DoraFactory/doravota/x/sponsor-contract-tx/simulation"
	"github.com/DoraFactory/doravota/x/sponsor-contract-tx/types"
)

var (
	_ module.AppModule      = AppModule{}
	_ module.AppModuleBasic = AppModuleBasic{}
)

// AppModuleBasic implements the AppModuleBasic interface for the sponsor module
type AppModuleBasic struct {
	cdc codec.BinaryCodec
}

// Name returns the sponsor module's name
func (AppModuleBasic) Name() string {
	return types.ModuleName
}

// RegisterLegacyAminoCodec registers the sponsor module's types with the provided legacy amino codec
func (AppModuleBasic) RegisterLegacyAminoCodec(cdc *codec.LegacyAmino) {
	types.RegisterLegacyAminoCodec(cdc)
}

// RegisterInterfaces registers the sponsor module's interface types
func (AppModuleBasic) RegisterInterfaces(reg cdctypes.InterfaceRegistry) {
	types.RegisterInterfaces(reg)
}

// DefaultGenesis returns the sponsor module's default genesis state
func (AppModuleBasic) DefaultGenesis(cdc codec.JSONCodec) json.RawMessage {
	bz, err := json.Marshal(types.DefaultGenesisState())
	if err != nil {
		panic(err)
	}
	return bz
}

// ValidateGenesis performs genesis state validation for the sponsor module
func (AppModuleBasic) ValidateGenesis(cdc codec.JSONCodec, config client.TxEncodingConfig, bz json.RawMessage) error {
	var genState types.GenesisState
	if err := json.Unmarshal(bz, &genState); err != nil {
		return fmt.Errorf("failed to unmarshal %s genesis state: %w", types.ModuleName, err)
	}
	return types.ValidateGenesis(genState)
}

// RegisterRESTRoutes registers the sponsor module's REST service handlers
func (AppModuleBasic) RegisterRESTRoutes(clientCtx client.Context, rtr *mux.Router) {
	// REST routes are deprecated in favor of gRPC
}

// RegisterGRPCGatewayRoutes registers the gRPC Gateway routes for the sponsor module
func (AppModuleBasic) RegisterGRPCGatewayRoutes(clientCtx client.Context, mux *runtime.ServeMux) {
	err := types.RegisterQueryHandlerClient(context.Background(), mux, types.NewQueryClient(clientCtx))
	if err != nil {
		panic(err)
	}
}

// GetTxCmd returns the sponsor module's root tx command
func (a AppModuleBasic) GetTxCmd() *cobra.Command {
	return cli.GetTxCmd()
}

// GetQueryCmd returns the sponsor module's root query command
func (AppModuleBasic) GetQueryCmd() *cobra.Command {
	return cli.GetQueryCmd()
}

// AppModule implements the AppModule interface for the sponsor module
type AppModule struct {
	AppModuleBasic

	keeper     keeper.Keeper
	bankKeeper types.BankKeeper
	authKeeper types.AuthKeeper
}

func (AppModule) IsOnePerModuleType() {}
func (AppModule) IsAppModule()        {}

// NewAppModule creates a new AppModule object
func NewAppModule(
	cdc codec.Codec,
	keeper keeper.Keeper,
	bankKeeper types.BankKeeper,
	authKeeper types.AuthKeeper,
) AppModule {
	return AppModule{
		AppModuleBasic: AppModuleBasic{cdc: cdc},
		keeper:         keeper,
		bankKeeper:     bankKeeper,
		authKeeper:     authKeeper,
	}
}

// Name returns the sponsor module's name
func (am AppModule) Name() string {
	return am.AppModuleBasic.Name()
}

// RegisterServices registers the sponsor module's services
func (am AppModule) RegisterServices(cfg module.Configurator) {
	// Register message server with dependencies
	types.RegisterMsgServer(cfg.MsgServer(), keeper.NewMsgServerImplWithDeps(am.keeper, am.bankKeeper, am.authKeeper))

	// Register query server with bank keeper to enable balance queries
	types.RegisterQueryServer(cfg.QueryServer(), keeper.NewQueryServerWithDeps(am.keeper, am.bankKeeper))
}

// RegisterInvariants registers the sponsor module's invariants
func (am AppModule) RegisterInvariants(ir sdk.InvariantRegistry) {
	keeper.RegisterInvariants(ir, am.keeper)
}

// InitGenesis performs the sponsor module's genesis initialization
func (am AppModule) InitGenesis(ctx sdk.Context, cdc codec.JSONCodec, gs json.RawMessage) []abci.ValidatorUpdate {
	var genState types.GenesisState
	if err := json.Unmarshal(gs, &genState); err != nil {
		panic(err)
	}

	InitGenesis(ctx, am.keeper, genState)

	return []abci.ValidatorUpdate{}
}

// ExportGenesis returns the sponsor module's exported genesis state
func (am AppModule) ExportGenesis(ctx sdk.Context, cdc codec.JSONCodec) json.RawMessage {
	genState := ExportGenesis(ctx, am.keeper)
	bz, err := json.Marshal(genState)
	if err != nil {
		panic(err)
	}
	return bz
}

// ConsensusVersion implements ConsensusVersion
func (AppModule) ConsensusVersion() uint64 { return 1 }

// BeginBlock executes all ABCI BeginBlock logic respective to the sponsor module
func (am AppModule) BeginBlock(goCtx context.Context) error {
	ctx := sdk.UnwrapSDKContext(goCtx)
	// Opportunistic GC: inspect a bounded number of expiry-index entries per block.
	params := am.keeper.GetParams(ctx)
	n := params.TicketGcPerBlock
	if n == 0 {
		return nil
	}
	if n > types.MaxTicketGCPerBlock {
		n = types.MaxTicketGCPerBlock
	}
	am.keeper.GarbageCollectByExpiry(ctx, int(n))
	return nil
}

// EndBlock executes all ABCI EndBlock logic respective to the sponsor module
func (am AppModule) EndBlock(context.Context) error {
	return nil
}

// GenerateGenesisState creates a randomized GenState of the sponsor module
func (AppModule) GenerateGenesisState(simState *module.SimulationState) {
	sponsorsimulation.RandomizedGenState(simState)
}

// ProposalContents returns the sponsor module's proposal contents
func (am AppModule) ProposalContents(simState module.SimulationState) []simtypes.WeightedProposalContent {
	return sponsorsimulation.NewAppModuleSimulation(
		am.keeper,
		am.authKeeper,
		am.bankKeeper,
		am.keeper.WasmKeeper(),
	).ProposalContents(simState)
}

// RandomizedParams creates randomized sponsor param changes for the simulator
func (am AppModule) RandomizedParams(r *rand.Rand) []simtypes.LegacyParamChange {
	return sponsorsimulation.ParamChanges(r)
}

// RegisterStoreDecoder registers a decoder for sponsor module's types
func (am AppModule) RegisterStoreDecoder(sdr simtypes.StoreDecoderRegistry) {
	sdr[types.StoreKey] = sponsorsimulation.NewDecodeStore(am.keeper.Cdc())
}

// WeightedOperations returns the sponsor module's weighted operations
func (am AppModule) WeightedOperations(simState module.SimulationState) []simtypes.WeightedOperation {
	return sponsorsimulation.WeightedOperations(
		simState.AppParams,
		simState.Cdc,
		am.keeper,
		am.authKeeper,
		am.bankKeeper,
		am.keeper.WasmKeeper(),
	)
}
