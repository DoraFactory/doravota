package app

import (
	"context"
	autocliv1 "cosmossdk.io/api/cosmos/autocli/v1"
	reflectionv1 "cosmossdk.io/api/cosmos/reflection/v1"
	"cosmossdk.io/client/v2/autocli"
	"cosmossdk.io/core/appmodule"
	"cosmossdk.io/log/v2"
	"encoding/json"
	"fmt"
	"github.com/DoraFactory/doravota/app/upgrades/sdk055"
	"github.com/DoraFactory/doravota/app/wasmarchive"
	pqcauth "github.com/DoraFactory/doravota/x/pqcauth"
	pqcauthante "github.com/DoraFactory/doravota/x/pqcauth/ante"
	pqcauthkeeper "github.com/DoraFactory/doravota/x/pqcauth/keeper"
	pqcauthtypes "github.com/DoraFactory/doravota/x/pqcauth/types"
	abci "github.com/cometbft/cometbft/abci/types"
	dbm "github.com/cosmos/cosmos-db"
	"github.com/cosmos/cosmos-sdk/baseapp"
	"github.com/cosmos/cosmos-sdk/client"
	"github.com/cosmos/cosmos-sdk/client/grpc/cmtservice"
	nodeservice "github.com/cosmos/cosmos-sdk/client/grpc/node"
	"github.com/cosmos/cosmos-sdk/codec"
	"github.com/cosmos/cosmos-sdk/codec/types"
	"github.com/cosmos/cosmos-sdk/runtime"
	runtimeservices "github.com/cosmos/cosmos-sdk/runtime/services"
	"github.com/cosmos/cosmos-sdk/server"
	"github.com/cosmos/cosmos-sdk/server/api"
	"github.com/cosmos/cosmos-sdk/server/config"
	servertypes "github.com/cosmos/cosmos-sdk/server/types"
	storetypes "github.com/cosmos/cosmos-sdk/store/v2/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/cosmos/cosmos-sdk/types/module"
	"github.com/cosmos/cosmos-sdk/version"
	"github.com/cosmos/cosmos-sdk/x/auth"
	"github.com/cosmos/cosmos-sdk/x/auth/ante"
	authcodec "github.com/cosmos/cosmos-sdk/x/auth/codec"
	authkeeper "github.com/cosmos/cosmos-sdk/x/auth/keeper"
	"github.com/cosmos/cosmos-sdk/x/auth/posthandler"
	authsims "github.com/cosmos/cosmos-sdk/x/auth/simulation"
	authtx "github.com/cosmos/cosmos-sdk/x/auth/tx"
	authtypes "github.com/cosmos/cosmos-sdk/x/auth/types"
	"github.com/cosmos/cosmos-sdk/x/auth/vesting"
	vestingtypes "github.com/cosmos/cosmos-sdk/x/auth/vesting/types"
	"github.com/cosmos/cosmos-sdk/x/authz"
	authzkeeper "github.com/cosmos/cosmos-sdk/x/authz/keeper"
	authzmodule "github.com/cosmos/cosmos-sdk/x/authz/module"
	"github.com/cosmos/cosmos-sdk/x/bank"
	bankkeeper "github.com/cosmos/cosmos-sdk/x/bank/keeper"
	banktypes "github.com/cosmos/cosmos-sdk/x/bank/types"
	"github.com/cosmos/cosmos-sdk/x/consensus"
	consensusparamkeeper "github.com/cosmos/cosmos-sdk/x/consensus/keeper"
	consensusparamtypes "github.com/cosmos/cosmos-sdk/x/consensus/types"
	distr "github.com/cosmos/cosmos-sdk/x/distribution"
	distrkeeper "github.com/cosmos/cosmos-sdk/x/distribution/keeper"
	distrtypes "github.com/cosmos/cosmos-sdk/x/distribution/types"
	"github.com/cosmos/cosmos-sdk/x/evidence"
	evidencekeeper "github.com/cosmos/cosmos-sdk/x/evidence/keeper"
	evidencetypes "github.com/cosmos/cosmos-sdk/x/evidence/types"
	"github.com/cosmos/cosmos-sdk/x/feegrant"
	feegrantkeeper "github.com/cosmos/cosmos-sdk/x/feegrant/keeper"
	"github.com/cosmos/cosmos-sdk/x/genutil"
	genutiltypes "github.com/cosmos/cosmos-sdk/x/genutil/types"
	"github.com/cosmos/cosmos-sdk/x/gov"
	govclient "github.com/cosmos/cosmos-sdk/x/gov/client"
	govkeeper "github.com/cosmos/cosmos-sdk/x/gov/keeper"
	govtypes "github.com/cosmos/cosmos-sdk/x/gov/types"
	govv1beta1 "github.com/cosmos/cosmos-sdk/x/gov/types/v1beta1"
	"github.com/cosmos/cosmos-sdk/x/mint"
	mintkeeper "github.com/cosmos/cosmos-sdk/x/mint/keeper"
	minttypes "github.com/cosmos/cosmos-sdk/x/mint/types"
	paramproposal "github.com/cosmos/cosmos-sdk/x/params/types/proposal"
	"github.com/cosmos/cosmos-sdk/x/slashing"
	slashingkeeper "github.com/cosmos/cosmos-sdk/x/slashing/keeper"
	slashingtypes "github.com/cosmos/cosmos-sdk/x/slashing/types"
	"github.com/cosmos/cosmos-sdk/x/staking"
	stakingkeeper "github.com/cosmos/cosmos-sdk/x/staking/keeper"
	stakingtypes "github.com/cosmos/cosmos-sdk/x/staking/types"
	"github.com/cosmos/cosmos-sdk/x/upgrade"
	upgradekeeper "github.com/cosmos/cosmos-sdk/x/upgrade/keeper"
	upgradetypes "github.com/cosmos/cosmos-sdk/x/upgrade/types"
	"io"
	"maps"
	"os"
	"path/filepath"

	ica "github.com/cosmos/ibc-go/v11/modules/apps/27-interchain-accounts"
	icacontroller "github.com/cosmos/ibc-go/v11/modules/apps/27-interchain-accounts/controller"
	icacontrollerkeeper "github.com/cosmos/ibc-go/v11/modules/apps/27-interchain-accounts/controller/keeper"
	icacontrollertypes "github.com/cosmos/ibc-go/v11/modules/apps/27-interchain-accounts/controller/types"
	icahost "github.com/cosmos/ibc-go/v11/modules/apps/27-interchain-accounts/host"
	icahostkeeper "github.com/cosmos/ibc-go/v11/modules/apps/27-interchain-accounts/host/keeper"
	icahosttypes "github.com/cosmos/ibc-go/v11/modules/apps/27-interchain-accounts/host/types"
	icatypes "github.com/cosmos/ibc-go/v11/modules/apps/27-interchain-accounts/types"
	"github.com/cosmos/ibc-go/v11/modules/apps/transfer"
	ibctransferkeeper "github.com/cosmos/ibc-go/v11/modules/apps/transfer/keeper"
	ibctransfertypes "github.com/cosmos/ibc-go/v11/modules/apps/transfer/types"
	ibc "github.com/cosmos/ibc-go/v11/modules/core"
	porttypes "github.com/cosmos/ibc-go/v11/modules/core/05-port/types"
	ibcapi "github.com/cosmos/ibc-go/v11/modules/core/api"
	ibcexported "github.com/cosmos/ibc-go/v11/modules/core/exported"
	ibckeeper "github.com/cosmos/ibc-go/v11/modules/core/keeper"
	solomachine "github.com/cosmos/ibc-go/v11/modules/light-clients/06-solomachine"
	ibctm "github.com/cosmos/ibc-go/v11/modules/light-clients/07-tendermint"

	// this line is used by starport scaffolding # stargate/app/moduleImport

	appparams "github.com/DoraFactory/doravota/app/params"
	"github.com/DoraFactory/doravota/docs"

	votatypes "github.com/DoraFactory/doravota/types"
	// crypto "github.com/cometbft/cometbft/proto/tendermint/crypto"
)

const (
	AccountAddressPrefix = "dora"
	Name                 = "dora"
)

// These constants are derived from the above variables.
// These are the ones we will want to use in the code, based on
// any overrides above
var (

	// Bech32PrefixAccAddr defines the Bech32 prefix of an account's address
	Bech32PrefixAccAddr = AccountAddressPrefix
	// Bech32PrefixAccPub defines the Bech32 prefix of an account's public key
	Bech32PrefixAccPub = AccountAddressPrefix + sdk.PrefixPublic
	// Bech32PrefixValAddr defines the Bech32 prefix of a validator's operator address
	Bech32PrefixValAddr = AccountAddressPrefix + sdk.PrefixValidator + sdk.PrefixOperator
	// Bech32PrefixValPub defines the Bech32 prefix of a validator's operator public key
	Bech32PrefixValPub = AccountAddressPrefix + sdk.PrefixValidator + sdk.PrefixOperator + sdk.PrefixPublic
	// Bech32PrefixConsAddr defines the Bech32 prefix of a consensus node address
	Bech32PrefixConsAddr = AccountAddressPrefix + sdk.PrefixValidator + sdk.PrefixConsensus
	// Bech32PrefixConsPub defines the Bech32 prefix of a consensus node public key
	Bech32PrefixConsPub = AccountAddressPrefix + sdk.PrefixValidator + sdk.PrefixConsensus + sdk.PrefixPublic
)

func getGovProposalHandlers() []govclient.ProposalHandler { return nil }

var (
	// DefaultNodeHome default home directories for the application daemon
	DefaultNodeHome string

	// ModuleBasics defines the module BasicManager is in charge of setting up basic,
	// non-dependant module elements, such as codec registration
	// and genesis verification.
	ModuleBasics = module.NewBasicManager(
		auth.AppModuleBasic{},
		authzAppModuleBasic{},
		genutil.NewAppModuleBasic(genutiltypes.DefaultMessageValidator),
		bankAppModuleBasic{},
		stakingAppModuleBasic{},
		mint.AppModuleBasic{},
		distributionAppModuleBasic{},
		gov.NewAppModuleBasic(getGovProposalHandlers()),
		slashing.AppModuleBasic{},
		feegrantAppModuleBasic{},
		ibc.AppModuleBasic{},
		ibctm.AppModuleBasic{},
		solomachine.AppModuleBasic{},
		upgradeAppModuleBasic{},
		evidence.AppModuleBasic{},
		transfer.AppModuleBasic{},
		ica.AppModuleBasic{},
		vestingAppModuleBasic{},
		consensus.AppModuleBasic{},
		pqcauth.AppModuleBasic{},
	)

	// module account permissions
	maccPerms = map[string][]string{
		authtypes.FeeCollectorName:          nil,
		distrtypes.ModuleName:               nil,
		icatypes.ModuleName:                 nil,
		minttypes.ModuleName:                {authtypes.Minter},
		stakingtypes.BondedPoolName:         {authtypes.Burner, authtypes.Staking},
		stakingtypes.KeyRotationFeePoolName: {authtypes.Burner},
		stakingtypes.NotBondedPoolName:      {authtypes.Burner, authtypes.Staking},
		govtypes.ModuleName:                 {authtypes.Burner},
		ibctransfertypes.ModuleName:         {authtypes.Minter, authtypes.Burner},
	}
)

var (
	_ runtime.AppI            = (*App)(nil)
	_ servertypes.Application = (*App)(nil)
)

func init() {
	userHomeDir, err := os.UserHomeDir()
	if err != nil {
		panic(err)
	}

	DefaultNodeHome = filepath.Join(userHomeDir, "."+Name)

	sdk.DefaultPowerReduction = votatypes.DefaultPowerReduction
}

// App extends an ABCI application, but with most of its parameters exported.
// They are exported for convenience in creating helper functions, as object
// capabilities aren't needed for testing.
type App struct {
	*baseapp.BaseApp

	cdc               *codec.LegacyAmino
	appCodec          codec.Codec
	interfaceRegistry types.InterfaceRegistry
	txConfig          client.TxConfig

	invCheckPeriod uint

	// keys to access the substores
	keys  map[string]*storetypes.KVStoreKey
	tkeys map[string]*storetypes.TransientStoreKey

	// keepers
	AccountKeeper         authkeeper.AccountKeeper
	AuthzKeeper           authzkeeper.Keeper
	BankKeeper            bankkeeper.Keeper
	StakingKeeper         *stakingkeeper.Keeper
	SlashingKeeper        slashingkeeper.Keeper
	MintKeeper            mintkeeper.Keeper
	DistrKeeper           distrkeeper.Keeper
	GovKeeper             govkeeper.Keeper
	UpgradeKeeper         *upgradekeeper.Keeper
	ConsensusParamsKeeper consensusparamkeeper.Keeper
	EvidenceKeeper        evidencekeeper.Keeper
	FeeGrantKeeper        feegrantkeeper.Keeper
	PQCAuthKeeper         pqcauthkeeper.Keeper

	IBCKeeper           *ibckeeper.Keeper // IBC Keeper must be a pointer in the app, so we can SetRouter on it correctly
	ICAControllerKeeper *icacontrollerkeeper.Keeper
	ICAHostKeeper       *icahostkeeper.Keeper
	TransferKeeper      *ibctransferkeeper.Keeper

	// this line is used by starport scaffolding # stargate/app/keeperDeclaration

	// mm is the module manager
	mm *module.Manager

	// sm is the simulation manager
	sm           *module.SimulationManager
	configurator module.Configurator
}

// New returns a reference to an initialized blockchain app
func New(
	logger log.Logger,
	db dbm.DB,
	traceStore io.Writer,
	loadLatest bool,
	skipUpgradeHeights map[int64]bool,
	homePath string,
	invCheckPeriod uint,
	encodingConfig appparams.EncodingConfig,
	appOpts servertypes.AppOptions,
	baseAppOptions ...func(*baseapp.BaseApp),
) *App {
	if err := sdk055.ValidateBoundary(logger, db, homePath, skipUpgradeHeights); err != nil {
		panic(fmt.Errorf("SDK 0.55 source boundary: %w", err))
	}
	if err := wasmarchive.ValidateBoundaryWithModules(logger, db, homePath, skipUpgradeHeights, map[string]uint64{pqcauthtypes.ModuleName: (pqcauth.AppModule{}).ConsensusVersion()}); err != nil {
		panic(fmt.Errorf("Wasm retirement source boundary: %w", err))
	}
	appCodec := encodingConfig.Marshaler
	cdc := encodingConfig.Amino
	interfaceRegistry := encodingConfig.InterfaceRegistry
	txConfig := encodingConfig.TxConfig

	bApp := baseapp.NewBaseApp(
		Name,
		logger,
		db,
		pqcauthante.CanonicalPQCAuthTxDecoder(encodingConfig.TxConfig.TxDecoder()),
		baseAppOptions...,
	)
	// Store v2 removed commit-store tracing; preserve the local constructor API.
	_ = traceStore
	// Preserve sequential execution with the legacy block gas meter.
	bApp.SetDisableBlockGasMeter(false)
	bApp.SetVersion(version.Version)
	bApp.SetInterfaceRegistry(interfaceRegistry)
	bApp.SetTxEncoder(txConfig.TxEncoder())

	keys := storetypes.NewKVStoreKeys(
		authtypes.StoreKey, banktypes.StoreKey, stakingtypes.StoreKey,
		minttypes.StoreKey, distrtypes.StoreKey, slashingtypes.StoreKey,
		govtypes.StoreKey, consensusparamtypes.StoreKey, upgradetypes.StoreKey, feegrant.StoreKey,
		evidencetypes.StoreKey,
		authzkeeper.StoreKey,
		// non sdk store keys
		ibcexported.StoreKey, ibctransfertypes.StoreKey,
		wasmarchive.StoreKey, icahosttypes.StoreKey,
		icacontrollertypes.StoreKey, pqcauthtypes.StoreKey,
	)
	tkeys := storetypes.NewTransientStoreKeys()
	if err := bApp.RegisterStreamingServices(appOpts, keys); err != nil {
		panic(fmt.Errorf("register streaming services: %w", err))
	}

	app := &App{
		BaseApp:           bApp,
		cdc:               cdc,
		appCodec:          appCodec,
		interfaceRegistry: interfaceRegistry,
		txConfig:          encodingConfig.TxConfig,
		invCheckPeriod:    invCheckPeriod,
		keys:              keys,
		tkeys:             tkeys,
	}

	app.ConsensusParamsKeeper = consensusparamkeeper.NewKeeper(
		appCodec,
		runtime.NewKVStoreService(keys[consensusparamtypes.StoreKey]),
		authtypes.NewModuleAddress(govtypes.ModuleName).String(),
		runtime.EventService{},
	)
	bApp.SetParamStore(app.ConsensusParamsKeeper.ParamsStore)

	// add keepers
	app.AccountKeeper = authkeeper.NewAccountKeeper(
		appCodec,
		runtime.NewKVStoreService(keys[authtypes.StoreKey]),
		authtypes.ProtoBaseAccount,
		maccPerms,
		authcodec.NewBech32Codec(sdk.GetConfig().GetBech32AccountAddrPrefix()),
		sdk.GetConfig().GetBech32AccountAddrPrefix(),
		authtypes.NewModuleAddress(govtypes.ModuleName).String(),
	)

	app.AuthzKeeper = authzkeeper.NewKeeper(
		runtime.NewKVStoreService(keys[authzkeeper.StoreKey]),
		appCodec,
		app.MsgServiceRouter(),
		app.AccountKeeper,
	)

	app.BankKeeper = bankkeeper.NewBaseKeeper(
		appCodec,
		runtime.NewKVStoreService(keys[banktypes.StoreKey]),
		app.AccountKeeper,
		app.BlockedModuleAccountAddrs(),
		authtypes.NewModuleAddress(govtypes.ModuleName).String(),
		logger,
	)

	app.StakingKeeper = stakingkeeper.NewKeeper(
		appCodec,
		runtime.NewKVStoreService(keys[stakingtypes.StoreKey]),
		app.AccountKeeper,
		app.BankKeeper,
		authtypes.NewModuleAddress(govtypes.ModuleName).String(),
		authcodec.NewBech32Codec(sdk.GetConfig().GetBech32ValidatorAddrPrefix()),
		authcodec.NewBech32Codec(sdk.GetConfig().GetBech32ConsensusAddrPrefix()),
	)

	app.FeeGrantKeeper = feegrantkeeper.NewKeeper(
		appCodec,
		runtime.NewKVStoreService(keys[feegrant.StoreKey]),
		app.AccountKeeper,
	)

	app.MintKeeper = mintkeeper.NewKeeper(
		appCodec,
		runtime.NewKVStoreService(keys[minttypes.StoreKey]),
		app.StakingKeeper,
		app.AccountKeeper,
		app.BankKeeper,
		authtypes.FeeCollectorName,
		authtypes.NewModuleAddress(govtypes.ModuleName).String(),
	)

	app.DistrKeeper = distrkeeper.NewKeeper(
		appCodec,
		runtime.NewKVStoreService(keys[distrtypes.StoreKey]),
		app.AccountKeeper,
		app.BankKeeper,
		app.StakingKeeper,
		authtypes.FeeCollectorName,
		authtypes.NewModuleAddress(govtypes.ModuleName).String(),
	)

	app.SlashingKeeper = slashingkeeper.NewKeeper(
		appCodec,
		cdc,
		runtime.NewKVStoreService(keys[slashingtypes.StoreKey]),
		app.StakingKeeper,
		authtypes.NewModuleAddress(govtypes.ModuleName).String(),
	)

	app.UpgradeKeeper = upgradekeeper.NewKeeper(
		skipUpgradeHeights,
		runtime.NewKVStoreService(keys[upgradetypes.StoreKey]),
		appCodec,
		homePath,
		app.BaseApp,
		authtypes.NewModuleAddress(govtypes.ModuleName).String(),
	)

	// ... other modules keepers

	// Create IBC Keeper
	app.IBCKeeper = ibckeeper.NewKeeper(
		appCodec, runtime.NewKVStoreService(keys[ibcexported.StoreKey]),
		app.UpgradeKeeper,
		authtypes.NewModuleAddress(govtypes.ModuleName).String(),
	)

	// Register the proposal types
	// Deprecated: Avoid adding new handlers, instead use the new proposal flow
	// by granting the governance module the right to execute the message.
	// See: https://docs.cosmos.network/main/modules/gov#proposal-messages
	govRouter := govv1beta1.NewRouter()
	govRouter.AddRoute(govtypes.RouterKey, govv1beta1.ProposalHandler)
	// Decode historical proposals but refuse execution against removed legacy subspaces.
	govRouter.AddRoute(paramproposal.RouterKey, func(sdk.Context, govv1beta1.Content) error {
		return fmt.Errorf("legacy parameter-change proposals are no longer executable; use module MsgUpdateParams")
	})

	govConfig := govtypes.DefaultConfig()
	/*
		Example of setting gov params:
		govConfig.MaxMetadataLen = 10000
	*/
	govKeeper := govkeeper.NewKeeper(
		appCodec,
		runtime.NewKVStoreService(keys[govtypes.StoreKey]),
		app.AccountKeeper,
		app.BankKeeper,
		app.DistrKeeper,
		app.MsgServiceRouter(),
		govConfig,
		authtypes.NewModuleAddress(govtypes.ModuleName).String(),
		govkeeper.NewDefaultCalculateVoteResultsAndVotingPower(app.StakingKeeper),
	)

	app.GovKeeper = *govKeeper.SetHooks(
		govtypes.NewMultiGovHooks(
		// register the governance hooks
		),
	)

	// Create evidence Keeper for to register the IBC light client misbehaviour evidence route
	evidenceKeeper := evidencekeeper.NewKeeper(
		appCodec,
		runtime.NewKVStoreService(keys[evidencetypes.StoreKey]),
		app.StakingKeeper,
		app.SlashingKeeper,
		app.AccountKeeper.AddressCodec(),
		runtime.ProvideCometInfoService(),
	)
	// If evidence needs to be handled for the app, set routes in router here and seal
	app.EvidenceKeeper = *evidenceKeeper

	// Create Transfer Keepers
	app.TransferKeeper = ibctransferkeeper.NewKeeper(
		appCodec,
		app.AccountKeeper.AddressCodec(),
		runtime.NewKVStoreService(keys[ibctransfertypes.StoreKey]),
		app.IBCKeeper.ChannelKeeper,
		app.MsgServiceRouter(),
		app.AccountKeeper,
		app.BankKeeper,
		authtypes.NewModuleAddress(govtypes.ModuleName).String(),
	)

	app.ICAHostKeeper = icahostkeeper.NewKeeper(
		appCodec,
		runtime.NewKVStoreService(keys[icahosttypes.StoreKey]),
		app.IBCKeeper.ChannelKeeper,
		app.AccountKeeper,
		app.MsgServiceRouter(),
		app.GRPCQueryRouter(),
		authtypes.NewModuleAddress(govtypes.ModuleName).String(),
	)
	app.ICAControllerKeeper = icacontrollerkeeper.NewKeeper(
		appCodec,
		runtime.NewKVStoreService(keys[icacontrollertypes.StoreKey]),
		app.IBCKeeper.ChannelKeeper,
		app.MsgServiceRouter(),
		authtypes.NewModuleAddress(govtypes.ModuleName).String(),
	)

	// Set legacy router for backwards compatibility with gov v1beta1
	app.GovKeeper.SetLegacyRouter(govRouter)

	// Create Interchain Accounts Stack.
	var icaControllerStack porttypes.IBCModule
	icaControllerModule := icacontroller.NewIBCMiddleware(app.ICAControllerKeeper)
	icaControllerModule.SetICS4Wrapper(app.IBCKeeper.ChannelKeeper)
	icaControllerStack = icaControllerModule

	// Create Transfer Stack.
	var transferStack porttypes.IBCModule
	transferModule := transfer.NewIBCModule(app.TransferKeeper)
	transferModule.SetICS4Wrapper(app.IBCKeeper.ChannelKeeper)
	transferStack = transferModule

	icaHostStack := icahost.NewIBCModule(app.ICAHostKeeper)
	icaHostStack.SetICS4Wrapper(app.IBCKeeper.ChannelKeeper)
	ibcRouter := porttypes.NewRouter().
		AddRoute(ibctransfertypes.ModuleName, transferStack).
		AddRoute(icacontrollertypes.SubModuleName, icaControllerStack).
		AddRoute(icahosttypes.SubModuleName, icaHostStack)
	app.IBCKeeper.SetRouter(ibcRouter)

	// IBC v2 is an optional feature, outside the 0.4.4 migration scope.
	// Keep a non-nil empty router without enabling new transfer/contract ports.
	app.IBCKeeper.SetRouterV2(ibcapi.NewRouter())

	clientKeeper := app.IBCKeeper.ClientKeeper
	storeProvider := clientKeeper.GetStoreProvider()
	tmLightClientModule := ibctm.NewLightClientModule(appCodec, storeProvider)
	clientKeeper.AddRoute(ibctm.ModuleName, &tmLightClientModule)
	soloLightClientModule := solomachine.NewLightClientModule(appCodec, storeProvider)
	clientKeeper.AddRoute(solomachine.ModuleName, &soloLightClientModule)

	/**** Module Hooks ****/

	// register hooks after all modules have been initialized

	app.StakingKeeper.SetHooks(
		stakingtypes.NewMultiStakingHooks(
			// insert staking hooks receivers here
			app.DistrKeeper.Hooks(),
			app.SlashingKeeper.Hooks(),
		),
	)

	/**** Module Options ****/

	// NOTE: we may consider parsing `appOpts` inside module constructors. For the moment
	// we prefer to be more strict in what arguments the modules expect.

	// NOTE: Any module instantiated in the module manager that is later modified
	// must be passed by reference here.

	app.PQCAuthKeeper = pqcauthkeeper.NewKeeper(appCodec, keys[pqcauthtypes.StoreKey], authtypes.NewModuleAddress(govtypes.ModuleName).String(), app.AccountKeeper)
	// NOTE: add upgrade(this must be called before `app.LoadLatestVersion()`)
	app.setupUpgradeHandlers()

	app.mm = module.NewManager(
		genutil.NewAppModule(
			app.AccountKeeper,
			app.StakingKeeper,
			app,
			encodingConfig.TxConfig,
		),
		auth.NewAppModule(appCodec, app.AccountKeeper, authsims.RandomGenesisAccounts),
		authzmodule.NewAppModule(appCodec, app.AuthzKeeper, app.AccountKeeper, app.BankKeeper, app.interfaceRegistry),
		vesting.NewAppModule(app.AccountKeeper, app.BankKeeper),
		bank.NewAppModule(appCodec, app.BankKeeper, app.AccountKeeper),
		newPQCAwareFeegrantAppModule(appCodec, app.AccountKeeper, app.BankKeeper, app.FeeGrantKeeper, app.interfaceRegistry, app.PQCAuthKeeper),
		gov.NewAppModule(appCodec, &app.GovKeeper, app.AccountKeeper, app.BankKeeper),
		mint.NewAppModule(appCodec, app.MintKeeper, app.AccountKeeper, nil),
		slashing.NewAppModule(appCodec, app.SlashingKeeper, app.AccountKeeper, app.BankKeeper, app.StakingKeeper, app.interfaceRegistry),
		distr.NewAppModule(appCodec, app.DistrKeeper, app.AccountKeeper, app.BankKeeper, app.StakingKeeper),
		staking.NewAppModule(appCodec, app.StakingKeeper, app.AccountKeeper, app.BankKeeper),
		upgrade.NewAppModule(app.UpgradeKeeper, app.AccountKeeper.AddressCodec()),
		evidence.NewAppModule(app.EvidenceKeeper),
		consensus.NewAppModule(appCodec, app.ConsensusParamsKeeper),
		ibc.NewAppModule(app.IBCKeeper),
		transfer.NewAppModule(app.TransferKeeper),
		ica.NewAppModule(app.ICAControllerKeeper, app.ICAHostKeeper),
		ibctm.NewAppModule(tmLightClientModule),
		solomachine.NewAppModule(soloLightClientModule),
		pqcauth.NewAppModule(app.PQCAuthKeeper, app.FeeGrantKeeper),
	)

	// x/upgrade executes scheduled upgrade plans in PreBlock. Register it
	// explicitly as required by SDK v0.53.
	app.mm.SetOrderPreBlockers(
		upgradetypes.ModuleName,
		authtypes.ModuleName,
	)

	// During begin block slashing happens after distr.BeginBlocker so that
	// there is nothing left over in the validator fee pool, so as to keep the
	// CanWithdrawInvariant invariant.
	// NOTE: staking module is required if HistoricalEntries param > 0
	app.mm.SetOrderBeginBlockers(
		minttypes.ModuleName, distrtypes.ModuleName, slashingtypes.ModuleName,
		evidencetypes.ModuleName, stakingtypes.ModuleName,
		authtypes.ModuleName, banktypes.ModuleName, govtypes.ModuleName, genutiltypes.ModuleName,
		authz.ModuleName, feegrant.ModuleName, pqcauthtypes.ModuleName,
		vestingtypes.ModuleName, consensusparamtypes.ModuleName,
		// additional non simd modules
		ibctransfertypes.ModuleName,
		ibcexported.ModuleName,
		icatypes.ModuleName,
	)

	app.mm.SetOrderEndBlockers(
		banktypes.ModuleName,
		govtypes.ModuleName, stakingtypes.ModuleName,
		authtypes.ModuleName, distrtypes.ModuleName,
		slashingtypes.ModuleName, minttypes.ModuleName,
		genutiltypes.ModuleName, evidencetypes.ModuleName, authz.ModuleName,
		feegrant.ModuleName, pqcauthtypes.ModuleName,
		upgradetypes.ModuleName, vestingtypes.ModuleName, consensusparamtypes.ModuleName,
		// additional non simd modules
		ibctransfertypes.ModuleName,
		ibcexported.ModuleName,
		icatypes.ModuleName,
	)

	// NOTE: The genutils module must occur after staking so that pools are
	// properly initialized with tokens from genesis accounts.
	genesisModuleOrder := []string{
		authtypes.ModuleName, banktypes.ModuleName,
		distrtypes.ModuleName, stakingtypes.ModuleName, slashingtypes.ModuleName, govtypes.ModuleName,
		minttypes.ModuleName, genutiltypes.ModuleName, evidencetypes.ModuleName, authz.ModuleName,
		feegrant.ModuleName, pqcauthtypes.ModuleName, upgradetypes.ModuleName,
		vestingtypes.ModuleName, consensusparamtypes.ModuleName,
		// additional non simd modules
		ibctransfertypes.ModuleName,
		ibcexported.ModuleName,
		icatypes.ModuleName,
	}
	app.mm.SetOrderInitGenesis(genesisModuleOrder...)
	app.mm.SetOrderExportGenesis(genesisModuleOrder...)

	// Uncomment if you want to set a custom migration order here.
	// app.mm.SetOrderMigrations(custom order)

	app.configurator = module.NewConfigurator(app.appCodec, app.MsgServiceRouter(), app.GRPCQueryRouter())
	app.mm.RegisterServices(app.configurator)
	wasmarchive.RegisterQueryServer(app.GRPCQueryRouter(), wasmarchive.NewServer(keys[wasmarchive.StoreKey]))

	autocliv1.RegisterQueryServer(app.GRPCQueryRouter(), runtimeservices.NewAutoCLIQueryService(app.mm.Modules))
	reflectionSvc, err := runtimeservices.NewReflectionService()
	if err != nil {
		panic(err)
	}
	reflectionv1.RegisterReflectionServiceServer(app.GRPCQueryRouter(), reflectionSvc)

	// create the simulation manager and define the order of the modules for deterministic simulations
	overrideModules := map[string]module.AppModuleSimulation{
		authtypes.ModuleName: auth.NewAppModule(app.appCodec, app.AccountKeeper, authsims.RandomGenesisAccounts),
	}
	app.sm = module.NewSimulationManagerFromAppModules(app.mm.Modules, overrideModules)
	app.sm.RegisterStoreDecoders()

	// initialize stores
	app.MountKVStores(keys)
	if err := sdk055.MountRetiringStores(app.CommitMultiStore(), db, logger); err != nil {
		panic(err)
	}
	app.MountTransientStores(tkeys)

	// initialize BaseApp
	app.setAnteHandler(encodingConfig.TxConfig)
	app.setProposalHandlers(encodingConfig.TxConfig)
	app.SetInitChainer(app.InitChainer)
	app.SetPreBlocker(app.PreBlocker)
	app.SetBeginBlocker(app.BeginBlocker)
	app.SetEndBlocker(app.EndBlocker)

	app.setPostHandler()

	if loadLatest {
		if err := app.LoadLatestVersion(); err != nil {
			panic(fmt.Errorf("load latest version: %w", err))
		}
	}

	return app
}

func (app *App) setAnteHandler(txConfig client.TxConfig) {
	anteHandler, err := NewAnteHandler(
		HandlerOptions{
			HandlerOptions: ante.HandlerOptions{
				AccountKeeper:   app.AccountKeeper,
				BankKeeper:      app.BankKeeper,
				SignModeHandler: txConfig.SignModeHandler(),
				FeegrantKeeper:  app.FeeGrantKeeper,
				SigGasConsumer:  pqcauthante.PQCSafeSigVerificationGasConsumer,
			},
			IBCKeeper:               app.IBCKeeper,
			PQCAuthKeeper:           app.PQCAuthKeeper,
			AuthzGrantReader:        app.AuthzKeeper,
			FeegrantAllowanceReader: app.FeeGrantKeeper,
			AppCodec:                app.appCodec,
		},
	)
	if err != nil {
		panic(fmt.Errorf("failed to create AnteHandler: %s", err))
	}
	app.SetAnteHandler(anteHandler)
}

func (app *App) setPostHandler() {
	postHandler, err := posthandler.NewPostHandler(
		posthandler.HandlerOptions{},
	)
	if err != nil {
		panic(err)
	}

	app.SetPostHandler(postHandler)
}

// Name returns the name of the App
func (app *App) Name() string { return app.BaseApp.Name() }

// PreBlocker runs module pre-block processing.
func (app *App) PreBlocker(ctx sdk.Context, _ *abci.RequestFinalizeBlock) (*sdk.ResponsePreBlock, error) {
	versions, err := app.UpgradeKeeper.GetModuleVersionMap(ctx)
	if err != nil {
		return nil, err
	}
	if versions[wasmarchive.GenesisKey] != 1 {
		plan, err := app.UpgradeKeeper.GetUpgradePlan(ctx)
		if err != nil || plan.Name != wasmarchive.UpgradeName || plan.Height != ctx.BlockHeight() {
			return nil, fmt.Errorf("archive activation is required before block execution")
		}
	}
	if versions[pqcauthtypes.ModuleName] == 0 {
		plan, err := app.UpgradeKeeper.GetUpgradePlan(ctx)
		if err != nil || plan.Name != PQCAuthUpgradeName || plan.Height != ctx.BlockHeight() {
			return nil, fmt.Errorf("PQC Auth activation is required before block execution")
		}
	}
	result, err := app.mm.PreBlock(ctx)
	if err != nil {
		return nil, err
	}
	versions, err = app.UpgradeKeeper.GetModuleVersionMap(ctx)
	if err != nil {
		return nil, err
	}
	_, live := versions[wasmarchive.StoreKey]
	if versions[wasmarchive.GenesisKey] != 1 || live {
		return nil, fmt.Errorf("inconsistent Wasm archive activation")
	}
	return result, nil
}

// BeginBlocker application updates every begin block
func (app *App) BeginBlocker(ctx sdk.Context) (sdk.BeginBlock, error) {
	return app.mm.BeginBlock(ctx)
}

// EndBlocker application updates every end block
func (app *App) EndBlocker(ctx sdk.Context) (sdk.EndBlock, error) {
	return app.mm.EndBlock(ctx)
}

// InitChainer application update at chain initialization
func (app *App) InitChainer(ctx sdk.Context, req *abci.RequestInitChain) (*abci.ResponseInitChain, error) {
	var genesisState GenesisState
	if err := json.Unmarshal(req.AppStateBytes, &genesisState); err != nil {
		panic(err)
	}
	if _, present := genesisState[wasmarchive.StoreKey]; present {
		return nil, fmt.Errorf("live wasm genesis is unsupported; use an explicitly exported wasm_archive genesis")
	}
	versions := app.mm.GetVersionMap()
	versions[wasmarchive.GenesisKey] = 1
	if err := app.UpgradeKeeper.SetModuleVersionMap(ctx, versions); err != nil {
		return nil, err
	}
	response, err := app.mm.InitGenesis(ctx, app.appCodec, genesisState)
	if err != nil {
		return nil, err
	}
	if err := wasmarchive.InitGenesis(ctx, app.keys[wasmarchive.StoreKey], genesisState[wasmarchive.GenesisKey]); err != nil {
		return nil, err
	}
	return response, nil
}

// Configurator get app configurator
func (app *App) Configurator() module.Configurator {
	return app.configurator
}

// LoadHeight loads a particular height
func (app *App) LoadHeight(height int64) error {
	return app.LoadVersion(height)
}

// ModuleAccountAddrs returns all the app's module account addresses.
func (app *App) ModuleAccountAddrs() map[string]bool {
	modAccAddrs := make(map[string]bool)
	for acc := range maccPerms {
		modAccAddrs[authtypes.NewModuleAddress(acc).String()] = true
	}

	return modAccAddrs
}

// GetMaccPerms returns a defensive copy of module account permissions.
func GetMaccPerms() map[string][]string { return maps.Clone(maccPerms) }

// BlockedModuleAccountAddrs returns all the app's blocked module account
// addresses.
func (app *App) BlockedModuleAccountAddrs() map[string]bool {
	modAccAddrs := app.ModuleAccountAddrs()
	delete(modAccAddrs, authtypes.NewModuleAddress(govtypes.ModuleName).String())
	// Retain the old bank-send restriction after removing the fee middleware.
	// The historical account remains in auth; do not turn it into a funds sink.
	modAccAddrs[authtypes.NewModuleAddress("feeibc").String()] = true
	modAccAddrs[authtypes.NewModuleAddress("wasm").String()] = true

	return modAccAddrs
}

// LegacyAmino returns SimApp's amino codec.
//
// NOTE: This is solely to be used for testing purposes as it may be desirable
// for modules to register their own custom testing types.
func (app *App) LegacyAmino() *codec.LegacyAmino {
	return app.cdc
}

// AppCodec returns an app codec.
//
// NOTE: This is solely to be used for testing purposes as it may be desirable
// for modules to register their own custom testing types.
func (app *App) AppCodec() codec.Codec {
	return app.appCodec
}

// InterfaceRegistry returns an InterfaceRegistry
func (app *App) InterfaceRegistry() types.InterfaceRegistry {
	return app.interfaceRegistry
}

// TxConfig returns SimApp's TxConfig
func (app *App) TxConfig() client.TxConfig {
	return app.txConfig
}

// AutoCliOpts exposes module query and transaction descriptors to the daemon
// CLI. SDK v0.53+ moved most query commands from AppModuleBasic to AutoCLI.
func (app *App) AutoCliOpts() autocli.AppOptions {
	modules := make(map[string]appmodule.AppModule)
	for _, candidate := range app.ModuleManager().Modules {
		moduleWithName, hasName := candidate.(module.HasName)
		appModule, isAppModule := candidate.(appmodule.AppModule)
		if hasName && isAppModule {
			modules[moduleWithName.Name()] = appModule
		}
	}

	return autocli.AppOptions{
		Modules:               modules,
		ModuleOptions:         runtimeservices.ExtractAutoCLIOptions(app.ModuleManager().Modules),
		AddressCodec:          authcodec.NewBech32Codec(sdk.GetConfig().GetBech32AccountAddrPrefix()),
		ValidatorAddressCodec: authcodec.NewBech32Codec(sdk.GetConfig().GetBech32ValidatorAddrPrefix()),
		ConsensusAddressCodec: authcodec.NewBech32Codec(sdk.GetConfig().GetBech32ConsensusAddrPrefix()),
	}
}

// GetKey returns the KVStoreKey for the provided store key.
//
// NOTE: This is solely to be used for testing purposes.
func (app *App) GetKey(storeKey string) *storetypes.KVStoreKey {
	return app.keys[storeKey]
}

// GetTKey returns the TransientStoreKey for the provided store key.
//
// NOTE: This is solely to be used for testing purposes.
func (app *App) GetTKey(storeKey string) *storetypes.TransientStoreKey {
	return app.tkeys[storeKey]
}

// RegisterAPIRoutes registers all application module routes with the provided
// API server.
func (app *App) RegisterAPIRoutes(apiSvr *api.Server, apiConfig config.APIConfig) {
	clientCtx := apiSvr.ClientCtx
	wasmarchive.RegisterREST(clientCtx, apiSvr.Router)
	// Register new tx routes from grpc-gateway.
	authtx.RegisterGRPCGatewayRoutes(clientCtx, apiSvr.GRPCGatewayRouter)
	// Register new tendermint queries routes from grpc-gateway.
	cmtservice.RegisterGRPCGatewayRoutes(clientCtx, apiSvr.GRPCGatewayRouter)
	// Register node gRPC service for grpc-gateway.
	nodeservice.RegisterGRPCGatewayRoutes(clientCtx, apiSvr.GRPCGatewayRouter)

	// Register grpc-gateway routes for all modules.
	ModuleBasics.RegisterGRPCGatewayRoutes(clientCtx, apiSvr.GRPCGatewayRouter)

	// register app's OpenAPI routes.
	docs.RegisterOpenAPIService(Name, apiSvr.Router)
}

// RegisterTxService implements the Application.RegisterTxService method.
func (app *App) RegisterTxService(clientCtx client.Context) {
	authtx.RegisterTxService(app.BaseApp.GRPCQueryRouter(), clientCtx, app.BaseApp.Simulate, app.interfaceRegistry)
}

// RegisterTendermintService implements the Application.RegisterTendermintService method.
func (app *App) RegisterTendermintService(clientCtx client.Context) {
	cmtservice.RegisterTendermintService(
		clientCtx,
		app.GRPCQueryRouter(),
		app.interfaceRegistry,
		server.NewCometABCIWrapper(app).Query,
	)
}

// RegisterNodeService implements the Application.RegisterNodeService method.
func (app *App) RegisterNodeService(clientCtx client.Context, cfg config.Config) {
	nodeservice.RegisterNodeService(clientCtx, app.GRPCQueryRouter(), cfg, func() int64 { return app.CommitMultiStore().EarliestVersion() })
}

// SimulationManager returns the app SimulationManager
func (app *App) SimulationManager() *module.SimulationManager {
	return app.sm
}

// ModuleManager returns the app ModuleManager
func (app *App) ModuleManager() *module.Manager {
	return app.mm
}

func (app *App) setupUpgradeHandlers() {
	app.registerPQCAuthUpgrade()
	// Recognize completed upgrades without permitting their migrations to run again.
	for _, name := range []string{"0.3.1", "0.4.0", "0.4.2", "0.4.3", "0.4.4", "0.5.0"} {
		app.UpgradeKeeper.SetUpgradeHandler(name, func(context.Context, upgradetypes.Plan, module.VersionMap) (module.VersionMap, error) {
			return nil, fmt.Errorf("complete legacy upgrades using their original binaries before Wasm retirement")
		})
	}
	// Recognize the completed v1.0.0 plan, but never rerun its retirement
	// migration with a binary that also mounts the new pqcauth store.
	app.UpgradeKeeper.SetUpgradeHandler(wasmarchive.UpgradeName,
		func(context.Context, upgradetypes.Plan, module.VersionMap) (module.VersionMap, error) {
			return nil, fmt.Errorf("complete v1.0.0 using its released binary before installing PQC Auth")
		})

	info, err := app.UpgradeKeeper.ReadUpgradeInfoFromDisk()
	if err != nil {
		panic(err)
	}
	if info.Name == PQCAuthUpgradeName && !app.UpgradeKeeper.IsSkipHeight(info.Height) {
		changes := storetypes.StoreUpgrades{Added: []string{pqcauthtypes.StoreKey}}
		app.SetStoreLoader(upgradetypes.UpgradeStoreLoader(info.Height, &changes))
	}

}
