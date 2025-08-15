package testutil

import (
	"testing"

	wasmtypes "github.com/CosmWasm/wasmd/x/wasm/types"
	"github.com/cometbft/cometbft/libs/log"
	tmproto "github.com/cometbft/cometbft/proto/tendermint/types"
	"github.com/cosmos/cosmos-sdk/codec"
	codectypes "github.com/cosmos/cosmos-sdk/codec/types"
	"github.com/cosmos/cosmos-sdk/store"
	storetypes "github.com/cosmos/cosmos-sdk/store/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
	authtypes "github.com/cosmos/cosmos-sdk/x/auth/types"
	banktypes "github.com/cosmos/cosmos-sdk/x/bank/types"

	dbm "github.com/cometbft/cometbft-db"

	"github.com/DoraFactory/doravota/x/sponsor-contract-tx/keeper"
	"github.com/DoraFactory/doravota/x/sponsor-contract-tx/types"
)

// TestSuite provides common test setup functionality
type TestSuite struct {
	Ctx        sdk.Context
	Keeper     keeper.Keeper
	WasmKeeper *MockWasmKeeper
	Codec      codec.Codec

	// Test accounts
	Admin      sdk.AccAddress
	User       sdk.AccAddress
	User2      sdk.AccAddress
	Contract   sdk.AccAddress
	FeeGranter sdk.AccAddress
}

// SetupBasicKeeper creates a basic keeper setup for simple tests
func SetupBasicKeeper(t *testing.T) (keeper.Keeper, sdk.Context, *MockWasmKeeper) {
	// Create codec
	registry := codectypes.NewInterfaceRegistry()
	cdc := codec.NewProtoCodec(registry)

	// Create store
	storeKey := sdk.NewKVStoreKey(types.StoreKey)

	// Create an in-memory database for testing
	db := dbm.NewMemDB()
	ms := store.NewCommitMultiStore(db)
	ms.MountStoreWithDB(storeKey, storetypes.StoreTypeIAVL, nil)

	// Load the stores
	err := ms.LoadLatestVersion()
	if err != nil {
		t.Fatalf("Failed to load store: %v", err)
	}

	// Create keeper with mock wasm keeper
	mockWasmKeeper := NewMockWasmKeeper()
	keeper := keeper.NewKeeper(cdc, storeKey, mockWasmKeeper)

	// Create context
	ctx := sdk.NewContext(
		ms,
		tmproto.Header{},
		false,
		log.NewNopLogger(),
	)

	return *keeper, ctx, mockWasmKeeper
}

// SetupBasicKeeperSimple provides backward compatibility for simple tests
func SetupBasicKeeperSimple(t *testing.T) (keeper.Keeper, sdk.Context) {
	keeper, ctx, _ := SetupBasicKeeper(t)
	return keeper, ctx
}

// SetupFullSuite creates a complete test suite with basic keeper setup
// For more complex setups requiring auth/bank keepers, use specific setup functions
func SetupFullSuite(t *testing.T) *TestSuite {
	// Use the basic keeper setup
	sponsorKeeper, ctx, wasmKeeper := SetupBasicKeeper(t)

	// Create codec
	interfaceRegistry := codectypes.NewInterfaceRegistry()
	authtypes.RegisterInterfaces(interfaceRegistry)
	banktypes.RegisterInterfaces(interfaceRegistry)
	wasmtypes.RegisterInterfaces(interfaceRegistry)
	types.RegisterInterfaces(interfaceRegistry)
	codec := codec.NewProtoCodec(interfaceRegistry)

	// Create test accounts
	admin := sdk.AccAddress("admin_______________")
	user := sdk.AccAddress("user________________")
	user2 := sdk.AccAddress("user2_______________") 
	contract := sdk.AccAddress("contract____________")
	feeGranter := sdk.AccAddress("feegranter__________")

	return &TestSuite{
		Ctx:        ctx,
		Keeper:     sponsorKeeper,
		WasmKeeper: wasmKeeper,
		Codec:      codec,
		Admin:      admin,
		User:       user,
		User2:      user2,
		Contract:   contract,
		FeeGranter: feeGranter,
	}
}

// SetupTestAccounts is a placeholder for account setup - requires proper auth/bank keepers
// For tests requiring funded accounts, use integration test setup functions
func (suite *TestSuite) SetupTestAccounts() {
	// This is a basic implementation that doesn't actually fund accounts
	// For full account setup with balances, use dedicated integration test helpers
}

// SetupDefaultSponsor creates a default sponsored contract for testing
func (suite *TestSuite) SetupDefaultSponsor() {
	// Set up contract info in mock wasm keeper
	suite.WasmKeeper.SetContractInfo(suite.Contract, suite.Admin.String())

	// Create sponsored contract
	sponsor := types.ContractSponsor{
		ContractAddress: suite.Contract.String(),
		CreatorAddress:  suite.Admin.String(),
		IsSponsored:     true,
		MaxGrantPerUser: CoinsToProtoCoins(sdk.NewCoins(sdk.NewCoin("peaka", sdk.NewInt(1000000)))),
	}

	err := suite.Keeper.SetSponsor(suite.Ctx, sponsor)
	if err != nil {
		panic(err)
	}
}

// SetupKeeperTestParams sets default parameters for testing
func (suite *TestSuite) SetupKeeperTestParams() {
	params := types.DefaultParams()
	params.SponsorshipEnabled = true
	params.MaxGasPerSponsorship = 1000000
	suite.Keeper.SetParams(suite.Ctx, params)
}