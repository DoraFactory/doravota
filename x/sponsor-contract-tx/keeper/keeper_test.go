package keeper

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
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	dbm "github.com/cometbft/cometbft-db"

	"github.com/DoraFactory/doravota/x/sponsor-contract-tx/types"
)

// MockWasmKeeper implements WasmKeeperInterface for testing
type MockWasmKeeper struct {
	contracts map[string]*wasmtypes.ContractInfo
}

func NewMockWasmKeeper() *MockWasmKeeper {
	return &MockWasmKeeper{
		contracts: make(map[string]*wasmtypes.ContractInfo),
	}
}

func (m *MockWasmKeeper) GetContractInfo(ctx sdk.Context, contractAddress sdk.AccAddress) *wasmtypes.ContractInfo {
	return m.contracts[contractAddress.String()]
}

func (m *MockWasmKeeper) QuerySmart(ctx sdk.Context, contractAddr sdk.AccAddress, req []byte) ([]byte, error) {
	// For testing purposes, return empty response
	return []byte(`{"eligible": true}`), nil
}

func (m *MockWasmKeeper) SetContractInfo(contractAddr string, admin string) {
	accAddr, _ := sdk.AccAddressFromBech32(contractAddr)
	m.contracts[accAddr.String()] = &wasmtypes.ContractInfo{
		Admin: admin,
	}
}

func setupKeeper(t *testing.T) (Keeper, sdk.Context, *MockWasmKeeper) {
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
	keeper := NewKeeper(cdc, storeKey, mockWasmKeeper)

	// Create context
	ctx := sdk.NewContext(
		ms,
		tmproto.Header{},
		false,
		log.NewNopLogger(),
	)

	return *keeper, ctx, mockWasmKeeper
}

// setupKeeperSimple provides backward compatibility for simple tests
func setupKeeperSimple(t *testing.T) (Keeper, sdk.Context) {
	keeper, ctx, _ := setupKeeper(t)
	return keeper, ctx
}

func TestSetSponsor(t *testing.T) {
	keeper, ctx := setupKeeperSimple(t)

	sponsor := types.ContractSponsor{
		ContractAddress: "dora1contract123",
		IsSponsored:     true,
	}

	// Test setting sponsor
	keeper.SetSponsor(ctx, sponsor)

	// Verify sponsor was set
	retrievedSponsor, found := keeper.GetSponsor(ctx, sponsor.ContractAddress)
	require.True(t, found)
	assert.Equal(t, sponsor.ContractAddress, retrievedSponsor.ContractAddress)
	assert.Equal(t, sponsor.IsSponsored, retrievedSponsor.IsSponsored)
}

func TestGetSponsor(t *testing.T) {
	keeper, ctx := setupKeeperSimple(t)

	sponsor := types.ContractSponsor{
		ContractAddress: "dora1contract123",
		IsSponsored:     true,
	}

	// Test getting non-existent sponsor
	_, found := keeper.GetSponsor(ctx, sponsor.ContractAddress)
	require.False(t, found)

	// Set sponsor
	keeper.SetSponsor(ctx, sponsor)

	// Test getting existing sponsor
	retrievedSponsor, found := keeper.GetSponsor(ctx, sponsor.ContractAddress)
	require.True(t, found)
	assert.Equal(t, sponsor.ContractAddress, retrievedSponsor.ContractAddress)
	assert.Equal(t, sponsor.IsSponsored, retrievedSponsor.IsSponsored)
}

func TestHasSponsor(t *testing.T) {
	keeper, ctx := setupKeeperSimple(t)

	contractAddr := "dora1contract123"

	// Test non-existent sponsor
	exists := keeper.HasSponsor(ctx, contractAddr)
	assert.False(t, exists)

	// Set sponsor
	sponsor := types.ContractSponsor{
		ContractAddress: contractAddr,
		IsSponsored:     true,
	}
	keeper.SetSponsor(ctx, sponsor)

	// Test existing sponsor
	exists = keeper.HasSponsor(ctx, contractAddr)
	assert.True(t, exists)
}

func TestDeleteSponsor(t *testing.T) {
	keeper, ctx := setupKeeperSimple(t)

	sponsor := types.ContractSponsor{
		ContractAddress: "dora1contract123",
		IsSponsored:     true,
	}

	// Set sponsor
	keeper.SetSponsor(ctx, sponsor)

	// Verify sponsor exists
	exists := keeper.HasSponsor(ctx, sponsor.ContractAddress)
	assert.True(t, exists)

	// Delete sponsor
	keeper.DeleteSponsor(ctx, sponsor.ContractAddress)

	// Verify sponsor is deleted
	exists = keeper.HasSponsor(ctx, sponsor.ContractAddress)
	assert.False(t, exists)

	// Test getting deleted sponsor
	_, found := keeper.GetSponsor(ctx, sponsor.ContractAddress)
	assert.False(t, found)
}

func TestIsSponsored(t *testing.T) {
	keeper, ctx := setupKeeperSimple(t)

	contractAddr := "dora1contract123"

	// Test non-existent sponsor
	isSponsored := keeper.IsSponsored(ctx, contractAddr)
	assert.False(t, isSponsored)

	// Set sponsored contract
	sponsor := types.ContractSponsor{
		ContractAddress: contractAddr,
		IsSponsored:     true,
	}
	keeper.SetSponsor(ctx, sponsor)

	// Test sponsored contract
	isSponsored = keeper.IsSponsored(ctx, contractAddr)
	assert.True(t, isSponsored)

	// Set non-sponsored contract
	sponsor.IsSponsored = false
	keeper.SetSponsor(ctx, sponsor)

	// Test non-sponsored contract
	isSponsored = keeper.IsSponsored(ctx, contractAddr)
	assert.False(t, isSponsored)
}

func TestGetAllSponsors(t *testing.T) {
	keeper, ctx := setupKeeperSimple(t)

	// Test empty sponsors
	sponsors := keeper.GetAllSponsors(ctx)
	assert.Empty(t, sponsors)

	// Set multiple sponsors
	sponsor1 := types.ContractSponsor{
		ContractAddress: "dora1contract123",
		IsSponsored:     true,
	}
	sponsor2 := types.ContractSponsor{
		ContractAddress: "dora1contract456",
		IsSponsored:     false,
	}
	sponsor3 := types.ContractSponsor{
		ContractAddress: "dora1contract789",
		IsSponsored:     true,
	}

	keeper.SetSponsor(ctx, sponsor1)
	keeper.SetSponsor(ctx, sponsor2)
	keeper.SetSponsor(ctx, sponsor3)

	// Test getting all sponsors
	sponsors = keeper.GetAllSponsors(ctx)
	assert.Len(t, sponsors, 3)

	// Verify all sponsors are included
	contractAddrs := make(map[string]bool)
	for _, sponsor := range sponsors {
		contractAddrs[sponsor.ContractAddress] = sponsor.IsSponsored
	}

	assert.True(t, contractAddrs["dora1contract123"])
	assert.False(t, contractAddrs["dora1contract456"])
	assert.True(t, contractAddrs["dora1contract789"])
}

func TestUpdateSponsor(t *testing.T) {
	keeper, ctx := setupKeeperSimple(t)

	contractAddr := "dora1contract123"

	// Set initial sponsor
	sponsor := types.ContractSponsor{
		ContractAddress: contractAddr,
		IsSponsored:     true,
	}
	keeper.SetSponsor(ctx, sponsor)

	// Verify initial state
	isSponsored := keeper.IsSponsored(ctx, contractAddr)
	assert.True(t, isSponsored)

	// Update sponsor
	sponsor.IsSponsored = false
	keeper.SetSponsor(ctx, sponsor)

	// Verify updated state
	isSponsored = keeper.IsSponsored(ctx, contractAddr)
	assert.False(t, isSponsored)

	// Verify sponsor still exists
	exists := keeper.HasSponsor(ctx, contractAddr)
	assert.True(t, exists)
}

func TestMultipleSponsors(t *testing.T) {
	keeper, ctx := setupKeeperSimple(t)

	// Set multiple sponsors with different states
	sponsors := []types.ContractSponsor{
		{
			ContractAddress: "dora1contract1",
			IsSponsored:     true,
		},
		{
			ContractAddress: "dora1contract2",
			IsSponsored:     false,
		},
		{
			ContractAddress: "dora1contract3",
			IsSponsored:     true,
		},
	}

	for _, sponsor := range sponsors {
		keeper.SetSponsor(ctx, sponsor)
	}

	// Test individual sponsor states
	assert.True(t, keeper.IsSponsored(ctx, "dora1contract1"))
	assert.False(t, keeper.IsSponsored(ctx, "dora1contract2"))
	assert.True(t, keeper.IsSponsored(ctx, "dora1contract3"))

	// Test that all sponsors exist
	for _, sponsor := range sponsors {
		assert.True(t, keeper.HasSponsor(ctx, sponsor.ContractAddress))
	}

	// Test getting all sponsors
	allSponsors := keeper.GetAllSponsors(ctx)
	assert.Len(t, allSponsors, 3)
}

func TestIsContractAdmin(t *testing.T) {
	keeper, ctx := setupKeeperSimple(t)

	// Generate valid test addresses
	adminAddr := sdk.AccAddress([]byte("test_admin_address_12")).String()

	// Test invalid contract address format
	t.Run("invalid contract address", func(t *testing.T) {
		userAccAddr, err := sdk.AccAddressFromBech32(adminAddr)
		require.NoError(t, err)

		isAdmin, err := keeper.IsContractAdmin(ctx, "invalid-address", userAccAddr)
		assert.Error(t, err)
		assert.False(t, isAdmin)
		assert.Contains(t, err.Error(), "invalid contract address")
	})

	// Note: Testing with valid contract address but non-existent contract
	// would cause panic with the current mock wasm keeper setup.
	// This functionality is validated through integration tests and
	// msg_server tests which handle the errors appropriately.
}

func TestIsContractAdminInvalidUserAddress(t *testing.T) {
	keeper, ctx, mockWasmKeeper := setupKeeper(t)

	// Generate valid test addresses
	contractAddr := sdk.AccAddress([]byte("test_contract_addr_12")).String()

	// Test with different user address formats to ensure our validation works
	validUserAddr, err := sdk.AccAddressFromBech32(sdk.AccAddress([]byte("test_user_address_123")).String())
	require.NoError(t, err)

	// Test case 1: Contract not found (mock wasm keeper returns nil for GetContractInfo)
	isAdmin, err := keeper.IsContractAdmin(ctx, contractAddr, validUserAddr)
	assert.Error(t, err)
	assert.False(t, isAdmin)
	assert.Contains(t, err.Error(), "contract not found")

	// Test case 2: Contract exists but user is not admin
	adminAddr := sdk.AccAddress([]byte("different_admin_addr")).String()
	mockWasmKeeper.SetContractInfo(contractAddr, adminAddr)

	isAdmin, err = keeper.IsContractAdmin(ctx, contractAddr, validUserAddr)
	assert.NoError(t, err)
	assert.False(t, isAdmin)

	// Test case 3: Contract exists and user is admin
	mockWasmKeeper.SetContractInfo(contractAddr, validUserAddr.String())

	isAdmin, err = keeper.IsContractAdmin(ctx, contractAddr, validUserAddr)
	assert.NoError(t, err)
	assert.True(t, isAdmin)
}

// Note: More comprehensive tests for IsContractAdmin functionality would require
// a proper mock of the wasm keeper that can return contract info.
// The current zero-value mock causes panics when GetContractInfo is called.
// The admin authorization functionality is tested indirectly through the
// msg_server tests which expect appropriate error messages.
