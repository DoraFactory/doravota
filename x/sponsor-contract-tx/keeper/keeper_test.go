package keeper

import (
	"testing"

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

func setupKeeper(t *testing.T) (Keeper, sdk.Context) {
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

	// Create keeper
	keeper := NewKeeper(cdc, storeKey)

	// Create context
	ctx := sdk.NewContext(
		ms,
		tmproto.Header{},
		false,
		log.NewNopLogger(),
	)

	return *keeper, ctx
}

func TestSetSponsor(t *testing.T) {
	keeper, ctx := setupKeeper(t)

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
	keeper, ctx := setupKeeper(t)

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
	keeper, ctx := setupKeeper(t)

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
	keeper, ctx := setupKeeper(t)

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
	keeper, ctx := setupKeeper(t)

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
	keeper, ctx := setupKeeper(t)

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
	keeper, ctx := setupKeeper(t)

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
	keeper, ctx := setupKeeper(t)

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
