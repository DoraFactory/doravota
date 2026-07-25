package keeper

import (
	"encoding/binary"
	"testing"

	tmproto "github.com/cometbft/cometbft/proto/tendermint/types"
	"github.com/cosmos/cosmos-sdk/store/prefix"
	"github.com/stretchr/testify/require"

	"github.com/DoraFactory/doravota/x/sponsor-contract-tx/types"
)

func TestGarbageCollectByExpiryIsIndependentOfBlockHeight(t *testing.T) {
	keeper, ctx := setupKeeperSimple(t)
	ctx = ctx.WithBlockHeader(tmproto.Header{Height: 1_000_000_000})

	result := keeper.garbageCollectByExpiry(ctx, 200)

	require.Zero(t, result.scanned)
	require.Zero(t, result.removed)
	require.Zero(t, result.invalidIndexes)
}

func TestGarbageCollectByExpiryUsesOrderedSparseIndex(t *testing.T) {
	keeper, ctx := setupKeeperSimple(t)
	ctx = ctx.WithBlockHeader(tmproto.Header{Height: 1_000_000_000})

	tickets := []types.PolicyTicket{
		{ContractAddress: "c", UserAddress: "u", Digest: "d1", ExpiryHeight: 1},
		{ContractAddress: "c", UserAddress: "u", Digest: "d2", ExpiryHeight: 1_000_000},
		{ContractAddress: "c", UserAddress: "u", Digest: "d3", ExpiryHeight: 900_000_000},
		{ContractAddress: "c", UserAddress: "u", Digest: "boundary", ExpiryHeight: 1_000_000_000},
	}
	for _, ticket := range tickets {
		require.NoError(t, keeper.SetPolicyTicket(ctx, ticket))
	}

	first := keeper.garbageCollectByExpiry(ctx, 2)
	require.Equal(t, 2, first.scanned)
	require.Equal(t, 2, first.removed)

	_, found := keeper.GetPolicyTicket(ctx, "c", "u", "d1")
	require.False(t, found)
	_, found = keeper.GetPolicyTicket(ctx, "c", "u", "d2")
	require.False(t, found)
	_, found = keeper.GetPolicyTicket(ctx, "c", "u", "d3")
	require.True(t, found)

	second := keeper.garbageCollectByExpiry(ctx, 10)
	require.Equal(t, 2, second.scanned, "one expired and one boundary entry should be inspected")
	require.Equal(t, 1, second.removed)
	_, found = keeper.GetPolicyTicket(ctx, "c", "u", "d3")
	require.False(t, found)
	_, found = keeper.GetPolicyTicket(ctx, "c", "u", "boundary")
	require.True(t, found, "a ticket remains valid at its expiry height")
}

func TestGarbageCollectByExpiryHardCapsMalformedIndexWork(t *testing.T) {
	keeper, ctx := setupKeeperSimple(t)
	ctx = ctx.WithBlockHeader(tmproto.Header{Height: 100})
	expiryStore := prefix.NewStore(ctx.KVStore(keeper.storeKey), types.ExpiryIndexKeyPrefix)

	for i := uint32(0); i < types.MaxTicketGCPerBlock+1; i++ {
		key := make([]byte, 4)
		binary.BigEndian.PutUint32(key, i)
		expiryStore.Set(key, []byte{})
	}

	result := keeper.garbageCollectByExpiry(ctx, int(types.MaxTicketGCPerBlock)+100)
	require.Equal(t, int(types.MaxTicketGCPerBlock), result.scanned)
	require.Equal(t, int(types.MaxTicketGCPerBlock), result.invalidIndexes)
	require.Zero(t, result.removed)
	require.Equal(t, 1, countKeys(expiryStore))
}

func TestGarbageCollectByExpiryRemovesOrphanIndex(t *testing.T) {
	keeper, ctx := setupKeeperSimple(t)
	ctx = ctx.WithBlockHeader(tmproto.Header{Height: 100})
	store := ctx.KVStore(keeper.storeKey)
	orphanIndex := types.GetExpiryIndexKey(50, "c", "u", "orphan")
	store.Set(orphanIndex, []byte{})

	result := keeper.garbageCollectByExpiry(ctx, 10)

	require.Equal(t, 1, result.scanned)
	require.Equal(t, 1, result.invalidIndexes)
	require.Zero(t, result.removed)
	require.False(t, store.Has(orphanIndex))
}

func TestGarbageCollectByExpiryDoesNotDeleteRenewedTicketThroughStaleIndex(t *testing.T) {
	keeper, ctx := setupKeeperSimple(t)
	ctx = ctx.WithBlockHeader(tmproto.Header{Height: 100})
	store := ctx.KVStore(keeper.storeKey)

	ticket := types.PolicyTicket{
		ContractAddress: "c",
		UserAddress:     "u",
		Digest:          "renewed",
		ExpiryHeight:    200,
	}
	require.NoError(t, keeper.SetPolicyTicket(ctx, ticket))
	staleIndex := types.GetExpiryIndexKey(50, ticket.ContractAddress, ticket.UserAddress, ticket.Digest)
	store.Set(staleIndex, []byte{})

	result := keeper.garbageCollectByExpiry(ctx, 10)

	require.Equal(t, 2, result.scanned, "the stale entry and first future entry should be inspected")
	require.Equal(t, 1, result.invalidIndexes)
	require.Zero(t, result.removed)
	stored, found := keeper.GetPolicyTicket(ctx, ticket.ContractAddress, ticket.UserAddress, ticket.Digest)
	require.True(t, found)
	require.Equal(t, uint64(200), stored.ExpiryHeight)
	require.False(t, store.Has(staleIndex))
	require.True(t, store.Has(types.GetExpiryIndexKey(200, ticket.ContractAddress, ticket.UserAddress, ticket.Digest)))
}

func TestSetPolicyTicketRemovesPreviousExpiryIndex(t *testing.T) {
	keeper, ctx := setupKeeperSimple(t)
	store := ctx.KVStore(keeper.storeKey)
	ticket := types.PolicyTicket{
		ContractAddress: "c",
		UserAddress:     "u",
		Digest:          "renewed",
		ExpiryHeight:    50,
	}
	require.NoError(t, keeper.SetPolicyTicket(ctx, ticket))
	oldIndex := types.GetExpiryIndexKey(50, ticket.ContractAddress, ticket.UserAddress, ticket.Digest)
	require.True(t, store.Has(oldIndex))

	ticket.ExpiryHeight = 200
	require.NoError(t, keeper.SetPolicyTicket(ctx, ticket))

	require.False(t, store.Has(oldIndex))
	require.True(t, store.Has(types.GetExpiryIndexKey(200, ticket.ContractAddress, ticket.UserAddress, ticket.Digest)))
}

func BenchmarkGarbageCollectByExpiryHighHeightNoExpiredTickets(b *testing.B) {
	keeper, ctx := setupKeeperSimple(b)
	ctx = ctx.WithBlockHeader(tmproto.Header{Height: 1_000_000_000})

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		result := keeper.garbageCollectByExpiry(ctx, 200)
		if result.scanned != 0 {
			b.Fatalf("expected no index scans, got %d", result.scanned)
		}
	}
}
