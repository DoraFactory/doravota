package legacyics29

import (
	"testing"

	"cosmossdk.io/log"
	"cosmossdk.io/store/metrics"
	"cosmossdk.io/store/rootmulti"
	storetypes "cosmossdk.io/store/types"
	tmproto "github.com/cometbft/cometbft/proto/tendermint/types"
	dbm "github.com/cosmos/cosmos-db"
	sdk "github.com/cosmos/cosmos-sdk/types"
	authtypes "github.com/cosmos/cosmos-sdk/x/auth/types"
	"github.com/stretchr/testify/require"
)

// Exercises the actual SDK store rename + refund commit boundary. This test is
// not a replacement for a 0.4.4 snapshot rehearsal with the final binary.
func TestStoreRenameRefundAndRestart(t *testing.T) {
	db := dbm.NewMemDB()
	t.Cleanup(func() { require.NoError(t, db.Close()) })
	oldKey, bankKey := storetypes.NewKVStoreKey("feeibc"), storetypes.NewKVStoreKey("testbank")
	old := rootmulti.NewStore(db, log.NewNopLogger(), metrics.NewNoOpMetrics())
	old.MountStoreWithDB(oldKey, storetypes.StoreTypeIAVL, nil)
	old.MountStoreWithDB(bankKey, storetypes.StoreTypeIAVL, nil)
	require.NoError(t, old.LoadLatestVersion())
	ctx := sdk.NewContext(old, tmproto.Header{Height: 1}, false, log.NewNopLogger())
	bank := testBank{key: bankKey}
	address := sdk.AccAddress(make([]byte, 20))
	escrowKey := []byte("feesInEscrow/transfer/channel-0/1")
	ctx.KVStore(oldKey).Set(feeKey("transfer", "channel-0"), []byte{1})
	ctx.KVStore(oldKey).Set(escrowKey, packetFee(t, address))
	bank.set(ctx, authtypes.NewModuleAddress("feeibc"), sdk.NewCoins(sdk.NewInt64Coin("peaka", 12)))
	before := old.Commit()
	key := storetypes.NewKVStoreKey(StoreKey)
	upgraded := rootmulti.NewStore(db, log.NewNopLogger(), metrics.NewNoOpMetrics())
	upgraded.MountStoreWithDB(key, storetypes.StoreTypeIAVL, nil)
	upgraded.MountStoreWithDB(bankKey, storetypes.StoreTypeIAVL, nil)
	require.NoError(t, upgraded.LoadVersionAndUpgrade(before.Version, &storetypes.StoreUpgrades{Renamed: []storetypes.StoreRename{{OldKey: "feeibc", NewKey: StoreKey}}}))
	require.Equal(t, before.Version, rootmulti.GetLatestVersion(db))
	ctx = sdk.NewContext(upgraded, tmproto.Header{Height: 2}, false, log.NewNopLogger())
	failing := bank
	failing.fail = address
	require.Error(t, RefundAndRetire(ctx, key, failing, testChannels{}))
	require.True(t, ctx.KVStore(key).Has(escrowKey))
	require.Equal(t, before.Version, rootmulti.GetLatestVersion(db))
	require.NoError(t, RefundAndRetire(ctx, key, bank, testChannels{}))
	after := upgraded.Commit()
	info, err := upgraded.GetCommitInfo(after.Version)
	require.NoError(t, err)
	for _, entry := range info.StoreInfos {
		require.NotEqual(t, "feeibc", entry.Name)
	}
	reopened := rootmulti.NewStore(db, log.NewNopLogger(), metrics.NewNoOpMetrics())
	reopened.MountStoreWithDB(key, storetypes.StoreTypeIAVL, nil)
	reopened.MountStoreWithDB(bankKey, storetypes.StoreTypeIAVL, nil)
	require.NoError(t, reopened.LoadLatestVersion())
	ctx = sdk.NewContext(reopened, tmproto.Header{Height: 3}, false, log.NewNopLogger())
	require.Equal(t, "12peaka", bank.GetAllBalances(ctx, address).String())
	require.False(t, ctx.KVStore(key).Has(escrowKey))
	require.True(t, ctx.KVStore(key).Has(feeKey("transfer", "channel-0")))
}
