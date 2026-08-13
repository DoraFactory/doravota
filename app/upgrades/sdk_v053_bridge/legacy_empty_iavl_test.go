package sdk_v053_bridge

import (
	"testing"

	"cosmossdk.io/log"
	"cosmossdk.io/store/metrics"
	"cosmossdk.io/store/rootmulti"
	storetypes "cosmossdk.io/store/types"
	"cosmossdk.io/store/wrapper"
	dbm "github.com/cosmos/cosmos-db"
	"github.com/cosmos/iavl"
	"github.com/stretchr/testify/require"
)

func TestLegacyEmptyIAVLDBLoadsOldEmptyRootWithoutMutation(t *testing.T) {
	db, err := dbm.NewDB("legacy-empty", dbm.GoLevelDBBackend, t.TempDir())
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, db.Close()) })
	logger := log.NewNopLogger()
	key := storetypes.NewKVStoreKey("empty")
	store := rootmulti.NewStore(db, logger, metrics.NewNoOpMetrics())
	store.MountStoreWithDB(key, storetypes.StoreTypeIAVL, nil)
	require.NoError(t, store.LoadLatestVersion())
	require.NoError(t, store.SetInitialVersion(9))
	appCommitID := store.Commit()
	require.EqualValues(t, 9, appCommitID.Version)
	commitInfo, err := store.GetCommitInfo(appCommitID.Version)
	require.NoError(t, err)
	require.Len(t, commitInfo.StoreInfos, 1)
	storeCommitID := commitInfo.StoreInfos[0].CommitId
	require.Equal(t, emptyIAVLHash[:], storeCommitID.Hash)

	// Replace the current marker with the v0.20 representation.
	deletePrefix(t, db, []byte(iavlStorePrefix+key.Name()+"/"))
	storeDB := dbm.NewPrefixDB(db, []byte(iavlStorePrefix+key.Name()+"/"))
	require.NoError(t, storeDB.Set(legacyIAVLRootKey(appCommitID.Version), []byte{}))

	tree := newTestTree(db, key.Name())
	_, err = tree.LoadVersion(appCommitID.Version)
	require.Error(t, err)

	awareDB := &emptyIAVLRootAwareDB{DB: db}
	tree = newTestTree(awareDB, key.Name())
	loadedVersion, err := tree.LoadVersion(appCommitID.Version)
	require.NoError(t, err)
	require.Equal(t, appCommitID.Version, loadedVersion)
	require.Equal(t, storeCommitID.Hash, tree.Hash())

	// The wrapper is a read view only; the legacy entry remains byte-for-byte
	// empty in the underlying database.
	exists, value, err := rawDBEntry(storeDB, legacyIAVLRootKey(appCommitID.Version))
	require.NoError(t, err)
	require.True(t, exists)
	require.Empty(t, value)
}

func TestValidateLegacyEmptyIAVLStoresOnlyAtUpgradeBoundary(t *testing.T) {
	db := dbm.NewMemDB()
	stores, err := validateLegacyEmptyIAVLStoresAtHeight(log.NewNopLogger(), db, 100)
	require.NoError(t, err)
	require.Empty(t, stores)
}

func TestIsIAVLRootKey(t *testing.T) {
	require.True(t, isIAVLRootKey(append([]byte("s/k:authz/"), legacyIAVLRootKey(42)...)))
	currentRoot := append([]byte("s/k:authz/s"), iavl.GetRootKey(42)...)
	require.True(t, isIAVLRootKey(currentRoot))
	require.False(t, isIAVLRootKey([]byte("s/k:authz/n-not-a-root")))
	require.False(t, isIAVLRootKey([]byte("unrelated/r12345678")))
}

func newTestTree(db dbm.DB, storeName string) *iavl.MutableTree {
	storeDB := dbm.NewPrefixDB(db, []byte(iavlStorePrefix+storeName+"/"))
	return iavl.NewMutableTree(
		wrapper.NewDBWrapper(storeDB),
		0,
		true,
		iavl.NewNopLogger(),
		iavl.AsyncPruningOption(false),
	)
}

func deletePrefix(t *testing.T, db dbm.DB, prefix []byte) {
	t.Helper()
	prefixDB := dbm.NewPrefixDB(db, prefix)
	iterator, err := prefixDB.Iterator(nil, nil)
	require.NoError(t, err)
	keys := make([][]byte, 0)
	for ; iterator.Valid(); iterator.Next() {
		keys = append(keys, append([]byte(nil), iterator.Key()...))
	}
	require.NoError(t, iterator.Close())
	for _, key := range keys {
		require.NoError(t, prefixDB.Delete(key))
	}
}
