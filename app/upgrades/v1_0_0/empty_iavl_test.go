package v1_0_0

import (
	"testing"

	"cosmossdk.io/log/v2"
	dbm "github.com/cosmos/cosmos-db"
	"github.com/cosmos/cosmos-sdk/store/v2/rootmulti"
	storetypes "github.com/cosmos/cosmos-sdk/store/v2/types"
	"github.com/stretchr/testify/require"
)

func TestEmptyIAVLRootAwareDBLoadsEmptyStore(t *testing.T) {
	db, err := dbm.NewDB("empty-iavl", dbm.GoLevelDBBackend, t.TempDir())
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, db.Close()) })
	logger := log.NewNopLogger()
	key := storetypes.NewKVStoreKey("empty")
	store := rootmulti.NewStore(db, logger)
	store.MountStoreWithDB(key, storetypes.StoreTypeIAVL, nil)
	require.NoError(t, store.LoadLatestVersion())
	require.NoError(t, store.SetInitialVersion(9))
	commitID := store.Commit()
	require.EqualValues(t, 9, commitID.Version)

	awareReload := rootmulti.NewStore(&emptyIAVLRootAwareDB{DB: db}, logger)
	awareReload.MountStoreWithDB(key, storetypes.StoreTypeIAVL, nil)
	require.NoError(t, awareReload.LoadLatestVersion())
	require.Equal(t, commitID, awareReload.LastCommitID())
}

func TestIsIAVLRootKey(t *testing.T) {
	require.True(t, isIAVLRootKey(append([]byte("s/k:evidence/"), legacyIAVLRootKey(42)...)))
	require.True(t, isIAVLRootKey(append([]byte("s/k:evidence/"), currentIAVLRootKey(42)...)))
	require.False(t, isIAVLRootKey([]byte("s/k:evidence/n-not-a-root")))
	require.False(t, isIAVLRootKey([]byte("unrelated/r12345678")))
}
