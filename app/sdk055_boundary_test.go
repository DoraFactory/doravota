package app

import (
	"testing"

	"cosmossdk.io/log/v2"
	dbm "github.com/cosmos/cosmos-db"
	"github.com/cosmos/cosmos-sdk/store/v2/rootmulti"
	storetypes "github.com/cosmos/cosmos-sdk/store/v2/types"
	"github.com/stretchr/testify/require"
)

func TestSDK055DependencyBoundaryRejectsLegacyStateWithoutMutation(t *testing.T) {
	db := dbm.NewMemDB()
	t.Cleanup(func() { require.NoError(t, db.Close()) })
	logger := log.NewNopLogger()
	require.NoError(t, validateSDK055DependencyBoundary(logger, db))
	key := storetypes.NewKVStoreKey("params")
	store := rootmulti.NewStore(db, logger)
	store.MountStoreWithDB(key, storetypes.StoreTypeIAVL, nil)
	require.NoError(t, store.LoadLatestVersion())
	branch := store.CacheMultiStore()
	branch.GetKVStore(key).Set([]byte("legacy"), []byte("preserve"))
	branch.Write()
	committed := store.Commit()
	require.ErrorContains(t, validateSDK055DependencyBoundary(logger, db), "coordinated upgrade handler")
	require.Equal(t, committed.Version, rootmulti.GetLatestVersion(db))
	require.Equal(t, []byte("preserve"), store.GetKVStore(key).Get([]byte("legacy")))
	require.Equal(t, committed, store.LastCommitID())
}
