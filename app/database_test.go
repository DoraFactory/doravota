package app_test

import (
	"testing"

	dbm "github.com/cosmos/cosmos-db"
	"github.com/cosmos/cosmos-sdk/store/v2/wrapper"
	"github.com/cosmos/iavl"
	"github.com/stretchr/testify/require"
)

// An empty IAVL root is a present key with a zero-length value. A LevelDB
// dependency that conflates it with a missing key prevents node restarts.
func TestEmptyIAVLRootSurvivesLevelDBRestart(t *testing.T) {
	dir := t.TempDir()
	db, err := dbm.NewDB("application", dbm.GoLevelDBBackend, dir)
	require.NoError(t, err)
	tree := iavl.NewMutableTree(wrapper.NewDBWrapper(db), 0, true, iavl.NewNopLogger(), iavl.AsyncPruningOption(false))
	hash, version, err := tree.SaveVersion()
	require.NoError(t, err)
	require.EqualValues(t, 1, version)
	require.NoError(t, tree.Close())
	require.NoError(t, db.Close())

	db, err = dbm.NewDB("application", dbm.GoLevelDBBackend, dir)
	require.NoError(t, err)
	defer db.Close()
	tree = iavl.NewMutableTree(wrapper.NewDBWrapper(db), 0, true, iavl.NewNopLogger(), iavl.AsyncPruningOption(false))
	defer tree.Close()
	_, err = tree.LoadVersion(version)
	require.NoError(t, err)
	require.Equal(t, hash, tree.Hash())
	require.Zero(t, tree.Size())
}
