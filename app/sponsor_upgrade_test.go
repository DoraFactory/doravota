package app

import (
	"testing"

	dbm "github.com/cometbft/cometbft-db"
	"github.com/cometbft/cometbft/libs/log"
	tmproto "github.com/cometbft/cometbft/proto/tendermint/types"
	"github.com/stretchr/testify/require"

	sponsortypes "github.com/DoraFactory/doravota/x/sponsor-contract-tx/types"
)

func TestRunMigrationsInitializesSponsorModuleForExistingChain(t *testing.T) {
	db := dbm.NewMemDB()
	t.Cleanup(func() {
		require.NoError(t, db.Close())
	})

	chainApp := New(
		log.NewNopLogger(),
		db,
		nil,
		true,
		map[int64]bool{},
		t.TempDir(),
		0,
		MakeEncodingConfig(),
		emptyAppOptions{},
		nil,
	)
	ctx := chainApp.BaseApp.NewUncachedContext(
		false,
		tmproto.Header{Height: 1},
	)

	store := ctx.KVStore(chainApp.GetKey(sponsortypes.StoreKey))
	require.False(t, store.Has(sponsortypes.ParamsKey))

	// An existing chain's version map does not contain a newly introduced
	// module. Cosmos SDK must therefore call its default InitGenesis.
	fromVM := chainApp.ModuleManager().GetVersionMap()
	delete(fromVM, sponsortypes.ModuleName)

	updatedVM, err := chainApp.ModuleManager().RunMigrations(
		ctx,
		chainApp.Configurator(),
		fromVM,
	)
	require.NoError(t, err)
	require.Equal(t, uint64(1), updatedVM[sponsortypes.ModuleName])
	require.True(t, store.Has(sponsortypes.ParamsKey))
	require.Equal(t, sponsortypes.DefaultParams(), chainApp.SponsorKeeper.GetParams(ctx))
}
