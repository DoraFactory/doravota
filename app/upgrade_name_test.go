package app_test

import (
	"testing"

	"cosmossdk.io/log"
	dbm "github.com/cosmos/cosmos-db"
	"github.com/cosmos/cosmos-sdk/baseapp"
	simtestutil "github.com/cosmos/cosmos-sdk/testutil/sims"
	"github.com/stretchr/testify/require"

	"github.com/DoraFactory/doravota/app"
)

// The actual application must recognize the exact proposal/Cosmovisor name.
func TestVersionedUpgradeHandlerRegistration(t *testing.T) {
	opts := simtestutil.AppOptionsMap{}
	db := dbm.NewMemDB()
	t.Cleanup(func() { require.NoError(t, db.Close()) })
	instance := app.New(log.NewNopLogger(), db, nil, true, map[int64]bool{},
		simulationHome(t, opts), 0, app.MakeEncodingConfig(), opts,
		simulationWasmOpts(t), baseapp.SetChainID("upgrade-name-test"))
	require.True(t, instance.UpgradeKeeper.HasHandler("0.5.0"))
	require.False(t, instance.UpgradeKeeper.HasHandler("v0.5.0"))
	require.False(t, instance.UpgradeKeeper.HasHandler("sdk-v0.53-bridge"))
}
