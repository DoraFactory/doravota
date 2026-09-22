package app_test

import (
	"testing"

	"cosmossdk.io/log"
	dbm "github.com/cosmos/cosmos-db"
	"github.com/cosmos/cosmos-sdk/baseapp"
	simtestutil "github.com/cosmos/cosmos-sdk/testutil/sims"
	"github.com/stretchr/testify/require"

	"cosmossdk.io/core/header"
	upgrade "cosmossdk.io/x/upgrade"
	upgradetypes "cosmossdk.io/x/upgrade/types"
	"encoding/binary"
	"github.com/DoraFactory/doravota/app"
	tmproto "github.com/cometbft/cometbft/proto/tendermint/types"
	"github.com/cosmos/cosmos-sdk/types/module"
)

// The actual application must recognize the exact proposal/Cosmovisor name.
func TestVersionedUpgradeHandlerRegistration(t *testing.T) {
	opts := simtestutil.AppOptionsMap{}
	db := dbm.NewMemDB()
	t.Cleanup(func() { require.NoError(t, db.Close()) })
	instance := app.New(log.NewNopLogger(), db, nil, true, map[int64]bool{},
		simulationHome(t, opts), 0, app.MakeEncodingConfig(), opts,
		simulationWasmOpts(t), baseapp.SetChainID("upgrade-name-test"))
	for _, name := range []string{"0.3.1", "0.4.0", "0.4.2", "0.4.3", "0.4.4", "0.5.0", "0.5.1"} {
		require.True(t, instance.UpgradeKeeper.HasHandler(name), name)
	}
	require.False(t, instance.UpgradeKeeper.HasHandler("v0.5.0"))
	require.False(t, instance.UpgradeKeeper.HasHandler("v0.5.1"))
	require.False(t, instance.UpgradeKeeper.HasHandler("sdk-v0.53-bridge"))
}

// A completed legacy upgrade must pass the SDK downgrade check without
// re-running its handler or changing the module version map.
func TestCompletedLegacyUpgradeRemainsRecognized(t *testing.T) {
	for _, name := range []string{"0.3.1", "0.4.0", "0.4.2", "0.4.3", "0.4.4"} {
		t.Run(name, func(t *testing.T) {
			a := policyTestApp(t)
			ctx := a.NewUncachedContext(true, tmproto.Header{}).WithHeaderInfo(header.Info{Height: 101})
			// The SDK's persisted done-key format is prefix, big-endian height, name.
			key := make([]byte, 9+len(name))
			key[0] = upgradetypes.DoneByte
			binary.BigEndian.PutUint64(key[1:9], 100)
			copy(key[9:], name)
			ctx.KVStore(a.GetKey(upgradetypes.StoreKey)).Set(key, []byte{1})
			before := module.VersionMap{"legacy-test-sentinel": 7}
			require.NoError(t, a.UpgradeKeeper.SetModuleVersionMap(ctx, before))
			response, err := upgrade.PreBlocker(ctx, a.UpgradeKeeper)
			require.NoError(t, err)
			require.False(t, response.IsConsensusParamsChanged())
			after, err := a.UpgradeKeeper.GetModuleVersionMap(ctx)
			require.NoError(t, err)
			require.Equal(t, before, after)
			completed, height, err := a.UpgradeKeeper.GetLastCompletedUpgrade(ctx)
			require.NoError(t, err)
			require.Equal(t, name, completed)
			require.EqualValues(t, 100, height)
			// Negative control: an unregistered completed plan must fail the same check.
			ctx.KVStore(a.GetKey(upgradetypes.StoreKey)).Delete(key)
			missingName := name + "-unregistered"
			missingKey := append(append([]byte{}, key[:9]...), []byte(missingName)...)
			ctx.KVStore(a.GetKey(upgradetypes.StoreKey)).Set(missingKey, []byte{1})
			a.UpgradeKeeper.SetDowngradeVerified(false)
			_, err = upgrade.PreBlocker(ctx, a.UpgradeKeeper)
			require.ErrorContains(t, err, "upgrade handler is missing for "+missingName)
		})
	}
}
