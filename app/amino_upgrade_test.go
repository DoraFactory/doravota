package app_test

import (
	"encoding/binary"
	"testing"

	"cosmossdk.io/core/header"
	"github.com/DoraFactory/doravota/app"
	aminoUpgrade "github.com/DoraFactory/doravota/app/upgrades/amino"
	pqctypes "github.com/DoraFactory/doravota/x/pqcauth/types"
	abci "github.com/cometbft/cometbft/abci/types"
	tmproto "github.com/cometbft/cometbft/proto/tendermint/types"
	upgradetypes "github.com/cosmos/cosmos-sdk/x/upgrade/types"
	"github.com/stretchr/testify/require"
)

func aminoDoneKey(height uint64) []byte {
	key := make([]byte, 9+len(aminoUpgrade.UpgradeName))
	key[0] = upgradetypes.DoneByte
	binary.BigEndian.PutUint64(key[1:9], height)
	copy(key[9:], aminoUpgrade.UpgradeName)
	return key
}

// Successor binaries recognize historical completion without rerunning the
// historical migration with a different store layout.
func TestAminoUpgradeLifecycle(t *testing.T) {
	c := newPQCChain(t)
	a := c.app
	ctx := a.NewNextBlockContext(tmproto.Header{ChainID: "policy-test", Height: 20}).WithHeaderInfo(header.Info{Height: 20})
	store := ctx.KVStore(a.GetKey(upgradetypes.StoreKey))
	store.Delete([]byte("vota/amino-compat/genesis/v1.0.1"))
	before, err := a.UpgradeKeeper.GetModuleVersionMap(ctx)
	require.NoError(t, err)
	require.ErrorContains(t, a.UpgradeKeeper.ApplyUpgrade(ctx, upgradetypes.Plan{Name: aminoUpgrade.UpgradeName, Height: 20}), "released binary")
	after, err := a.UpgradeKeeper.GetModuleVersionMap(ctx)
	require.NoError(t, err)
	require.Equal(t, before, after)
	active, err := aminoUpgrade.IsActive(ctx, a.GetKey(upgradetypes.StoreKey))
	require.NoError(t, err)
	require.False(t, active)
	_, err = a.PreBlocker(ctx, &abci.RequestFinalizeBlock{Height: 20})
	require.ErrorContains(t, err, "v1.0.1 activation required")
	store.Set(aminoDoneKey(10), []byte{1})
	active, err = aminoUpgrade.IsActive(ctx, a.GetKey(upgradetypes.StoreKey))
	require.NoError(t, err)
	require.True(t, active)
	_, err = a.PreBlocker(ctx, &abci.RequestFinalizeBlock{Height: 20})
	require.NoError(t, err)
}

func TestPQCAuthRequiresV101Activation(t *testing.T) {
	for _, tc := range []struct {
		name           string
		done           uint64
		genesis, valid bool
	}{
		{"missing prerequisite", 0, false, false},
		{"future completion", 21, false, false},
		{"completed v1.0.1", 10, false, true},
		{"fresh v1.0.1 signing rules", 0, true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := newPQCChain(t)
			a := c.app
			ctx := a.NewNextBlockContext(tmproto.Header{ChainID: "policy-test", Height: 20}).WithHeaderInfo(header.Info{Height: 20})
			store := ctx.KVStore(a.GetKey(upgradetypes.StoreKey))
			if !tc.genesis {
				store.Delete([]byte("vota/amino-compat/genesis/v1.0.1"))
			}
			if tc.done != 0 {
				store.Set(aminoDoneKey(tc.done), []byte{1})
			}
			store.Delete(append([]byte{upgradetypes.VersionMapByte}, []byte(pqctypes.ModuleName)...))
			before, err := a.UpgradeKeeper.GetModuleVersionMap(ctx)
			require.NoError(t, err)
			plan := upgradetypes.Plan{Name: app.PQCAuthUpgradeName, Height: 20}
			// A correct PQCAuth plan cannot substitute for the v1.0.1 prerequisite.
			require.NoError(t, a.UpgradeKeeper.ScheduleUpgrade(ctx.WithBlockHeight(19), plan))
			if !tc.valid {
				_, err = a.PreBlocker(ctx, &abci.RequestFinalizeBlock{Height: 20})
				require.ErrorContains(t, err, "v1.0.1 activation required")
				require.ErrorContains(t, a.UpgradeKeeper.ApplyUpgrade(ctx, plan), "requires activated v1.0.1")
				after, err := a.UpgradeKeeper.GetModuleVersionMap(ctx)
				require.NoError(t, err)
				require.Equal(t, before, after)
				return
			}
			_, err = a.PreBlocker(ctx, &abci.RequestFinalizeBlock{Height: 20})
			require.NoError(t, err)
			after, err := a.UpgradeKeeper.GetModuleVersionMap(ctx)
			require.NoError(t, err)
			require.NotZero(t, after[pqctypes.ModuleName])
			done, err := a.UpgradeKeeper.GetDoneHeight(ctx, app.PQCAuthUpgradeName)
			require.NoError(t, err)
			require.EqualValues(t, 20, done)
		})
	}
}
