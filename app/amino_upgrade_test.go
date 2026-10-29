package app_test

import (
	"testing"

	"cosmossdk.io/core/header"

	aminoUpgrade "github.com/DoraFactory/doravota/app/upgrades/amino"
	"github.com/DoraFactory/doravota/app/wasmarchive"
	abci "github.com/cometbft/cometbft/abci/types"
	tmproto "github.com/cometbft/cometbft/proto/tendermint/types"
	"github.com/cosmos/cosmos-sdk/types/module"
	upgradetypes "github.com/cosmos/cosmos-sdk/x/upgrade/types"
	"github.com/stretchr/testify/require"
)

func TestAminoUpgradeLifecycle(t *testing.T) {
	a := policyTestApp(t)
	ctx := a.NewContextLegacy(true, tmproto.Header{Height: 19})
	before := module.VersionMap{wasmarchive.GenesisKey: 1, "ibc": 9, "transfer": 7, "upgrade": 3, "sentinel": 23}
	require.NoError(t, a.UpgradeKeeper.SetModuleVersionMap(ctx, before))
	key := a.GetKey(upgradetypes.StoreKey)
	active, err := aminoUpgrade.IsActive(ctx, key)
	require.NoError(t, err)
	require.False(t, active)
	_, err = a.PreBlocker(ctx, &abci.RequestFinalizeBlock{Height: 19})
	require.ErrorContains(t, err, "activation required")
	plan := upgradetypes.Plan{Name: aminoUpgrade.UpgradeName, Height: 20}
	require.NoError(t, a.UpgradeKeeper.ScheduleUpgrade(ctx, plan))
	_, err = a.PreBlocker(ctx, &abci.RequestFinalizeBlock{Height: 19})
	require.ErrorContains(t, err, "activation required")
	ctx = ctx.WithBlockHeight(20).WithHeaderInfo(header.Info{Height: 20})
	// Apply through the real x/upgrade keeper: it invokes the registered handler,
	// persists completion, increments protocol metadata and clears the plan.
	require.NoError(t, a.UpgradeKeeper.ApplyUpgrade(ctx, plan))
	after, err := a.UpgradeKeeper.GetModuleVersionMap(ctx)
	require.NoError(t, err)
	require.Equal(t, before, after)
	h, err := a.UpgradeKeeper.GetDoneHeight(ctx, aminoUpgrade.UpgradeName)
	require.NoError(t, err)
	require.EqualValues(t, 20, h)
	active, err = aminoUpgrade.IsActive(ctx, key)
	require.NoError(t, err)
	require.True(t, active)
	_, err = a.UpgradeKeeper.GetUpgradePlan(ctx)
	require.Error(t, err)
	// The completion record is sufficient on a later block; no local halt file needed.
	active, err = aminoUpgrade.IsActive(ctx.WithBlockHeight(21), key)
	require.NoError(t, err)
	require.True(t, active)
}
