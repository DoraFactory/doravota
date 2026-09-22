package app_test

import (
	upgradetypes "cosmossdk.io/x/upgrade/types"
	tmproto "github.com/cometbft/cometbft/proto/tendermint/types"
	"github.com/cosmos/cosmos-sdk/types/module"
	"github.com/stretchr/testify/require"
	"testing"
)

func Test051RejectsAlreadyMigratedSource(t *testing.T) {
	a := policyTestApp(t)
	ctx := a.NewUncachedContext(true, tmproto.Header{Height: 10})
	newer := module.VersionMap{"auth": 5, "bank": 4, "ibc": 8}
	require.NoError(t, a.UpgradeKeeper.SetModuleVersionMap(ctx, newer))
	err := a.UpgradeKeeper.ApplyUpgrade(ctx, upgradetypes.Plan{Name: "0.5.1", Height: 10})
	require.ErrorContains(t, err, "unsupported source module")
	after, err := a.UpgradeKeeper.GetModuleVersionMap(ctx)
	require.NoError(t, err)
	require.Equal(t, newer, after)
}
func Test051DoesNotExecutePublished050Plan(t *testing.T) {
	a := policyTestApp(t)
	ctx := a.NewUncachedContext(true, tmproto.Header{Height: 10})
	require.NoError(t, a.UpgradeKeeper.SetModuleVersionMap(ctx, module.VersionMap{}))
	err := a.UpgradeKeeper.ApplyUpgrade(ctx, upgradetypes.Plan{Name: "0.5.0", Height: 10})
	require.ErrorContains(t, err, "use plan 0.5.1")
}
