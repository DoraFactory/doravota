package app_test

import (
	"testing"

	upgradetypes "cosmossdk.io/x/upgrade/types"
	tmproto "github.com/cometbft/cometbft/proto/tendermint/types"
	"github.com/cosmos/cosmos-sdk/types/module"
	"github.com/stretchr/testify/require"
)

func TestRecoveryKeepsOriginalPlanName(t *testing.T) {
	a := policyTestApp(t)
	require.True(t, a.UpgradeKeeper.HasHandler("0.5.0"))
	require.False(t, a.UpgradeKeeper.HasHandler("0.5.1"))
	require.False(t, a.UpgradeKeeper.HasHandler("0.5.0-fee-recovery.1"))
}
func TestRecoveryRejectsAlreadyUpgradedSource(t *testing.T) {
	a := policyTestApp(t)
	ctx := a.NewUncachedContext(true, tmproto.Header{Height: 10})
	newer := module.VersionMap{"auth": 5, "bank": 4, "ibc": 8}
	require.NoError(t, a.UpgradeKeeper.SetModuleVersionMap(ctx, newer))
	require.ErrorContains(t, a.UpgradeKeeper.ApplyUpgrade(ctx, upgradetypes.Plan{Name: "0.5.0", Height: 10}), "unsupported source module")
	after, err := a.UpgradeKeeper.GetModuleVersionMap(ctx)
	require.NoError(t, err)
	require.Equal(t, newer, after)
}
