package v1_0_0

import (
	"testing"

	"github.com/stretchr/testify/require"

	sponsortypes "github.com/DoraFactory/doravota/x/sponsor-contract-tx/types"
)

func TestStoreUpgradesAddsSponsorStore(t *testing.T) {
	upgrades := StoreUpgrades()

	require.Equal(t, []string{sponsortypes.StoreKey}, upgrades.Added)
	require.Empty(t, upgrades.Deleted)
	require.Empty(t, upgrades.Renamed)
}
