package v1_0_0

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"

	pqcauthtypes "github.com/DoraFactory/doravota/x/pqcauth/types"
	sponsortypes "github.com/DoraFactory/doravota/x/sponsor-contract-tx/types"
)

func TestStoreUpgradesAddsV100Stores(t *testing.T) {
	upgrades := StoreUpgrades()

	require.Equal(t, []string{sponsortypes.StoreKey, pqcauthtypes.StoreKey}, upgrades.Added)
	require.Empty(t, upgrades.Deleted)
	require.Empty(t, upgrades.Renamed)
}

func TestPQCNetworkIDIsStableAndNetworkSpecific(t *testing.T) {
	mainnet := PQCNetworkID("vota-ash")
	testnet := PQCNetworkID("vota-testnet")
	development := PQCNetworkID("local-rehearsal")

	require.Len(t, mainnet, 32)
	require.Equal(t, mainnet, PQCNetworkID("vota-ash"))
	require.False(t, bytes.Equal(mainnet, testnet))
	require.False(t, bytes.Equal(mainnet, development))
	require.False(t, bytes.Equal(testnet, development))
}
