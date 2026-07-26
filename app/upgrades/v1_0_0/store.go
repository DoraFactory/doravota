package v1_0_0

import (
	"crypto/sha256"

	storetypes "github.com/cosmos/cosmos-sdk/store/types"

	pqcauthtypes "github.com/DoraFactory/doravota/x/pqcauth/types"
	sponsortypes "github.com/DoraFactory/doravota/x/sponsor-contract-tx/types"
)

// PQCNetworkID commits a launch-specific network identity into the v1.0.0
// binary. Mainnet and public testnet deliberately use separate launch domains;
// custom rehearsal chains receive a chain-specific development identity.
func PQCNetworkID(chainID string) []byte {
	launchDomain := "development/" + chainID
	switch chainID {
	case "vota-ash":
		launchDomain = "mainnet/vota-ash/launch-2026-07"
	case "vota-testnet":
		launchDomain = "testnet/vota-testnet/launch-2026-07"
	}
	sum := sha256.Sum256([]byte("doravota/pqcauth/network/v1/" + launchDomain))
	return append([]byte(nil), sum[:]...)
}

// StoreUpgrades declares the stores introduced by the v1.0.0 upgrade.
func StoreUpgrades() storetypes.StoreUpgrades {
	return storetypes.StoreUpgrades{
		Added: []string{sponsortypes.StoreKey, pqcauthtypes.StoreKey},
	}
}
