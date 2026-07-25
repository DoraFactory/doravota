package v1_0_0

import (
	storetypes "github.com/cosmos/cosmos-sdk/store/types"

	sponsortypes "github.com/DoraFactory/doravota/x/sponsor-contract-tx/types"
)

// StoreUpgrades declares the Sponsor store introduced by the v1.0.0 upgrade.
func StoreUpgrades() storetypes.StoreUpgrades {
	return storetypes.StoreUpgrades{
		Added: []string{sponsortypes.StoreKey},
	}
}
