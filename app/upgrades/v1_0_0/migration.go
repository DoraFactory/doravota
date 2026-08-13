package v1_0_0

import (
	"fmt"
	"sort"
	"strings"

	"github.com/cosmos/cosmos-sdk/types/module"
)

// minimumMigrationSourceVersions is the state boundary supported by the
// v1.0.0 (SDK v0.55) binary. A production v0.47 chain must first run an
// intermediate SDK v0.53 / IBC-Go v10 upgrade, which brings these modules to
// the versions below and performs migrations that no longer exist in v0.55.
//
// This check is deliberately independent from the target module versions: it
// protects historical state migrations, not just whether RunMigrations can
// find a syntactically valid next migration.
var minimumMigrationSourceVersions = module.VersionMap{
	"auth":               5,
	"bank":               4,
	"distribution":       3,
	"gov":                5,
	"group":              2,
	"ibc":                8,
	"interchainaccounts": 3,
	"mint":               2,
	"slashing":           4,
	"staking":            5,
	"transfer":           6,
	"wasm":               4,
}

// ValidateMigrationSource rejects unsupported direct upgrades before any
// module migration or PQC state initialization is attempted. In particular,
// v0.47 state must never be handed directly to the SDK v0.55 migration code.
func ValidateMigrationSource(fromVM module.VersionMap) error {
	var incompatible []string
	for name, minimum := range minimumMigrationSourceVersions {
		actual, ok := fromVM[name]
		if !ok {
			incompatible = append(incompatible, fmt.Sprintf("%s=missing (need >=%d)", name, minimum))
			continue
		}
		if actual < minimum {
			incompatible = append(incompatible, fmt.Sprintf("%s=%d (need >=%d)", name, actual, minimum))
		}
	}

	if len(incompatible) == 0 {
		return nil
	}
	sort.Strings(incompatible)
	return fmt.Errorf(
		"unsupported v1.0.0 migration source; first run the SDK v0.53 / IBC-Go v10 bridge upgrade: %s",
		strings.Join(incompatible, ", "),
	)
}
