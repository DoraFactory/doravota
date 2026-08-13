package v1_0_0

import (
	"testing"

	"github.com/cosmos/cosmos-sdk/types/module"
	"github.com/stretchr/testify/require"
)

func TestValidateMigrationSourceAcceptsBridgeState(t *testing.T) {
	fromVM := module.VersionMap{}
	for name, version := range minimumMigrationSourceVersions {
		fromVM[name] = version
	}

	require.NoError(t, ValidateMigrationSource(fromVM))
}

func TestValidateMigrationSourceAcceptsNewerState(t *testing.T) {
	fromVM := module.VersionMap{}
	for name, version := range minimumMigrationSourceVersions {
		fromVM[name] = version + 1
	}

	require.NoError(t, ValidateMigrationSource(fromVM))
}

func TestValidateMigrationSourceRejectsDirectV047State(t *testing.T) {
	fromVM := module.VersionMap{
		"auth":               4,
		"bank":               4,
		"distribution":       3,
		"gov":                4,
		"group":              1,
		"ibc":                4,
		"interchainaccounts": 2,
		"mint":               2,
		"slashing":           4,
		"staking":            4,
		"transfer":           3,
		"wasm":               3,
	}

	err := ValidateMigrationSource(fromVM)
	require.ErrorContains(t, err, "first run the SDK v0.53 / IBC-Go v10 bridge upgrade")
	require.ErrorContains(t, err, "auth=4 (need >=5)")
	require.ErrorContains(t, err, "ibc=4 (need >=8)")
	require.ErrorContains(t, err, "wasm=3 (need >=4)")
}

func TestValidateMigrationSourceRejectsMissingRequiredModule(t *testing.T) {
	fromVM := module.VersionMap{}
	for name, version := range minimumMigrationSourceVersions {
		fromVM[name] = version
	}
	delete(fromVM, "group")

	err := ValidateMigrationSource(fromVM)
	require.ErrorContains(t, err, "group=missing (need >=2)")
}
