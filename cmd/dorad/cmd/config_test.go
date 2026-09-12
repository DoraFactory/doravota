package cmd

import (
	"testing"

	"github.com/cosmos/cosmos-sdk/version"
	"github.com/stretchr/testify/require"
)

func TestSetVersionInfoPreservesReleaseIdentity(t *testing.T) {
	oldName, oldAppName, oldVersion := version.Name, version.AppName, version.Version
	t.Cleanup(func() { version.Name, version.AppName, version.Version = oldName, oldAppName, oldVersion })
	version.Version = "bridge-release-candidate"
	setVersionInfo()
	require.Equal(t, "bridge-release-candidate", version.Version)
	version.Version = ""
	setVersionInfo()
	require.Equal(t, Version, version.Version)
}
