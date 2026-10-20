package cmd

import (
	"os"
	"strings"
	"testing"

	"github.com/cosmos/cosmos-sdk/version"
	"github.com/stretchr/testify/require"
)

func TestDefaultVersionMatchesReleaseFile(t *testing.T) {
	raw, err := os.ReadFile("../../../VERSION")
	require.NoError(t, err)
	require.Equal(t, strings.TrimSpace(string(raw)), Version)
	require.Regexp(t, `^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$`, Version)
}

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
