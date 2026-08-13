package cmd

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNewRootCmdBuildsModuleCommands(t *testing.T) {
	root, _ := NewRootCmd()
	require.NotNil(t, root)

	for _, path := range [][]string{
		{"version"},
		{"tx", "bank"},
		{"tx", "staking"},
		{"tx", "distribution"},
		{"tx", "upgrade"},
		{"tx", "vesting"},
		{"tx", "group"},
		{"tx", "pqcauth"},
	} {
		command, _, err := root.Find(path)
		require.NoError(t, err, "resolve command %v", path)
		require.Equal(t, path[len(path)-1], command.Name(), "resolve command %v", path)
	}
}
