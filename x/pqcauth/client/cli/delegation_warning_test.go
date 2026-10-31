package cli

import (
	"bytes"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/require"
)

func TestDelegationWarningDoesNotPolluteTransactionOutput(t *testing.T) {
	var stdout, stderr bytes.Buffer
	cmd := &cobra.Command{}
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)
	warnDelegationBoundary(cmd, "test-owner")
	require.Empty(t, stdout.String())
	for _, text := range []string{"WARNING", "Authz/Feegrant", "NOT been queried or revoked", "query authz grants-by-granter test-owner", "query feegrant grants-by-granter test-owner", "all pages", "without your PQC signature"} {
		require.Contains(t, stderr.String(), text)
	}
}
