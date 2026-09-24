package cmd

import (
	"encoding/json"

	"github.com/DoraFactory/doravota/app"
	"github.com/cosmos/cosmos-sdk/version"
	"github.com/spf13/cobra"
)

// Reports build-time coordination values without opening a node DB or writing
// client/server config. It does not assert that PIE or ASLR is enabled.
func releaseInfoCmd() *cobra.Command {
	return &cobra.Command{
		Use: "release-info", Short: "Print the embedded release settings",
		Args:              cobra.NoArgs,
		PersistentPreRunE: func(*cobra.Command, []string) error { return nil },
		RunE: func(cmd *cobra.Command, _ []string) error {
			return json.NewEncoder(cmd.OutOrStdout()).Encode(struct {
				Version string `json:"version"`
				Commit  string `json:"commit"`
				ChainID string `json:"chain_id"`
				Height  string `json:"activation_height"`
			}{app.MaintenanceVersion, version.Commit, app.MaintenanceChainID, app.MaintenanceHeight})
		},
	}
}
