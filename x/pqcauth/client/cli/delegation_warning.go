package cli

import "github.com/spf13/cobra"

// Keep the warning offline-safe and off stdout (which may contain an unsigned
// transaction or bundle). Do not silently scan all grants on a public RPC or
// imply that a failed/partial query proves the absence of delegations.
func warnDelegationBoundary(command *cobra.Command, owner string) {
	command.PrintErrln("WARNING: PQCAuth protects direct signatures, not delegated authority. Existing and future Authz/Feegrant grants remain valid after enrollment and recovery. A compromised grantee can use the assets or fees allowed by its grants without your PQC signature.")
	command.PrintErrln("Delegations have NOT been queried or revoked. Review all pages and revoke unwanted grants yourself:")
	command.PrintErrf("  dorad query authz grants-by-granter %s\n", owner)
	command.PrintErrf("  dorad query feegrant grants-by-granter %s\n", owner)
	command.PrintErrln("Use the intended chain's node/height options. An RPC failure or one page of results is not proof that no grants exist.")
}
