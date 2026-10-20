package cli

import (
	"fmt"

	pqcauthclient "github.com/DoraFactory/doravota/x/pqcauth/client"
	"github.com/cosmos/cosmos-sdk/client"
	"github.com/cosmos/cosmos-sdk/client/flags"
	"github.com/spf13/cobra"
)

const flagPQCKey = "pqc-key"
const flagRecoveryKey = "recovery-key"
const flagLegacyKeyFile = "legacy-key-file"

func selectedSigner(ctx client.Context, keyName, legacyPath string) (pqcauthclient.PQCSigner, func(), error) {
	if keyName != "" && legacyPath != "" {
		return nil, func() {}, fmt.Errorf("choose a keyring key or a legacy key file, not both")
	}
	if keyName != "" {
		s, err := pqcauthclient.NewKeyringSigner(ctx.Keyring, keyName)
		return s, func() {}, err
	}
	if legacyPath != "" {
		return pqcauthclient.NewLegacyFileSigner(legacyPath)
	}
	return nil, func() {}, fmt.Errorf("an ML-DSA keyring key is required")
}
func offlineSigner(cmd *cobra.Command, name string) (pqcauthclient.PQCSigner, func(), error) {
	ctx, err := client.GetClientQueryContext(cmd)
	if err != nil {
		return nil, func() {}, err
	}
	legacy, _ := cmd.Flags().GetBool(flagLegacyKeyFile)
	if legacy {
		return selectedSigner(ctx, "", name)
	}
	return selectedSigner(ctx, name, "")
}
func addOfflineKeyFlags(cmd *cobra.Command) {
	cmd.Flags().Bool(flagLegacyKeyFile, false, "Interpret the key argument as an old raw private-key file (recovery compatibility only)")
	cmd.Flags().String(flags.FlagKeyringBackend, "os", "Keyring backend")
	cmd.Flags().String(flags.FlagKeyringDir, "", "Keyring directory")
}

// Check only newly introduced factors. Legacy factors must remain usable to
// authorize recovery/rotation away from an unsafe mnemonic.
func checkNewFactors(cmd *cobra.Command, ctx client.Context, publicKeys ...[]byte) error {
	checked, err := pqcauthclient.CheckFactorIndependence(ctx.Keyring, ctx.GetFromName(), publicKeys...)
	if err != nil {
		return err
	}
	if !checked {
		cmd.PrintErrln("WARNING: owner key unavailable locally; mnemonic independence could not be checked.")
	}
	cmd.PrintErrln("Use separate dedicated mnemonics for PQC signing and recovery. This local check cannot detect reuse with other wallets or derivation paths.")
	return nil
}
