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
const flagAcknowledgeIndependentFactors = "acknowledge-independent-factors"

func checkRegistrationBackend(cmd *cobra.Command, ctx client.Context) error {
	mode, err := cmd.Flags().GetString(flags.FlagSignMode)
	if err != nil {
		return err
	}
	if mode != "" && mode != "direct" {
		return fmt.Errorf("PQC registration and protected transactions require --sign-mode direct")
	}
	if ctx.Keyring != nil && ctx.GetFromName() != "" {
		record, err := ctx.Keyring.Key(ctx.GetFromName())
		if err != nil {
			return err
		}
		if record == nil {
			return fmt.Errorf("owner keyring record is missing")
		}
		if record.GetLedger() != nil {
			return fmt.Errorf("PQC registration is unsupported with this SDK's Amino-only Ledger backend; a DIRECT-capable signer with PQC extension support is required")
		}
	}
	return nil
}

func addFactorIndependenceFlag(cmd *cobra.Command) {
	cmd.Flags().Bool(flagAcknowledgeIndependentFactors, false, "Acknowledge that new PQC factors use separate dedicated mnemonics when owner-key independence cannot be checked (Ledger/watch-only/offline)")
}

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
		acknowledged, _ := cmd.Flags().GetBool(flagAcknowledgeIndependentFactors)
		if !acknowledged {
			return fmt.Errorf("owner private key unavailable locally (Ledger/watch-only/offline); cannot check mnemonic independence: use fresh dedicated PQC signing and recovery mnemonics, never import the Ledger mnemonic, and explicitly pass --%s to continue; this acknowledgement does not prove independence", flagAcknowledgeIndependentFactors)
		}
		cmd.PrintErrln("WARNING: owner-key independence was NOT verified. You acknowledged separate dedicated PQC mnemonics. Never import a Ledger mnemonic to create PQC factors.")
	}
	cmd.PrintErrln("Use separate dedicated mnemonics for PQC signing and recovery. This local check cannot detect reuse with other wallets or derivation paths.")
	return nil
}
