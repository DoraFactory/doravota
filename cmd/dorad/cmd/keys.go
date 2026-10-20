package cmd

import (
	"github.com/cosmos/cosmos-sdk/client/flags"
	"github.com/cosmos/cosmos-sdk/client/keys"
	"github.com/cosmos/cosmos-sdk/crypto/hd"
	"github.com/spf13/cobra"
)

const mlDSAMnemonicWarning = `WARNING: ML-DSA mnemonic safety
Use a fresh, dedicated mnemonic for a NEW ML-DSA account. Do not reuse a
mnemonic from a conventional account or import this mnemonic into a
non-PQC wallet such as Keplr.
With the same mnemonic, BIP39 passphrase and HD path, the current derivation
uses the secp256k1 private key as the ML-DSA seed. Exposure of that private
key compromises both accounts. Publishing the corresponding secp256k1
public key also creates a future quantum attack path to the ML-DSA account.
A conventional wallet derives a different address; it does not restore
your ML-DSA account.
Recovery is still allowed, including for a previously reused mnemonic,
so you can regain access and move assets to a fresh, dedicated account.
This warning does not change derivation or verify your mnemonic's history.
`

// Keep the SDK command and its validation/recovery behavior intact. Warn before
// mnemonic input without consuming stdin or contaminating machine-readable stdout.
func keysCommand() *cobra.Command {
	cmd := keys.Commands()
	for _, child := range cmd.Commands() {
		if child.Name() != "add" {
			continue
		}
		child.Long += "\n" + mlDSAMnemonicWarning
		run := child.RunE
		child.RunE = func(cmd *cobra.Command, args []string) error {
			algo, _ := cmd.Flags().GetString(flags.FlagKeyType)
			pubkey, _ := cmd.Flags().GetString(keys.FlagPublicKey)
			pubkeyBase64, _ := cmd.Flags().GetString("pubkey-base64")
			multisig, _ := cmd.Flags().GetStringSlice("multisig")
			ledger, _ := cmd.Flags().GetBool(flags.FlagUseLedger)
			if algo == string(hd.MlDsa65Type) && pubkey == "" && pubkeyBase64 == "" && len(multisig) == 0 && !ledger {
				cmd.PrintErr(mlDSAMnemonicWarning)
			}
			return run(cmd, args)
		}
	}
	return cmd
}
