package cli

import (
	"bytes"
	"testing"

	"github.com/cosmos/cosmos-sdk/client"
	"github.com/cosmos/cosmos-sdk/crypto/hd"
	"github.com/cosmos/cosmos-sdk/crypto/keyring"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/require"
)

type externalOwnerKeyring struct {
	keyring.Keyring
	owner *keyring.Record
}

func (k externalOwnerKeyring) Key(name string) (*keyring.Record, error) {
	if name == "owner" {
		return k.owner, nil
	}
	return k.Keyring.Key(name)
}

// Hardware transport is deliberately not involved: the failure boundary is a
// keyring record with no exportable private key, exactly as with a Ledger.
func TestNewFactorAcknowledgementForExternalOwners(t *testing.T) {
	var output bytes.Buffer
	ctx := cliTestClientContext(t, &output)
	keys := keyring.NewInMemory(ctx.Codec)
	owner, mnemonic, err := keys.NewMnemonic("owner", keyring.English, sdk.FullFundraiserPath, "", hd.Secp256k1)
	require.NoError(t, err)
	pub, err := owner.GetPubKey()
	require.NoError(t, err)
	coupled, err := keys.NewAccount("coupled", mnemonic, "", sdk.FullFundraiserPath, hd.MlDsa65)
	require.NoError(t, err)
	bad, err := coupled.GetPubKey()
	require.NoError(t, err)
	factor, _, err := keys.NewMnemonic("factor", keyring.English, sdk.FullFundraiserPath, "", hd.MlDsa65)
	require.NoError(t, err)
	good, err := factor.GetPubKey()
	require.NoError(t, err)
	watch, err := keys.SaveOfflineKey("watch", pub)
	require.NoError(t, err)
	ledger, err := keyring.NewLedgerRecord("owner", pub, hd.NewFundraiserParams(0, sdk.CoinType, 0))
	require.NoError(t, err)
	for _, makeCmd := range []func() *cobra.Command{registerKeyCommand, rotateKeyCommand, rotateRecoveryKeyCommand, recoverKeyCommand} {
		cmd := makeCmd()
		t.Run(cmd.Name(), func(t *testing.T) {
			for label, record := range map[string]*keyring.Record{"watch": watch, "ledger": ledger} {
				t.Run(label, func(t *testing.T) {
					cmd := makeCmd()
					cmd.SetErr(&output)
					external := ctx.WithKeyring(externalOwnerKeyring{keys, record}).WithFromName("owner")
					require.ErrorContains(t, checkNewFactors(cmd, external, good.Bytes()), "--acknowledge-independent-factors")
					require.NoError(t, cmd.Flags().Set(flagAcknowledgeIndependentFactors, "true"))
					require.NoError(t, checkNewFactors(cmd, external, good.Bytes()))
					require.Contains(t, output.String(), "NOT verified")
				})
			}
			local := ctx.WithKeyring(keys).WithFromName("owner")
			require.NoError(t, checkNewFactors(cmd, local, good.Bytes()))
			require.NoError(t, cmd.Flags().Set(flagAcknowledgeIndependentFactors, "true"))
			// The flag never overrides a detected unsafe factor, including recovery.
			require.ErrorContains(t, checkNewFactors(cmd, local, bad.Bytes()), "unsafe PQC factor")
			require.ErrorContains(t, checkNewFactors(cmd, local, good.Bytes(), bad.Bytes()), "unsafe PQC factor")
			require.Error(t, checkNewFactors(cmd, ctx.WithKeyring(keys).WithFromName("missing"), good.Bytes()))
		})
	}
	// Context without owner/keyring is also explicitly uncheckable, not safe.
	require.ErrorContains(t, checkNewFactors(registerKeyCommand(), client.Context{}, good.Bytes()), "--acknowledge-independent-factors")
}
