package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cosmos/cosmos-sdk/client"
	"github.com/cosmos/cosmos-sdk/crypto/hd"
	"github.com/cosmos/cosmos-sdk/crypto/keyring"
	sdk "github.com/cosmos/cosmos-sdk/types"
	moduletestutil "github.com/cosmos/cosmos-sdk/types/module/testutil"
	"github.com/stretchr/testify/require"
)

func TestMLDSAMnemonicWarning(t *testing.T) {
	// Public test fixture only; never use it for funds.
	const mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
	for _, tc := range []struct {
		name, input     string
		flags           []string
		warn, recovered bool
	}{
		{"create", "", []string{"--key-type", "ml_dsa_65"}, true, false},
		{"recover", mnemonic + "\n", []string{"--key-type", "ml_dsa_65", "--recover"}, true, true},
		{"legacy-alias", mnemonic + "\n", []string{"--algo", "ml_dsa_65", "--recover"}, true, true},
		{"interactive", mnemonic + "\n\n", []string{"--key-type", "ml_dsa_65", "--interactive"}, true, true},
		{"source", "", []string{"--key-type", "ml_dsa_65", "--recover", "--source", "FIXTURE"}, true, true},
		{"secp256k1", mnemonic + "\n", []string{"--recover"}, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			home := t.TempDir()
			input := strings.NewReader(tc.input)
			cdc := moduletestutil.MakeTestEncodingConfig().Codec
			kb, err := keyring.New(sdk.KeyringServiceName(), keyring.BackendTest, home, input, cdc)
			require.NoError(t, err)
			clientCtx := client.Context{}.WithKeyring(kb).WithKeyringDir(home).WithInput(input).WithCodec(cdc)
			ctx := context.WithValue(context.Background(), client.ClientContextKey, &clientCtx)
			cmd := keysCommand()
			var stdout, stderr bytes.Buffer
			cmd.SetOut(&stdout)
			cmd.SetErr(&stderr)
			args := append([]string{"add", "fixture", "--keyring-backend", "test", "--keyring-dir", home, "--output", "json", "--no-backup"}, tc.flags...)
			for i := range args {
				if args[i] == "FIXTURE" {
					path := filepath.Join(home, "mnemonic.txt")
					require.NoError(t, os.WriteFile(path, []byte(mnemonic), 0600))
					args[i] = path
				}
			}
			cmd.SetArgs(args)
			require.NoError(t, cmd.ExecuteContext(ctx))
			require.Equal(t, tc.warn, strings.Contains(stderr.String(), "WARNING: ML-DSA mnemonic safety"))
			require.True(t, json.Valid(stdout.Bytes()), "warning must not corrupt JSON stdout")
			require.NotContains(t, stdout.String(), mnemonic)
			require.NotContains(t, stderr.String(), mnemonic)
			record, err := kb.Key("fixture")
			require.NoError(t, err)
			pub, err := record.GetPubKey()
			require.NoError(t, err)
			if tc.warn {
				require.Equal(t, "ml_dsa_65", pub.Type())
			} else {
				require.Equal(t, "secp256k1", pub.Type())
			}
			if tc.recovered {
				// Compare recovery against the unchanged SDK derivation.
				algo := hd.Secp256k1
				seed, err := algo.Derive()(mnemonic, "", hd.CreateHDPath(sdk.GetConfig().GetCoinType(), 0, 0).String())
				require.NoError(t, err)
				want := algo.Generate()(seed).PubKey()
				if tc.warn {
					want = hd.MlDsa65.Generate()(seed).PubKey()
				}
				require.Equal(t, want.Bytes(), pub.Bytes())
				require.Equal(t, want.Address(), pub.Address())
			}
		})
	}
}
