package cli

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	pqcclient "github.com/DoraFactory/doravota/x/pqcauth/client"
	pqccrypto "github.com/DoraFactory/doravota/x/pqcauth/crypto"
	"github.com/DoraFactory/doravota/x/pqcauth/types"
	"github.com/cosmos/cosmos-sdk/crypto/keyring"
	"github.com/cosmos/cosmos-sdk/crypto/keys/mldsa65"
	"github.com/cosmos/cosmos-sdk/crypto/keys/secp256k1"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/cosmos/cosmos-sdk/types/tx/signing"
	"github.com/stretchr/testify/require"
)

func TestSignBundleRotationTargetGuard(t *testing.T) {
	var output bytes.Buffer
	ctx := cliTestClientContext(t, &output)
	keys := keyring.NewInMemory(ctx.Codec)
	ctx = ctx.WithKeyring(keys)
	classical := secp256k1.GenPrivKey().PubKey()
	owner := sdk.AccAddress(classical.Address()).String()
	currentPublic, currentPrivate, err := pqccrypto.GenerateMLDSA65Key(nil)
	require.NoError(t, err)
	defer clear(currentPrivate)
	trustedPublic, trustedPrivate, err := pqccrypto.GenerateMLDSA65Key(nil)
	require.NoError(t, err)
	defer clear(trustedPrivate)
	attackerPublic, attackerPrivate, err := pqccrypto.GenerateMLDSA65Key(nil)
	require.NoError(t, err)
	defer clear(attackerPrivate)
	_, err = keys.SaveOfflineKey("trusted", &mldsa65.PubKey{Key: trustedPublic})
	require.NoError(t, err)
	_, err = keys.SaveOfflineKey("classic", classical)
	require.NoError(t, err)
	dir := t.TempDir()
	privatePath := filepath.Join(dir, "current.key")
	require.NoError(t, os.WriteFile(privatePath, currentPrivate, 0o600))
	expected := pqcclient.PublicKeySHA256(trustedPublic)

	build := func(recovery, attacker bool) []byte {
		pub, priv := trustedPublic, trustedPrivate
		if attacker {
			pub, priv = attackerPublic, attackerPrivate
		}
		role, purpose, domain := types.KeyRole_KEY_ROLE_SIGNING, types.PurposeRotateSigning, types.RotateProofContext
		if recovery {
			role, purpose, domain = types.KeyRole_KEY_ROLE_RECOVERY, types.PurposeRotateRecovery, types.RotateRecoveryContext
		}
		proofDoc, err := types.MarshalKeyProofDocV1(types.KeyProofDocV1{FormatVersion: 1,
			NetworkId: types.DefaultParams().NetworkId, ChainId: "rotation-cli-test", Owner: owner,
			ProposedKeyId: 3, Algorithm: types.Algorithm_ALGORITHM_ML_DSA_65, PublicKey: pub,
			Role: role, Purpose: purpose, CurrentPolicyVersion: 1})
		require.NoError(t, err)
		proof, err := pqccrypto.SignMLDSA65(priv, proofDoc, []byte(domain), true)
		require.NoError(t, err)
		var msg sdk.Msg = &types.MsgRotateKey{Owner: owner, ExpectedNewKeyId: 3, NewAlgorithm: types.Algorithm_ALGORITHM_ML_DSA_65, NewPublicKey: pub, NewKeyProof: proof}
		if recovery {
			msg = &types.MsgRotateRecoveryKey{Owner: owner, ExpectedNewKeyId: 3, NewAlgorithm: types.Algorithm_ALGORITHM_ML_DSA_65, NewPublicKey: pub, NewKeyProof: proof}
		}
		b := ctx.TxConfig.NewTxBuilder()
		require.NoError(t, b.SetMsgs(msg))
		b.SetGasLimit(300000)
		require.NoError(t, b.SetSignatures(signing.SignatureV2{PubKey: classical, Sequence: 8,
			Data: &signing.SingleSignatureData{SignMode: signing.SignMode_SIGN_MODE_DIRECT}}))
		doc, err := types.NewPQCSignDocV1(b.GetTx().(cliProtoTxProvider).GetProtoTx(), types.DefaultParams().NetworkId,
			"rotation-cli-test", 7, 8, 0, owner, 1, types.Algorithm_ALGORITHM_ML_DSA_65, 1)
		require.NoError(t, err)
		signBytes, err := types.MarshalPQCSignDocV1(doc)
		require.NoError(t, err)
		raw, err := ctx.TxConfig.TxEncoder()(b.GetTx())
		require.NoError(t, err)
		txHash, docHash := sha256.Sum256(raw), sha256.Sum256(signBytes)
		encoded, err := pqcclient.MarshalPQCSignBundle(ctx.TxConfig, &pqcclient.PQCSignBundleV1{
			Format: pqcclient.PQCSignBundleFormatV1, UnsignedTx: raw, UnsignedTxSHA256: txHash[:],
			SignDoc: signBytes, SignDocSHA256: docHash[:], OnChainPublicKey: currentPublic}, false)
		require.NoError(t, err)
		return encoded
	}
	for _, recovery := range []bool{false, true} {
		operation, role := "rotate-key", "signing"
		if recovery {
			operation, role = "rotate-recovery-key", "recovery"
		}
		t.Run(operation, func(t *testing.T) {
			honestPath, swappedPath := filepath.Join(t.TempDir(), "honest.json"), filepath.Join(t.TempDir(), "swapped.json")
			require.NoError(t, os.WriteFile(honestPath, build(recovery, false), 0o600))
			require.NoError(t, os.WriteFile(swappedPath, build(recovery, true), 0o600))
			for _, tc := range []struct {
				name  string
				path  string
				flags []string
				want  string
			}{
				{"missing", honestPath, nil, "provide exactly one"},
				{"short", honestPath, []string{"--expect-new-key-sha256", "abcd"}, "full 64-character"},
				{"malformed", honestPath, []string{"--expect-new-key-sha256", strings.Repeat("z", 64)}, "full 64-character"},
				{"unknown key", honestPath, []string{"--expect-new-key", "missing"}, "load expected"},
				{"classic key", honestPath, []string{"--expect-new-key", "classic"}, "ml_dsa_65"},
				{"both", honestPath, []string{"--expect-new-key", "trusted", "--expect-new-key-sha256", expected}, "provide exactly one"},
				{"substitution hash", swappedPath, []string{"--expect-new-key-sha256", expected}, "does not match"},
				{"substitution key", swappedPath, []string{"--expect-new-key", "trusted"}, "does not match"},
			} {
				t.Run(tc.name, func(t *testing.T) {
					for _, yes := range []bool{false, true} {
						cmd := signBundleCommand()
						cmd.SetContext(attachClientContext(context.Background(), &ctx))
						cmd.SetErr(&bytes.Buffer{})
						cmd.SetOut(&bytes.Buffer{})
						cmd.SetIn(strings.NewReader("y\n"))
						out := filepath.Join(t.TempDir(), "must-not-exist.json")
						args := append([]string{tc.path, "missing-current-private-key", out, "--legacy-key-file"}, tc.flags...)
						if yes {
							args = append(args, "--yes")
						}
						cmd.SetArgs(args)
						require.ErrorContains(t, cmd.Execute(), tc.want)
						_, err := os.Stat(out)
						require.True(t, os.IsNotExist(err))
					}
				})
			}
			for _, local := range []bool{false, true} {
				cmd := signBundleCommand()
				cmd.SetContext(attachClientContext(context.Background(), &ctx))
				var review, result bytes.Buffer
				cmd.SetErr(&review)
				cmd.SetOut(&result)
				cmd.SetIn(strings.NewReader("y\n"))
				out := filepath.Join(t.TempDir(), "signed.json")
				args := []string{honestPath, privatePath, out, "--legacy-key-file"}
				if local {
					args = append(args, "--expect-new-key", "trusted")
				} else {
					args = append(args, "--expect-new-key-sha256", strings.ToUpper(expected), "--yes")
				}
				cmd.SetArgs(args)
				require.NoError(t, cmd.Execute())
				if local {
					require.Contains(t, review.String(), "key_change_operation: "+operation)
					require.Contains(t, review.String(), "new_key_role: "+role)
					require.Contains(t, review.String(), "new_public_key_sha256: "+expected)
				}
				var decoded bundleCommandResult
				require.NoError(t, json.Unmarshal(result.Bytes(), &decoded))
				require.Equal(t, operation, decoded.KeyChange.Operation)
				require.Equal(t, role, decoded.KeyChange.Role)
				require.Equal(t, expected, decoded.KeyChange.PublicKeySHA256)
				signed, err := os.ReadFile(out)
				require.NoError(t, err)
				_, summary, err := pqcclient.UnmarshalPQCSignBundle(ctx.TxConfig, signed, true)
				require.NoError(t, err)
				require.True(t, summary.Signed)
			}
		})
	}
}
