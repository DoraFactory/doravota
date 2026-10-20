package cli

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"github.com/cosmos/cosmos-sdk/crypto/hd"
	"github.com/cosmos/cosmos-sdk/crypto/keyring"
	"os"
	"path/filepath"
	"testing"

	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/stretchr/testify/require"

	pqccrypto "github.com/DoraFactory/doravota/x/pqcauth/crypto"
	"github.com/DoraFactory/doravota/x/pqcauth/types"
)

func TestLegacyOfflineRegistrationProof(t *testing.T) {
	privateKeyPath := filepath.Join(t.TempDir(), "legacy.key")
	publicKey, privateKey, err := pqccrypto.GenerateMLDSA65Key(nil)
	require.NoError(t, err)
	defer clear(privateKey)
	require.NoError(t, os.WriteFile(privateKeyPath, privateKey, 0o600))

	owner := sdk.AccAddress(bytes.Repeat([]byte{0x33}, 20)).String()
	params := types.DefaultParams()
	var proofOutput bytes.Buffer
	proofCommand := createKeyProofCommand()
	proofCommand.SetOut(&proofOutput)
	proofCommand.SetArgs([]string{
		privateKeyPath,
		owner,
		"1",
		"signing",
		types.PurposeRegisterSigning,
		"--network-id-base64", base64.StdEncoding.EncodeToString(params.NetworkId),
		"--chain-id", "pqc-cli-test-1", "--legacy-key-file", "--keyring-backend", "test",
	})
	require.NoError(t, proofCommand.Execute())

	var proofResult encodedKeyOutput
	require.NoError(t, json.Unmarshal(proofOutput.Bytes(), &proofResult))
	proof, err := base64.StdEncoding.DecodeString(proofResult.Proof)
	require.NoError(t, err)
	signBytes, err := types.MarshalKeyProofDocV1(types.KeyProofDocV1{
		FormatVersion: types.FormatVersionV1,
		NetworkId:     params.NetworkId,
		ChainId:       "pqc-cli-test-1",
		Owner:         owner,
		ProposedKeyId: 1,
		Algorithm:     types.Algorithm_ALGORITHM_ML_DSA_65,
		PublicKey:     publicKey,
		Role:          types.KeyRole_KEY_ROLE_SIGNING,
		Purpose:       types.PurposeRegisterSigning,
	})
	require.NoError(t, err)
	require.NoError(t, pqccrypto.Verify(
		pqccrypto.AlgorithmMLDSA65,
		publicKey,
		signBytes,
		[]byte(types.RegisterProofContext),
		proof,
	))
}

func TestRotateRecoveryProofUsesDedicatedContext(t *testing.T) {
	context, err := proofContext(types.PurposeRotateRecovery, types.KeyRole_KEY_ROLE_RECOVERY)
	require.NoError(t, err)
	require.Equal(t, []byte(types.RotateRecoveryContext), context)

	_, err = proofContext(types.PurposeRotateRecovery, types.KeyRole_KEY_ROLE_SIGNING)
	require.Error(t, err)
}

func TestWriteNewFileAtomicUsesRestrictedPermissionsAndRefusesOverwrite(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bundle.json")
	require.NoError(t, writeNewFileAtomic(path, []byte("first"), 0o600))
	info, err := os.Stat(path)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o600), info.Mode().Perm())
	contents, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Equal(t, []byte("first"), contents)

	err = writeNewFileAtomic(path, []byte("replacement"), 0o600)
	require.ErrorContains(t, err, "without overwrite")
	contents, err = os.ReadFile(path)
	require.NoError(t, err)
	require.Equal(t, []byte("first"), contents)
}

func TestSDKKeyringOfflineProofAndRegistrationGuard(t *testing.T) {
	var output bytes.Buffer
	ctx := cliTestClientContext(t, &output)
	keys := keyring.NewInMemory(ctx.Codec)
	ownerRecord, mnemonic, err := keys.NewMnemonic("owner", keyring.English, sdk.FullFundraiserPath, "", hd.Secp256k1)
	require.NoError(t, err)
	ownerPub, err := ownerRecord.GetPubKey()
	require.NoError(t, err)
	coupled, err := keys.NewAccount("coupled", mnemonic, "", sdk.FullFundraiserPath, hd.MlDsa65)
	require.NoError(t, err)
	coupledPub, err := coupled.GetPubKey()
	require.NoError(t, err)
	ctx = ctx.WithKeyring(keys).WithFromName("owner").WithFromAddress(sdk.AccAddress(ownerPub.Address()))
	for _, name := range []string{"signing", "recovery"} {
		rec, _, err := keys.NewMnemonic(name, keyring.English, sdk.FullFundraiserPath, "", hd.MlDsa65)
		require.NoError(t, err)
		pub, err := rec.GetPubKey()
		require.NoError(t, err)
		output.Reset()
		cmd := createKeyProofCommand()
		cmd.SetOut(&output)
		cmd.SetContext(attachClientContext(context.Background(), &ctx))
		purpose := types.PurposeRegisterSigning
		role := types.KeyRole_KEY_ROLE_SIGNING
		if name == "recovery" {
			purpose = types.PurposeRegisterRecovery
			role = types.KeyRole_KEY_ROLE_RECOVERY
		}
		params := types.DefaultParams()
		cmd.SetArgs([]string{name, ctx.GetFromAddress().String(), "1", name, purpose, "--network-id-base64", base64.StdEncoding.EncodeToString(params.NetworkId), "--chain-id", "cli-keyring"})
		require.NoError(t, cmd.Execute())
		var result encodedKeyOutput
		require.NoError(t, json.Unmarshal(output.Bytes(), &result))
		signature, err := base64.StdEncoding.DecodeString(result.Proof)
		require.NoError(t, err)
		doc, err := types.MarshalKeyProofDocV1(types.KeyProofDocV1{FormatVersion: 1, NetworkId: params.NetworkId, ChainId: "cli-keyring", Owner: ctx.GetFromAddress().String(), ProposedKeyId: 1, Algorithm: types.Algorithm_ALGORITHM_ML_DSA_65, PublicKey: pub.Bytes(), Role: role, Purpose: purpose})
		require.NoError(t, err)
		require.NoError(t, pqccrypto.Verify(pqccrypto.AlgorithmMLDSA65, pub.Bytes(), doc, []byte(types.RegisterProofContext), signature))
		require.NoError(t, checkNewFactors(cmd, ctx, pub.Bytes()))
		require.ErrorContains(t, checkNewFactors(cmd, ctx, coupledPub.Bytes()), "unsafe PQC factor")
	}
	// Prohibit accidentally falling back to the old keygen command.
	_, _, err = GetTxCmd().Find([]string{"keygen"})
	require.ErrorContains(t, err, "unknown command")
}
