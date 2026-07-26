package cli

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/stretchr/testify/require"

	pqcauthclient "github.com/DoraFactory/doravota/x/pqcauth/client"
	pqccrypto "github.com/DoraFactory/doravota/x/pqcauth/crypto"
	"github.com/DoraFactory/doravota/x/pqcauth/types"
)

func TestOfflineKeygenAndRegistrationProof(t *testing.T) {
	privateKeyPath := filepath.Join(t.TempDir(), "account.mldsa65")
	var keygenOutput bytes.Buffer
	keygen := keygenCommand()
	keygen.SetOut(&keygenOutput)
	keygen.SetArgs([]string{privateKeyPath})
	require.NoError(t, keygen.Execute())

	info, err := os.Stat(privateKeyPath)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o600), info.Mode().Perm())
	var generated encodedKeyOutput
	require.NoError(t, json.Unmarshal(keygenOutput.Bytes(), &generated))
	publicKey, err := base64.StdEncoding.DecodeString(generated.PublicKey)
	require.NoError(t, err)
	privateKey, err := pqcauthclient.LoadPrivateKeyFile(privateKeyPath)
	require.NoError(t, err)
	derivedPublicKey, err := pqccrypto.MLDSA65PublicKeyFromPrivate(privateKey)
	require.NoError(t, err)
	require.Equal(t, publicKey, derivedPublicKey)

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
		"--chain-id", "pqc-cli-test-1",
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
