package client

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	sdkclient "github.com/cosmos/cosmos-sdk/client"
	sdktx "github.com/cosmos/cosmos-sdk/client/tx"
	"github.com/cosmos/cosmos-sdk/codec"
	codectypes "github.com/cosmos/cosmos-sdk/codec/types"
	"github.com/cosmos/cosmos-sdk/crypto/keyring"
	"github.com/cosmos/cosmos-sdk/crypto/keys/secp256k1"
	sdk "github.com/cosmos/cosmos-sdk/types"
	txsigning "github.com/cosmos/cosmos-sdk/types/tx/signing"
	banktypes "github.com/cosmos/cosmos-sdk/x/bank/types"
	"github.com/stretchr/testify/require"

	pqccrypto "github.com/DoraFactory/doravota/x/pqcauth/crypto"
	"github.com/DoraFactory/doravota/x/pqcauth/types"
)

func TestLoadPrivateKeyFileChecksDescriptorPermissionsAndSize(t *testing.T) {
	_, privateKey, err := pqccrypto.GenerateMLDSA65Key(nil)
	require.NoError(t, err)

	path := filepath.Join(t.TempDir(), "account.mldsa65")
	require.NoError(t, os.WriteFile(path, privateKey, 0o600))
	loaded, err := LoadPrivateKeyFile(path)
	require.NoError(t, err)
	require.Equal(t, privateKey, loaded)

	require.NoError(t, os.Chmod(path, 0o644))
	_, err = LoadPrivateKeyFile(path)
	require.ErrorContains(t, err, "permissions")

	require.NoError(t, os.Chmod(path, 0o600))
	require.NoError(t, os.WriteFile(path, privateKey[:len(privateKey)-1], 0o600))
	_, err = LoadPrivateKeyFile(path)
	require.ErrorContains(t, err, "length")

	_, err = LoadPrivateKeyFile(filepath.Join(t.TempDir(), "missing"))
	require.ErrorContains(t, err, "open PQC private key file")
	_, err = LoadPrivateKeyFile(t.TempDir())
	require.ErrorContains(t, err, "regular file")

	require.NoError(t, os.WriteFile(path, append(privateKey, 0x01), 0o600))
	_, err = LoadPrivateKeyFile(path)
	require.ErrorContains(t, err, "length")
}

func TestLocalMLDSA65SignerImplementsTransportBoundary(t *testing.T) {
	publicKey, privateKey, err := pqccrypto.GenerateMLDSA65Key(nil)
	require.NoError(t, err)
	signer := localMLDSA65Signer{privateKey: privateKey}
	require.Equal(t, types.Algorithm_ALGORITHM_ML_DSA_65, signer.Algorithm())

	derived, err := signer.PublicKey(context.Background())
	require.NoError(t, err)
	require.Equal(t, publicKey, derived)

	message := []byte("remote-signer-boundary")
	signature, err := signer.Sign(context.Background(), message, []byte(types.TxSignatureContext))
	require.NoError(t, err)
	require.NoError(t, pqccrypto.Verify(
		pqccrypto.AlgorithmMLDSA65,
		publicKey,
		message,
		[]byte(types.TxSignatureContext),
		signature,
	))

	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = signer.PublicKey(cancelled)
	require.ErrorIs(t, err, context.Canceled)
	_, err = signer.Sign(cancelled, message, []byte(types.TxSignatureContext))
	require.ErrorIs(t, err, context.Canceled)
}

func TestBuildPQCAuthSimulationExtensionUsesStateBoundPlaceholder(t *testing.T) {
	registry := testInterfaceRegistry()
	cdc := codec.NewProtoCodec(registry)
	signer := sdk.AccAddress(bytes.Repeat([]byte{0x71}, 20))
	publicKey, _, err := pqccrypto.GenerateMLDSA65Key(nil)
	require.NoError(t, err)
	queryServer := &mutableBundleQueryServer{
		account: types.QueryAccountResponse{
			Policy: types.AccountPolicy{
				Owner:               signer.String(),
				CurrentSigningKeyId: 7,
				PolicyVersion:       3,
				SelfEnforced:        true,
			},
			ActiveSigningKey: &types.PQCKeyRecord{
				Owner:     signer.String(),
				KeyId:     7,
				Algorithm: types.Algorithm_ALGORITHM_ML_DSA_65,
				PublicKey: publicKey,
				Role:      types.KeyRole_KEY_ROLE_SIGNING,
				Status:    types.KeyStatus_KEY_STATUS_LIVE,
			},
		},
		params: types.QueryParamsResponse{
			Params:                   types.DefaultParams(),
			EffectiveEnforcementMode: types.EnforcementMode_ENFORCEMENT_MODE_REQUIRED_FOR_REGISTERED,
			EffectiveEmergencyMode:   types.EmergencyMode_EMERGENCY_MODE_NORMAL,
		},
	}
	connection := startBundleQueryServer(t, queryServer)
	clientCtx := sdkclient.Context{}.
		WithCodec(cdc).
		WithInterfaceRegistry(registry).
		WithFromAddress(signer).
		WithGRPCClient(connection)

	extensionAny, err := BuildPQCAuthSimulationExtension(
		context.Background(),
		clientCtx,
	)
	require.NoError(t, err)
	require.Equal(t, types.ExtensionPQCAuthTypeURL, extensionAny.TypeUrl)
	extension, ok := extensionAny.GetCachedValue().(*types.ExtensionPQCAuth)
	require.True(t, ok)
	require.Equal(t, types.FormatVersionV1, extension.FormatVersion)
	require.Len(t, extension.Signatures, 1)
	entry := extension.Signatures[0]
	require.Equal(t, signer.String(), entry.Signer)
	require.Equal(t, uint64(7), entry.KeyId)
	require.Equal(t, uint64(3), entry.PolicyVersion)
	require.Equal(t, types.Algorithm_ALGORITHM_ML_DSA_65, entry.Algorithm)
	algorithm, err := types.CryptoAlgorithm(entry.Algorithm)
	require.NoError(t, err)
	_, signatureSize, err := pqccrypto.Sizes(algorithm)
	require.NoError(t, err)
	require.Len(t, entry.Signature, signatureSize)
	require.Equal(t, make([]byte, signatureSize), entry.Signature)
}

func TestBuildPQCAuthSimulationExtensionRejectsUnavailablePolicyState(t *testing.T) {
	registry := testInterfaceRegistry()
	cdc := codec.NewProtoCodec(registry)
	signer := sdk.AccAddress(bytes.Repeat([]byte{0x72}, 20))
	queryServer := &mutableBundleQueryServer{
		params: types.QueryParamsResponse{
			Params:                 types.DefaultParams(),
			EffectiveEmergencyMode: types.EmergencyMode_EMERGENCY_MODE_NORMAL,
		},
	}
	connection := startBundleQueryServer(t, queryServer)
	clientCtx := sdkclient.Context{}.
		WithCodec(cdc).
		WithInterfaceRegistry(registry).
		WithGRPCClient(connection)

	_, err := BuildPQCAuthSimulationExtension(context.Background(), clientCtx)
	require.ErrorContains(t, err, "signer address is required")

	clientCtx = clientCtx.WithFromAddress(signer)
	_, err = BuildPQCAuthSimulationExtension(context.Background(), clientCtx)
	require.ErrorIs(t, err, types.ErrKeyNotFound)

	publicKey, _, err := pqccrypto.GenerateMLDSA65Key(nil)
	require.NoError(t, err)
	queryServer.account = types.QueryAccountResponse{
		Policy: types.AccountPolicy{
			Owner:               signer.String(),
			CurrentSigningKeyId: 1,
			PolicyVersion:       1,
		},
		ActiveSigningKey: &types.PQCKeyRecord{
			Owner:     signer.String(),
			KeyId:     1,
			Algorithm: types.Algorithm_ALGORITHM_ML_DSA_65,
			PublicKey: publicKey,
		},
	}
	queryServer.params.EffectiveEmergencyMode =
		types.EmergencyMode_EMERGENCY_MODE_PAUSE_PQC_TRANSACTIONS
	_, err = BuildPQCAuthSimulationExtension(context.Background(), clientCtx)
	require.ErrorIs(t, err, types.ErrEmergencyPause)

	queryServer.params.EffectiveEmergencyMode =
		types.EmergencyMode_EMERGENCY_MODE_NORMAL
	queryServer.account.ActiveSigningKey.Algorithm = types.Algorithm(99)
	_, err = BuildPQCAuthSimulationExtension(context.Background(), clientCtx)
	require.ErrorIs(t, err, types.ErrUnsupportedAlgorithm)
}

type wrongAlgorithmSigner struct{}

func (wrongAlgorithmSigner) Algorithm() types.Algorithm { return types.Algorithm(99) }
func (wrongAlgorithmSigner) PublicKey(context.Context) ([]byte, error) {
	return nil, errors.New("must not be called")
}
func (wrongAlgorithmSigner) Sign(context.Context, []byte, []byte) ([]byte, error) {
	return nil, errors.New("must not be called")
}

func TestAttachPQCAuthSignerBoundarySuccessAndFailures(t *testing.T) {
	registry := testInterfaceRegistry()
	cdc := codec.NewProtoCodec(registry)
	classicalPrivateKey := secp256k1.GenPrivKey()
	classicalPublicKey := classicalPrivateKey.PubKey()
	signer := sdk.AccAddress(classicalPublicKey.Address())
	keyringBackend := keyring.NewInMemory(cdc)
	_, err := keyringBackend.SaveOfflineKey("alice", classicalPublicKey)
	require.NoError(t, err)
	pqcPublicKey, pqcPrivateKey, err := pqccrypto.GenerateMLDSA65Key(nil)
	require.NoError(t, err)
	defer clear(pqcPrivateKey)

	queryServer := &mutableBundleQueryServer{
		account: types.QueryAccountResponse{
			Policy: types.AccountPolicy{
				Owner:               signer.String(),
				CurrentSigningKeyId: 9,
				PolicyVersion:       4,
				SelfEnforced:        true,
			},
			ActiveSigningKey: &types.PQCKeyRecord{
				Owner:     signer.String(),
				KeyId:     9,
				Algorithm: types.Algorithm_ALGORITHM_ML_DSA_65,
				PublicKey: pqcPublicKey,
				Role:      types.KeyRole_KEY_ROLE_SIGNING,
				Status:    types.KeyStatus_KEY_STATUS_LIVE,
			},
		},
		params: types.QueryParamsResponse{
			Params:                 types.DefaultParams(),
			EffectiveEmergencyMode: types.EmergencyMode_EMERGENCY_MODE_NORMAL,
		},
	}
	connection := startBundleQueryServer(t, queryServer)
	txConfig := testTxConfig()
	clientCtx := sdkclient.Context{}.
		WithCodec(cdc).
		WithInterfaceRegistry(registry).
		WithTxConfig(txConfig).
		WithKeyring(keyringBackend).
		WithFromName("alice").
		WithFromAddress(signer).
		WithChainID("pqc-sign-online-test-1").
		WithGRPCClient(connection)
	txf := sdktx.Factory{}.
		WithTxConfig(txConfig).
		WithKeybase(keyringBackend).
		WithFromName("alice").
		WithChainID(clientCtx.ChainID).
		WithAccountNumber(23).
		WithSequence(17).
		WithSignMode(txsigning.SignMode_SIGN_MODE_DIRECT)
	newBuilder := func() sdkclient.TxBuilder {
		builder := txConfig.NewTxBuilder()
		require.NoError(t, builder.SetMsgs(banktypes.NewMsgSend(
			signer,
			sdk.AccAddress(make([]byte, 20)),
			sdk.NewCoins(sdk.NewInt64Coin("udora", 1)),
		)))
		builder.SetGasLimit(200_000)
		return builder
	}

	builder := newBuilder()
	require.NoError(t, AttachPQCAuth(clientCtx, txf, builder, pqcPrivateKey))
	provider := builder.GetTx().(protoTxProvider)
	require.Len(t, provider.GetProtoTx().Body.ExtensionOptions, 1)

	builderWithExistingExtension := newBuilder()
	existingExtension := &codectypes.Any{
		TypeUrl: "/example.security.v1.RequiredExtension",
		Value:   []byte{0x01},
	}
	builderWithExistingExtension.(sdkclient.ExtendedTxBuilder).SetExtensionOptions(
		existingExtension,
	)
	require.NoError(t, AttachPQCAuth(
		clientCtx,
		txf,
		builderWithExistingExtension,
		pqcPrivateKey,
	))
	provider = builderWithExistingExtension.GetTx().(protoTxProvider)
	require.Len(t, provider.GetProtoTx().Body.ExtensionOptions, 2)
	require.Equal(t, existingExtension, provider.GetProtoTx().Body.ExtensionOptions[0])
	require.Equal(
		t,
		types.ExtensionPQCAuthTypeURL,
		provider.GetProtoTx().Body.ExtensionOptions[1].TypeUrl,
	)

	err = AttachPQCAuthWithSigner(
		context.Background(),
		clientCtx,
		txf,
		newBuilder(),
		nil,
	)
	require.ErrorContains(t, err, "PQC signer is required")
	err = AttachPQCAuthWithSigner(
		context.Background(),
		clientCtx,
		txf,
		newBuilder(),
		wrongAlgorithmSigner{},
	)
	require.ErrorContains(t, err, "does not match active on-chain algorithm")

	wrongPublicKey, wrongPrivateKey, err := pqccrypto.GenerateMLDSA65Key(nil)
	require.NoError(t, err)
	err = AttachPQCAuthWithSigner(
		context.Background(),
		clientCtx,
		txf,
		newBuilder(),
		&recordingBundleSigner{
			publicKey:  wrongPublicKey,
			privateKey: wrongPrivateKey,
		},
	)
	require.ErrorContains(t, err, "does not match active on-chain key")

	err = AttachPQCAuthWithSigner(
		context.Background(),
		clientCtx,
		txf,
		newBuilder(),
		&recordingBundleSigner{
			publicKey:        pqcPublicKey,
			privateKey:       pqcPrivateKey,
			corruptSignature: true,
		},
	)
	require.ErrorContains(t, err, "returned an invalid signature")
}
