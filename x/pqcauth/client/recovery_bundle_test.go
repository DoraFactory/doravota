package client

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"testing"

	sdkclient "github.com/cosmos/cosmos-sdk/client"
	sdktx "github.com/cosmos/cosmos-sdk/client/tx"
	"github.com/cosmos/cosmos-sdk/codec"
	"github.com/cosmos/cosmos-sdk/crypto/keyring"
	"github.com/cosmos/cosmos-sdk/crypto/keys/secp256k1"
	sdk "github.com/cosmos/cosmos-sdk/types"
	txsigning "github.com/cosmos/cosmos-sdk/types/tx/signing"
	"github.com/stretchr/testify/require"

	pqccrypto "github.com/DoraFactory/doravota/x/pqcauth/crypto"
	"github.com/DoraFactory/doravota/x/pqcauth/types"
)

func TestRecoverySignBundleOfflineRoundTripAndTransactionTamperRejection(t *testing.T) {
	txConfig := testTxConfig()
	bundle, recoveryPrivateKey := testUnsignedRecoveryBundle(t, txConfig)
	defer clear(recoveryPrivateKey)

	summary, err := ValidateRecoverySignBundle(txConfig, bundle, false)
	require.NoError(t, err)
	require.False(t, summary.Signed)
	require.Equal(t, uint64(2), summary.RecoveryKeyID)

	encoded, err := MarshalRecoverySignBundle(txConfig, bundle, false)
	require.NoError(t, err)
	decoded, _, err := UnmarshalRecoverySignBundle(txConfig, encoded, false)
	require.NoError(t, err)
	signed, signedSummary, err := SignRecoverySignBundleWithPrivateKey(
		context.Background(),
		txConfig,
		decoded,
		recoveryPrivateKey,
	)
	require.NoError(t, err)
	require.True(t, signedSummary.Signed)
	require.Empty(t, decoded.RecoverySignature)
	_, err = MarshalRecoverySignBundle(txConfig, signed, true)
	require.NoError(t, err)

	tamperedSignature := cloneRecoverySignBundle(signed)
	tamperedSignature.RecoverySignature[0] ^= 1
	_, err = ValidateRecoverySignBundle(txConfig, tamperedSignature, true)
	require.ErrorContains(t, err, "invalid bundled recovery signature")

	for _, testCase := range []struct {
		name   string
		mutate func(sdkclient.TxBuilder)
	}{
		{
			name: "fee",
			mutate: func(builder sdkclient.TxBuilder) {
				builder.SetFeeAmount(sdk.NewCoins(sdk.NewInt64Coin("peaka", 1)))
			},
		},
		{
			name: "gas",
			mutate: func(builder sdkclient.TxBuilder) {
				builder.SetGasLimit(200_001)
			},
		},
		{
			name: "memo",
			mutate: func(builder sdkclient.TxBuilder) {
				builder.SetMemo("tampered")
			},
		},
		{
			name: "timeout",
			mutate: func(builder sdkclient.TxBuilder) {
				builder.SetTimeoutHeight(99)
			},
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			tampered := cloneRecoverySignBundle(bundle)
			decodedTx, err := txConfig.TxDecoder()(tampered.UnsignedTx)
			require.NoError(t, err)
			builder, err := txConfig.WrapTxBuilder(decodedTx)
			require.NoError(t, err)
			testCase.mutate(builder)
			tampered.UnsignedTx, err = txConfig.TxEncoder()(builder.GetTx())
			require.NoError(t, err)
			txHash := sha256.Sum256(tampered.UnsignedTx)
			tampered.UnsignedTxSHA256 = txHash[:]
			_, err = ValidateRecoverySignBundle(txConfig, tampered, false)
			require.ErrorContains(t, err, "does not match bundled transaction")
		})
	}
}

func TestRecoverySignBundleOnlinePrepareAttachAndStalePolicy(t *testing.T) {
	txConfig := testTxConfig()
	registry := testInterfaceRegistry()
	cdc := codec.NewProtoCodec(registry)
	classicalPrivateKey := secp256k1.GenPrivKey()
	classicalPublicKey := classicalPrivateKey.PubKey()
	signer := sdk.AccAddress(classicalPublicKey.Address())
	keyringBackend := keyring.NewInMemory(cdc)
	_, err := keyringBackend.SaveOfflineKey("alice", classicalPublicKey)
	require.NoError(t, err)

	recoveryPublicKey, recoveryPrivateKey, err := pqccrypto.GenerateMLDSA65Key(nil)
	require.NoError(t, err)
	defer clear(recoveryPrivateKey)
	newPublicKey, _, err := pqccrypto.GenerateMLDSA65Key(nil)
	require.NoError(t, err)
	_, signatureSize, err := pqccrypto.Sizes(pqccrypto.AlgorithmMLDSA65)
	require.NoError(t, err)

	queryServer := &mutableBundleQueryServer{
		account: types.QueryAccountResponse{Policy: types.AccountPolicy{
			Owner:               signer.String(),
			CurrentSigningKeyId: 1,
			RecoveryKeyId:       2,
			PolicyVersion:       4,
			SelfEnforced:        true,
		}},
		key: types.PQCKeyRecord{
			Owner:     signer.String(),
			KeyId:     2,
			Algorithm: types.Algorithm_ALGORITHM_ML_DSA_65,
			PublicKey: recoveryPublicKey,
			Role:      types.KeyRole_KEY_ROLE_RECOVERY,
			Status:    types.KeyStatus_KEY_STATUS_LIVE,
		},
		params: types.QueryParamsResponse{
			Params:                 types.DefaultParams(),
			EffectiveEmergencyMode: types.EmergencyMode_EMERGENCY_MODE_NORMAL,
		},
	}
	connection := startBundleQueryServer(t, queryServer)
	clientCtx := sdkclient.Context{}.
		WithCodec(cdc).
		WithInterfaceRegistry(registry).
		WithTxConfig(txConfig).
		WithKeyring(keyringBackend).
		WithFromName("alice").
		WithFromAddress(signer).
		WithChainID("pqc-recovery-bundle-online-test-1").
		WithGRPCClient(connection)
	txf := sdktx.Factory{}.
		WithTxConfig(txConfig).
		WithKeybase(keyringBackend).
		WithFromName("alice").
		WithChainID(clientCtx.ChainID).
		WithAccountNumber(23).
		WithSequence(17).
		WithSignMode(txsigning.SignMode_SIGN_MODE_DIRECT)
	builder := txConfig.NewTxBuilder()
	require.NoError(t, builder.SetMsgs(&types.MsgRecoverKey{
		Owner:                   signer.String(),
		RecoveryKeyId:           2,
		RecoverySignature:       make([]byte, signatureSize),
		ExpectedNewSigningKeyId: 3,
		NewSigningAlgorithm:     types.Algorithm_ALGORITHM_ML_DSA_65,
		NewSigningPublicKey:     newPublicKey,
		NewSigningKeyProof:      make([]byte, signatureSize),
	}))
	builder.SetGasLimit(200_000)

	bundle, _, err := PrepareRecoverySignBundle(
		context.Background(),
		clientCtx,
		txf,
		builder,
	)
	require.NoError(t, err)
	signed, _, err := SignRecoverySignBundleWithPrivateKey(
		context.Background(),
		txConfig,
		bundle,
		recoveryPrivateKey,
	)
	require.NoError(t, err)
	queryServer.setEmergencyMode(
		types.EmergencyMode_EMERGENCY_MODE_PAUSE_PQC_TRANSACTIONS,
	)
	finalBuilder, _, err := AttachRecoverySignBundle(
		context.Background(),
		clientCtx,
		txf,
		signed,
	)
	require.NoError(t, err)
	message, err := recoveryMessageFromTx(finalBuilder.GetTx())
	require.NoError(t, err)
	require.Equal(t, signed.RecoverySignature, message.RecoverySignature)

	queryServer.setPolicyVersion(5)
	_, _, err = AttachRecoverySignBundle(
		context.Background(),
		clientCtx,
		txf,
		signed,
	)
	require.ErrorContains(t, err, "stale")
}

func testUnsignedRecoveryBundle(
	t testing.TB,
	txConfig sdkclient.TxConfig,
) (*RecoverySignBundleV1, []byte) {
	t.Helper()
	classicalPublicKey := secp256k1.GenPrivKey().PubKey()
	signer := sdk.AccAddress(classicalPublicKey.Address())
	recoveryPublicKey, recoveryPrivateKey, err := pqccrypto.GenerateMLDSA65Key(nil)
	require.NoError(t, err)
	newPublicKey, _, err := pqccrypto.GenerateMLDSA65Key(nil)
	require.NoError(t, err)
	_, signatureSize, err := pqccrypto.Sizes(pqccrypto.AlgorithmMLDSA65)
	require.NoError(t, err)
	builder := txConfig.NewTxBuilder()
	require.NoError(t, builder.SetMsgs(&types.MsgRecoverKey{
		Owner:                   signer.String(),
		RecoveryKeyId:           2,
		RecoverySignature:       make([]byte, signatureSize),
		ExpectedNewSigningKeyId: 3,
		NewSigningAlgorithm:     types.Algorithm_ALGORITHM_ML_DSA_65,
		NewSigningPublicKey:     newPublicKey,
		NewSigningKeyProof:      make([]byte, signatureSize),
	}))
	builder.SetGasLimit(200_000)
	require.NoError(t, builder.SetSignatures(txsigning.SignatureV2{
		PubKey: classicalPublicKey,
		Data: &txsigning.SingleSignatureData{
			SignMode: txsigning.SignMode_SIGN_MODE_DIRECT,
		},
		Sequence: 17,
	}))
	provider := builder.GetTx().(protoTxProvider)
	params := types.DefaultParams()
	signDoc, err := types.NewRecoverySignDocV1(
		provider.GetProtoTx(),
		params.NetworkId,
		"pqc-recovery-bundle-test-1",
		23,
		17,
		0,
		signer.String(),
		signer.String(),
		2,
		3,
		types.Algorithm_ALGORITHM_ML_DSA_65,
		newPublicKey,
		4,
	)
	require.NoError(t, err)
	signBytes, err := types.MarshalRecoverySignDocV1(signDoc)
	require.NoError(t, err)
	unsignedTx, err := txConfig.TxEncoder()(builder.GetTx())
	require.NoError(t, err)
	txHash := sha256.Sum256(unsignedTx)
	signDocHash := sha256.Sum256(signBytes)
	return &RecoverySignBundleV1{
		Format:                   RecoverySignBundleFormatV1,
		UnsignedTx:               unsignedTx,
		UnsignedTxSHA256:         txHash[:],
		SignDoc:                  signBytes,
		SignDocSHA256:            signDocHash[:],
		RecoveryAlgorithm:        types.Algorithm_ALGORITHM_ML_DSA_65,
		OnChainRecoveryPublicKey: recoveryPublicKey,
	}, recoveryPrivateKey
}

func TestRecoveryCanonicalizationClearsOnlyEmbeddedSignature(t *testing.T) {
	txConfig := testTxConfig()
	bundle, privateKey := testUnsignedRecoveryBundle(t, txConfig)
	defer clear(privateKey)
	decodedTx, err := txConfig.TxDecoder()(bundle.UnsignedTx)
	require.NoError(t, err)
	provider := decodedTx.(protoTxProvider)
	before, err := types.CanonicalRecoveryBodyBytes(provider.GetProtoTx())
	require.NoError(t, err)
	message, err := recoveryMessageFromTx(decodedTx)
	require.NoError(t, err)
	message.RecoverySignature = bytes.Repeat([]byte{0x42}, len(message.RecoverySignature))
	builder, err := txConfig.WrapTxBuilder(decodedTx)
	require.NoError(t, err)
	require.NoError(t, builder.SetMsgs(message))
	afterProvider := builder.GetTx().(protoTxProvider)
	after, err := types.CanonicalRecoveryBodyBytes(afterProvider.GetProtoTx())
	require.NoError(t, err)
	require.Equal(t, before, after)
}

func TestRecoverySignBundleValidationFailureMatrix(t *testing.T) {
	txConfig := testTxConfig()
	valid, privateKey := testUnsignedRecoveryBundle(t, txConfig)
	defer clear(privateKey)

	_, err := ValidateRecoverySignBundle(nil, valid, false)
	require.ErrorContains(t, err, "transaction config is required")
	_, err = ValidateRecoverySignBundle(txConfig, nil, false)
	require.ErrorContains(t, err, "recovery sign bundle is required")

	testCases := []struct {
		name   string
		mutate func(*RecoverySignBundleV1)
		want   string
	}{
		{
			name: "format",
			mutate: func(bundle *RecoverySignBundleV1) {
				bundle.Format = "future"
			},
			want: "unsupported recovery sign bundle format",
		},
		{
			name: "empty unsigned transaction",
			mutate: func(bundle *RecoverySignBundleV1) {
				bundle.UnsignedTx = nil
			},
			want: "unsigned recovery transaction length",
		},
		{
			name: "empty sign document",
			mutate: func(bundle *RecoverySignBundleV1) {
				bundle.SignDoc = nil
			},
			want: "recovery sign document length",
		},
		{
			name: "transaction hash",
			mutate: func(bundle *RecoverySignBundleV1) {
				bundle.UnsignedTxSHA256[0] ^= 1
			},
			want: "recovery transaction SHA-256 mismatch",
		},
		{
			name: "sign document hash",
			mutate: func(bundle *RecoverySignBundleV1) {
				bundle.SignDocSHA256[0] ^= 1
			},
			want: "recovery sign document SHA-256 mismatch",
		},
		{
			name: "malformed sign document",
			mutate: func(bundle *RecoverySignBundleV1) {
				bundle.SignDoc = []byte{0xff}
				hash := sha256.Sum256(bundle.SignDoc)
				bundle.SignDocSHA256 = hash[:]
			},
			want: "decode bundled recovery sign document",
		},
		{
			name: "wrong signer index",
			mutate: func(bundle *RecoverySignBundleV1) {
				mutateRecoveryBundleSignDoc(t, bundle, func(doc *types.RecoverySignDocV1) {
					doc.SignerIndex = 1
				})
			},
			want: "owner at signer index 0",
		},
		{
			name: "signer differs from owner",
			mutate: func(bundle *RecoverySignBundleV1) {
				mutateRecoveryBundleSignDoc(t, bundle, func(doc *types.RecoverySignDocV1) {
					doc.Signer = sdk.AccAddress(bytes.Repeat([]byte{0x94}, 20)).String()
				})
			},
			want: "owner at signer index 0",
		},
		{
			name: "invalid signer",
			mutate: func(bundle *RecoverySignBundleV1) {
				mutateRecoveryBundleSignDoc(t, bundle, func(doc *types.RecoverySignDocV1) {
					doc.Signer = "not-an-address"
					doc.Owner = "not-an-address"
				})
			},
			want: "recovery signer address is invalid",
		},
		{
			name: "malformed unsigned transaction",
			mutate: func(bundle *RecoverySignBundleV1) {
				bundle.UnsignedTx = []byte{0xff}
				hash := sha256.Sum256(bundle.UnsignedTx)
				bundle.UnsignedTxSHA256 = hash[:]
			},
			want: "decode bundled recovery transaction",
		},
		{
			name: "message mismatch",
			mutate: func(bundle *RecoverySignBundleV1) {
				mutateRecoveryBundleSignDoc(t, bundle, func(doc *types.RecoverySignDocV1) {
					doc.ProposedSigningKeyId++
				})
			},
			want: "message does not match sign document",
		},
		{
			name: "sequence mismatch",
			mutate: func(bundle *RecoverySignBundleV1) {
				mutateRecoveryBundleSignDoc(t, bundle, func(doc *types.RecoverySignDocV1) {
					doc.Sequence++
				})
			},
			want: "signer sequence does not match",
		},
		{
			name: "unsupported recovery algorithm",
			mutate: func(bundle *RecoverySignBundleV1) {
				bundle.RecoveryAlgorithm = types.Algorithm(99)
			},
			want: "unsupported PQC algorithm",
		},
		{
			name: "public key length",
			mutate: func(bundle *RecoverySignBundleV1) {
				bundle.OnChainRecoveryPublicKey = bundle.OnChainRecoveryPublicKey[:1]
			},
			want: "recovery public key length",
		},
		{
			name: "signature length",
			mutate: func(bundle *RecoverySignBundleV1) {
				bundle.RecoverySignature = []byte{1}
			},
			want: "recovery signature length",
		},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			bundle := cloneRecoverySignBundle(valid)
			testCase.mutate(bundle)
			_, err := ValidateRecoverySignBundle(txConfig, bundle, false)
			require.ErrorContains(t, err, testCase.want)
		})
	}

	_, err = ValidateRecoverySignBundle(txConfig, valid, true)
	require.ErrorContains(t, err, "has no signature")
	require.Nil(t, cloneRecoverySignBundle(nil))
}

func TestRecoverySignBundleSignerFailureMatrix(t *testing.T) {
	txConfig := testTxConfig()
	bundle, privateKey := testUnsignedRecoveryBundle(t, txConfig)
	defer clear(privateKey)

	_, _, err := SignRecoverySignBundle(context.Background(), txConfig, bundle, nil)
	require.ErrorContains(t, err, "recovery signer is required")
	_, _, err = SignRecoverySignBundle(
		context.Background(),
		txConfig,
		nil,
		&recordingBundleSigner{},
	)
	require.ErrorContains(t, err, "recovery sign bundle is required")

	wrongAlgorithm := &recordingBundleSigner{
		algorithm:  types.Algorithm(99),
		publicKey:  bundle.OnChainRecoveryPublicKey,
		privateKey: privateKey,
	}
	_, _, err = SignRecoverySignBundle(
		context.Background(),
		txConfig,
		bundle,
		wrongAlgorithm,
	)
	require.ErrorContains(t, err, "does not match bundle algorithm")

	publicKeyFailure := errors.New("recovery key unavailable")
	_, _, err = SignRecoverySignBundle(
		context.Background(),
		txConfig,
		bundle,
		&recordingBundleSigner{publicKeyErr: publicKeyFailure},
	)
	require.ErrorIs(t, err, publicKeyFailure)

	wrongPublicKey, _, err := pqccrypto.GenerateMLDSA65Key(nil)
	require.NoError(t, err)
	_, _, err = SignRecoverySignBundle(
		context.Background(),
		txConfig,
		bundle,
		&recordingBundleSigner{publicKey: wrongPublicKey},
	)
	require.ErrorContains(t, err, "does not match on-chain recovery key")

	signFailure := errors.New("recovery hardware signer unavailable")
	_, _, err = SignRecoverySignBundle(
		context.Background(),
		txConfig,
		bundle,
		&recordingBundleSigner{
			publicKey: bundle.OnChainRecoveryPublicKey,
			signErr:   signFailure,
		},
	)
	require.ErrorIs(t, err, signFailure)

	invalidSignature := &recordingBundleSigner{
		publicKey:        bundle.OnChainRecoveryPublicKey,
		privateKey:       privateKey,
		corruptSignature: true,
	}
	_, _, err = SignRecoverySignBundle(
		context.Background(),
		txConfig,
		bundle,
		invalidSignature,
	)
	require.ErrorContains(t, err, "returned an invalid signature")

	signed, _, err := SignRecoverySignBundleWithPrivateKey(
		context.Background(),
		txConfig,
		bundle,
		privateKey,
	)
	require.NoError(t, err)
	_, _, err = SignRecoverySignBundle(
		context.Background(),
		txConfig,
		signed,
		wrongAlgorithm,
	)
	require.ErrorContains(t, err, "already signed")
}

func TestRecoverySignBundleStrictJSONAndMessageValidation(t *testing.T) {
	txConfig := testTxConfig()
	bundle, privateKey := testUnsignedRecoveryBundle(t, txConfig)
	defer clear(privateKey)

	_, _, err := UnmarshalRecoverySignBundle(txConfig, nil, false)
	require.ErrorContains(t, err, "length must be between")
	_, _, err = UnmarshalRecoverySignBundle(txConfig, []byte("{"), false)
	require.ErrorContains(t, err, "decode recovery sign bundle")
	_, _, err = UnmarshalRecoverySignBundle(
		txConfig,
		[]byte(`{"unexpected":true}`),
		false,
	)
	require.ErrorContains(t, err, "unknown field")

	encoded, err := MarshalRecoverySignBundle(txConfig, bundle, false)
	require.NoError(t, err)
	encoded = append(encoded, []byte("{}")...)
	_, _, err = UnmarshalRecoverySignBundle(txConfig, encoded, false)
	require.ErrorContains(t, err, "multiple JSON values")
	_, err = MarshalRecoverySignBundle(txConfig, nil, false)
	require.ErrorContains(t, err, "recovery sign bundle is required")

	_, err = recoveryMessageFromTx(nil)
	require.ErrorContains(t, err, "exactly one message")
	builder := txConfig.NewTxBuilder()
	sender := sdk.AccAddress(bytes.Repeat([]byte{0x95}, 20))
	require.NoError(t, builder.SetMsgs(bankMessage(sender)))
	_, err = recoveryMessageFromTx(builder.GetTx())
	require.ErrorContains(t, err, "top-level MsgRecoverKey")

	message, err := recoveryMessageFromTx(
		mustDecodeRecoveryTx(t, txConfig, bundle.UnsignedTx),
	)
	require.NoError(t, err)
	message.RecoverySignature = message.RecoverySignature[:1]
	require.ErrorContains(
		t,
		validateRecoveryPlaceholder(
			message,
			types.Algorithm_ALGORITHM_ML_DSA_65,
		),
		"placeholder length",
	)
	_, signatureSize, err := pqccrypto.Sizes(pqccrypto.AlgorithmMLDSA65)
	require.NoError(t, err)
	message.RecoverySignature = make([]byte, signatureSize)
	message.RecoverySignature[0] = 1
	require.ErrorContains(
		t,
		validateRecoveryPlaceholder(
			message,
			types.Algorithm_ALGORITHM_ML_DSA_65,
		),
		"all-zero",
	)
}

func mutateRecoveryBundleSignDoc(
	t testing.TB,
	bundle *RecoverySignBundleV1,
	mutate func(*types.RecoverySignDocV1),
) {
	t.Helper()
	var signDoc types.RecoverySignDocV1
	require.NoError(t, signDoc.Unmarshal(bundle.SignDoc))
	mutate(&signDoc)
	signBytes, err := types.MarshalRecoverySignDocV1(signDoc)
	require.NoError(t, err)
	bundle.SignDoc = signBytes
	hash := sha256.Sum256(signBytes)
	bundle.SignDocSHA256 = hash[:]
}

func mustDecodeRecoveryTx(
	t testing.TB,
	txConfig sdkclient.TxConfig,
	encoded []byte,
) sdk.Tx {
	t.Helper()
	tx, err := txConfig.TxDecoder()(encoded)
	require.NoError(t, err)
	return tx
}

func bankMessage(sender sdk.AccAddress) sdk.Msg {
	return &types.MsgSetProtection{
		Owner:   sender.String(),
		Enabled: true,
	}
}
