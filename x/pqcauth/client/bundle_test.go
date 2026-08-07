package client

import (
	"context"
	"crypto/sha256"
	"errors"
	"net"
	"sync"
	"testing"

	sdkclient "github.com/cosmos/cosmos-sdk/client"
	sdktx "github.com/cosmos/cosmos-sdk/client/tx"
	"github.com/cosmos/cosmos-sdk/codec"
	codectypes "github.com/cosmos/cosmos-sdk/codec/types"
	"github.com/cosmos/cosmos-sdk/crypto/keyring"
	"github.com/cosmos/cosmos-sdk/crypto/keys/secp256k1"
	"github.com/cosmos/cosmos-sdk/std"
	sdk "github.com/cosmos/cosmos-sdk/types"
	txsigning "github.com/cosmos/cosmos-sdk/types/tx/signing"
	authtx "github.com/cosmos/cosmos-sdk/x/auth/tx"
	banktypes "github.com/cosmos/cosmos-sdk/x/bank/types"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/test/bufconn"

	pqccrypto "github.com/DoraFactory/doravota/x/pqcauth/crypto"
	"github.com/DoraFactory/doravota/x/pqcauth/types"
)

func TestPQCSignBundleOfflineRoundTripAndTamperRejection(t *testing.T) {
	txConfig := testTxConfig()
	bundle, privateKey := testUnsignedBundle(t, txConfig)
	defer clear(privateKey)

	summary, err := ValidatePQCSignBundle(txConfig, bundle, false)
	require.NoError(t, err)
	require.False(t, summary.Signed)
	require.Equal(t, uint64(17), summary.Sequence)

	encoded, err := MarshalPQCSignBundle(txConfig, bundle, false)
	require.NoError(t, err)
	decoded, decodedSummary, err := UnmarshalPQCSignBundle(txConfig, encoded, false)
	require.NoError(t, err)
	require.Equal(t, summary.TxSHA256, decodedSummary.TxSHA256)

	remoteSigner := &recordingBundleSigner{
		publicKey:  append([]byte(nil), bundle.OnChainPublicKey...),
		privateKey: privateKey,
	}
	signed, signedSummary, err := SignPQCSignBundle(
		context.Background(),
		txConfig,
		decoded,
		remoteSigner,
	)
	require.NoError(t, err)
	require.True(t, signedSummary.Signed)
	require.Equal(t, bundle.SignDoc, remoteSigner.message)
	require.Equal(t, []byte(types.TxSignatureContext), remoteSigner.signatureContext)
	require.Empty(t, decoded.Signature, "offline signing must not mutate the input bundle")
	_, err = MarshalPQCSignBundle(txConfig, signed, true)
	require.NoError(t, err)

	tamperedSignature := clonePQCSignBundle(signed)
	tamperedSignature.Signature[0] ^= 0x01
	_, err = ValidatePQCSignBundle(txConfig, tamperedSignature, true)
	require.ErrorContains(t, err, "invalid bundled PQC signature")

	wrongPublicKey, _, err := pqccrypto.GenerateMLDSA65Key(nil)
	require.NoError(t, err)
	tamperedPublicKey := clonePQCSignBundle(bundle)
	tamperedPublicKey.OnChainPublicKey = wrongPublicKey
	_, _, err = SignPQCSignBundleWithPrivateKey(
		context.Background(),
		txConfig,
		tamperedPublicKey,
		privateKey,
	)
	require.ErrorContains(t, err, "does not match bundle on-chain public key")

	invalidRemoteSigner := &recordingBundleSigner{
		publicKey:        append([]byte(nil), bundle.OnChainPublicKey...),
		privateKey:       privateKey,
		corruptSignature: true,
	}
	_, _, err = SignPQCSignBundle(
		context.Background(),
		txConfig,
		bundle,
		invalidRemoteSigner,
	)
	require.ErrorContains(t, err, "returned an invalid signature")
}

func TestPQCSignBundleBindsExactTransactionAndUsesStrictJSON(t *testing.T) {
	txConfig := testTxConfig()
	bundle, privateKey := testUnsignedBundle(t, txConfig)
	defer clear(privateKey)

	decodedTx, err := txConfig.TxDecoder()(bundle.UnsignedTx)
	require.NoError(t, err)
	builder, err := txConfig.WrapTxBuilder(decodedTx)
	require.NoError(t, err)
	builder.SetMemo("substituted after offline preparation")
	tamperedTx, err := txConfig.TxEncoder()(builder.GetTx())
	require.NoError(t, err)

	tamperedBundle := clonePQCSignBundle(bundle)
	tamperedBundle.UnsignedTx = tamperedTx
	txHash := sha256.Sum256(tamperedTx)
	tamperedBundle.UnsignedTxSHA256 = txHash[:]
	_, err = ValidatePQCSignBundle(txConfig, tamperedBundle, false)
	require.ErrorContains(t, err, "does not match bundled unsigned transaction")

	encoded, err := MarshalPQCSignBundle(txConfig, bundle, false)
	require.NoError(t, err)
	encoded = append(encoded[:len(encoded)-2], []byte(",\"unexpected\":true}\n")...)
	_, _, err = UnmarshalPQCSignBundle(txConfig, encoded, false)
	require.ErrorContains(t, err, "unknown field")

	validEncoded, err := MarshalPQCSignBundle(txConfig, bundle, false)
	require.NoError(t, err)
	validEncoded = append(validEncoded, []byte("{}")...)
	_, _, err = UnmarshalPQCSignBundle(txConfig, validEncoded, false)
	require.ErrorContains(t, err, "multiple JSON values")
}

func TestPQCSignBundleValidationFailureMatrix(t *testing.T) {
	txConfig := testTxConfig()
	valid, privateKey := testUnsignedBundle(t, txConfig)
	defer clear(privateKey)

	_, err := ValidatePQCSignBundle(nil, valid, false)
	require.ErrorContains(t, err, "transaction config is required")
	_, err = ValidatePQCSignBundle(txConfig, nil, false)
	require.ErrorContains(t, err, "bundle is required")

	testCases := []struct {
		name   string
		mutate func(*PQCSignBundleV1)
		want   string
	}{
		{
			name: "format",
			mutate: func(bundle *PQCSignBundleV1) {
				bundle.Format = "future"
			},
			want: "unsupported PQC sign bundle format",
		},
		{
			name: "empty unsigned tx",
			mutate: func(bundle *PQCSignBundleV1) {
				bundle.UnsignedTx = nil
			},
			want: "unsigned transaction length",
		},
		{
			name: "empty sign doc",
			mutate: func(bundle *PQCSignBundleV1) {
				bundle.SignDoc = nil
			},
			want: "sign document length",
		},
		{
			name: "tx hash",
			mutate: func(bundle *PQCSignBundleV1) {
				bundle.UnsignedTxSHA256[0] ^= 1
			},
			want: "transaction SHA-256 mismatch",
		},
		{
			name: "sign doc hash",
			mutate: func(bundle *PQCSignBundleV1) {
				bundle.SignDocSHA256[0] ^= 1
			},
			want: "sign document SHA-256 mismatch",
		},
		{
			name: "malformed sign doc",
			mutate: func(bundle *PQCSignBundleV1) {
				bundle.SignDoc = []byte{0xff}
				hash := sha256.Sum256(bundle.SignDoc)
				bundle.SignDocSHA256 = hash[:]
			},
			want: "decode bundled PQC sign document",
		},
		{
			name: "wrong signer index",
			mutate: func(bundle *PQCSignBundleV1) {
				mutateBundleSignDoc(t, bundle, func(doc *types.PQCSignDocV1) {
					doc.SignerIndex = 1
				})
			},
			want: "only signer index 0",
		},
		{
			name: "invalid signer",
			mutate: func(bundle *PQCSignBundleV1) {
				mutateBundleSignDoc(t, bundle, func(doc *types.PQCSignDocV1) {
					doc.Signer = "not-an-address"
				})
			},
			want: "signer address is invalid",
		},
		{
			name: "malformed unsigned tx",
			mutate: func(bundle *PQCSignBundleV1) {
				bundle.UnsignedTx = []byte{0xff}
				hash := sha256.Sum256(bundle.UnsignedTx)
				bundle.UnsignedTxSHA256 = hash[:]
			},
			want: "decode bundled unsigned transaction",
		},
		{
			name: "sequence mismatch",
			mutate: func(bundle *PQCSignBundleV1) {
				mutateBundleSignDoc(t, bundle, func(doc *types.PQCSignDocV1) {
					doc.Sequence++
				})
			},
			want: "signer sequence does not match",
		},
		{
			name: "unsupported algorithm",
			mutate: func(bundle *PQCSignBundleV1) {
				var signDoc types.PQCSignDocV1
				require.NoError(t, signDoc.Unmarshal(bundle.SignDoc))
				signDoc.Algorithm = types.Algorithm_ALGORITHM_UNSPECIFIED
				signBytes, err := signDoc.Marshal()
				require.NoError(t, err)
				bundle.SignDoc = signBytes
				hash := sha256.Sum256(signBytes)
				bundle.SignDocSHA256 = hash[:]
			},
			want: "unsupported PQC algorithm",
		},
		{
			name: "public key length",
			mutate: func(bundle *PQCSignBundleV1) {
				bundle.OnChainPublicKey = bundle.OnChainPublicKey[:1]
			},
			want: "on-chain public key length",
		},
		{
			name: "signature length",
			mutate: func(bundle *PQCSignBundleV1) {
				bundle.Signature = []byte{1}
			},
			want: "PQC signature length",
		},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			bundle := clonePQCSignBundle(valid)
			testCase.mutate(bundle)
			_, err := ValidatePQCSignBundle(txConfig, bundle, false)
			require.ErrorContains(t, err, testCase.want)
		})
	}

	_, err = ValidatePQCSignBundle(txConfig, valid, true)
	require.ErrorContains(t, err, "has no signature")
	require.Nil(t, clonePQCSignBundle(nil))
	require.Nil(t, (*PQCSignBundleV1)(nil).GetSignature())
}

func TestPQCSignBundleSignerFailureMatrix(t *testing.T) {
	txConfig := testTxConfig()
	bundle, privateKey := testUnsignedBundle(t, txConfig)
	defer clear(privateKey)

	_, _, err := SignPQCSignBundle(context.Background(), txConfig, bundle, nil)
	require.ErrorContains(t, err, "signer is required")

	wrongAlgorithm := &recordingBundleSigner{
		algorithm:  types.Algorithm(99),
		publicKey:  bundle.OnChainPublicKey,
		privateKey: privateKey,
	}
	_, _, err = SignPQCSignBundle(context.Background(), txConfig, bundle, wrongAlgorithm)
	require.ErrorContains(t, err, "does not match bundle algorithm")

	publicKeyFailure := errors.New("public key unavailable")
	_, _, err = SignPQCSignBundle(context.Background(), txConfig, bundle, &recordingBundleSigner{
		publicKeyErr: publicKeyFailure,
	})
	require.ErrorIs(t, err, publicKeyFailure)

	signFailure := errors.New("hardware signer unavailable")
	_, _, err = SignPQCSignBundle(context.Background(), txConfig, bundle, &recordingBundleSigner{
		publicKey:  bundle.OnChainPublicKey,
		privateKey: privateKey,
		signErr:    signFailure,
	})
	require.ErrorIs(t, err, signFailure)

	signed, _, err := SignPQCSignBundleWithPrivateKey(
		context.Background(),
		txConfig,
		bundle,
		privateKey,
	)
	require.NoError(t, err)
	_, _, err = SignPQCSignBundle(context.Background(), txConfig, signed, wrongAlgorithm)
	require.ErrorContains(t, err, "already signed")
}

func TestDecodeAndUnmarshalPQCBundleRejectMalformedInputs(t *testing.T) {
	txConfig := testTxConfig()

	_, err := DecodeUnsignedTxJSONForPQCBundle(nil, []byte("{}"))
	require.ErrorContains(t, err, "transaction config is required")
	_, err = DecodeUnsignedTxJSONForPQCBundle(txConfig, nil)
	require.ErrorContains(t, err, "length must be between")
	_, err = DecodeUnsignedTxJSONForPQCBundle(txConfig, []byte("{"))
	require.ErrorContains(t, err, "decode unsigned transaction JSON")

	emptyBuilder := txConfig.NewTxBuilder()
	emptyJSON, err := txConfig.TxJSONEncoder()(emptyBuilder.GetTx())
	require.NoError(t, err)
	_, err = DecodeUnsignedTxJSONForPQCBundle(txConfig, emptyJSON)
	require.ErrorContains(t, err, "at least one message")

	_, _, err = UnmarshalPQCSignBundle(txConfig, nil, false)
	require.ErrorContains(t, err, "length must be between")
	_, _, err = UnmarshalPQCSignBundle(txConfig, []byte("{"), false)
	require.ErrorContains(t, err, "decode PQC sign bundle")
	_, _, err = UnmarshalPQCSignBundle(txConfig, []byte("{} trailing"), false)
	require.ErrorContains(t, err, "decode PQC sign bundle")

	_, err = MarshalPQCSignBundle(txConfig, nil, false)
	require.ErrorContains(t, err, "bundle is required")
}

func TestDecodeUnsignedTxJSONForPQCBundleRejectsExistingSignerInfo(t *testing.T) {
	txConfig := testTxConfig()
	classicalPublicKey := secp256k1.GenPrivKey().PubKey()
	signer := sdk.AccAddress(classicalPublicKey.Address())
	builder := txConfig.NewTxBuilder()
	require.NoError(t, builder.SetMsgs(banktypes.NewMsgSend(
		signer,
		sdk.AccAddress(make([]byte, 20)),
		sdk.NewCoins(sdk.NewInt64Coin("udora", 1)),
	)))
	unsignedJSON, err := txConfig.TxJSONEncoder()(builder.GetTx())
	require.NoError(t, err)
	_, err = DecodeUnsignedTxJSONForPQCBundle(txConfig, unsignedJSON)
	require.NoError(t, err)

	require.NoError(t, builder.SetSignatures(txsigning.SignatureV2{
		PubKey: classicalPublicKey,
		Data: &txsigning.SingleSignatureData{
			SignMode: txsigning.SignMode_SIGN_MODE_DIRECT,
		},
		Sequence: 1,
	}))
	withSignerInfo, err := txConfig.TxJSONEncoder()(builder.GetTx())
	require.NoError(t, err)
	_, err = DecodeUnsignedTxJSONForPQCBundle(txConfig, withSignerInfo)
	require.ErrorContains(t, err, "must not contain signer info")
}

func TestPQCSignBundleOnlineRevalidationRejectsStalePolicy(t *testing.T) {
	txConfig := testTxConfig()
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
			Params:                   types.DefaultParams(),
			EffectiveEnforcementMode: types.EnforcementMode_ENFORCEMENT_MODE_REQUIRED_FOR_REGISTERED,
			EffectiveEmergencyMode:   types.EmergencyMode_EMERGENCY_MODE_NORMAL,
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
		WithChainID("pqc-bundle-online-test-1").
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
	require.NoError(t, builder.SetMsgs(banktypes.NewMsgSend(
		signer,
		sdk.AccAddress(make([]byte, 20)),
		sdk.NewCoins(sdk.NewInt64Coin("udora", 1)),
	)))
	builder.SetGasLimit(200_000)

	bundle, _, err := PreparePQCSignBundle(
		context.Background(),
		clientCtx,
		txf,
		builder,
	)
	require.NoError(t, err)
	signed, _, err := SignPQCSignBundleWithPrivateKey(
		context.Background(),
		txConfig,
		bundle,
		pqcPrivateKey,
	)
	require.NoError(t, err)

	queryServer.setPolicyVersion(5)
	_, _, err = AttachPQCSignBundle(
		context.Background(),
		clientCtx,
		txf,
		signed,
	)
	require.ErrorContains(t, err, "bundle is stale")

	queryServer.setPolicyVersion(4)
	finalBuilder, _, err := AttachPQCSignBundle(
		context.Background(),
		clientCtx,
		txf,
		signed,
	)
	require.NoError(t, err)
	provider, ok := finalBuilder.GetTx().(protoTxProvider)
	require.True(t, ok)
	_, removed, err := types.CanonicalBodyBytesWithoutPQCAuth(provider.GetProtoTx())
	require.NoError(t, err)
	require.Equal(t, 1, removed)
}

func testTxConfig() sdkclient.TxConfig {
	registry := codectypes.NewInterfaceRegistry()
	std.RegisterInterfaces(registry)
	banktypes.RegisterInterfaces(registry)
	types.RegisterInterfaces(registry)
	cdc := codec.NewProtoCodec(registry)
	return authtx.NewTxConfig(cdc, authtx.DefaultSignModes)
}

func testInterfaceRegistry() codectypes.InterfaceRegistry {
	registry := codectypes.NewInterfaceRegistry()
	std.RegisterInterfaces(registry)
	banktypes.RegisterInterfaces(registry)
	types.RegisterInterfaces(registry)
	return registry
}

func testUnsignedBundle(
	t *testing.T,
	txConfig sdkclient.TxConfig,
) (*PQCSignBundleV1, []byte) {
	t.Helper()
	classicalPrivateKey := secp256k1.GenPrivKey()
	classicalPublicKey := classicalPrivateKey.PubKey()
	signer := sdk.AccAddress(classicalPublicKey.Address())
	recipient := sdk.AccAddress(make([]byte, 20))
	builder := txConfig.NewTxBuilder()
	require.NoError(t, builder.SetMsgs(banktypes.NewMsgSend(
		signer,
		recipient,
		sdk.NewCoins(sdk.NewInt64Coin("udora", 1)),
	)))
	builder.SetGasLimit(200_000)
	require.NoError(t, builder.SetSignatures(txsigning.SignatureV2{
		PubKey: classicalPublicKey,
		Data: &txsigning.SingleSignatureData{
			SignMode: txsigning.SignMode_SIGN_MODE_DIRECT,
		},
		Sequence: 17,
	}))

	unsignedTx, err := txConfig.TxEncoder()(builder.GetTx())
	require.NoError(t, err)
	provider, ok := builder.GetTx().(protoTxProvider)
	require.True(t, ok)
	params := types.DefaultParams()
	signDoc, err := types.NewPQCSignDocV1(
		provider.GetProtoTx(),
		params.NetworkId,
		"pqc-bundle-test-1",
		23,
		17,
		0,
		signer.String(),
		9,
		types.Algorithm_ALGORITHM_ML_DSA_65,
		4,
	)
	require.NoError(t, err)
	signBytes, err := types.MarshalPQCSignDocV1(signDoc)
	require.NoError(t, err)
	publicKey, privateKey, err := pqccrypto.GenerateMLDSA65Key(nil)
	require.NoError(t, err)
	txHash := sha256.Sum256(unsignedTx)
	signDocHash := sha256.Sum256(signBytes)
	return &PQCSignBundleV1{
		Format:           PQCSignBundleFormatV1,
		UnsignedTx:       unsignedTx,
		UnsignedTxSHA256: txHash[:],
		SignDoc:          signBytes,
		SignDocSHA256:    signDocHash[:],
		OnChainPublicKey: publicKey,
	}, privateKey
}

type mutableBundleQueryServer struct {
	types.UnimplementedQueryServer
	mu      sync.RWMutex
	account types.QueryAccountResponse
	key     types.PQCKeyRecord
	params  types.QueryParamsResponse
}

func (s *mutableBundleQueryServer) Account(
	context.Context,
	*types.QueryAccountRequest,
) (*types.QueryAccountResponse, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	response := s.account
	policy := s.account.Policy
	response.Policy = policy
	if s.account.ActiveSigningKey != nil {
		key := *s.account.ActiveSigningKey
		response.ActiveSigningKey = &key
	}
	return &response, nil
}

func (s *mutableBundleQueryServer) Params(
	context.Context,
	*types.QueryParamsRequest,
) (*types.QueryParamsResponse, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	response := s.params
	return &response, nil
}

func (s *mutableBundleQueryServer) Key(
	_ context.Context,
	request *types.QueryKeyRequest,
) (*types.QueryKeyResponse, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if request.Owner != s.key.Owner || request.KeyId != s.key.KeyId {
		return nil, types.ErrKeyNotFound
	}
	return &types.QueryKeyResponse{Key: s.key}, nil
}

func (s *mutableBundleQueryServer) setPolicyVersion(version uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.account.Policy.PolicyVersion = version
}

func (s *mutableBundleQueryServer) setEmergencyMode(mode types.EmergencyMode) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.params.EffectiveEmergencyMode = mode
}

func startBundleQueryServer(
	t *testing.T,
	queryServer types.QueryServer,
) *grpc.ClientConn {
	t.Helper()
	listener := bufconn.Listen(1 << 20)
	server := grpc.NewServer()
	types.RegisterQueryServer(server, queryServer)
	go func() {
		_ = server.Serve(listener)
	}()
	t.Cleanup(server.Stop)
	connection, err := grpc.DialContext(
		context.Background(),
		"bufnet",
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) {
			return listener.Dial()
		}),
		grpc.WithInsecure(),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = connection.Close() })
	return connection
}

type recordingBundleSigner struct {
	publicKey        []byte
	privateKey       []byte
	message          []byte
	signatureContext []byte
	corruptSignature bool
	algorithm        types.Algorithm
	publicKeyErr     error
	signErr          error
}

func (s *recordingBundleSigner) Algorithm() types.Algorithm {
	if s.algorithm != types.Algorithm_ALGORITHM_UNSPECIFIED {
		return s.algorithm
	}
	return types.Algorithm_ALGORITHM_ML_DSA_65
}

func (s *recordingBundleSigner) PublicKey(ctx context.Context) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if s.publicKeyErr != nil {
		return nil, s.publicKeyErr
	}
	return append([]byte(nil), s.publicKey...), nil
}

func (s *recordingBundleSigner) Sign(
	ctx context.Context,
	message []byte,
	signatureContext []byte,
) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if s.signErr != nil {
		return nil, s.signErr
	}
	s.message = append([]byte(nil), message...)
	s.signatureContext = append([]byte(nil), signatureContext...)
	signature, err := pqccrypto.SignMLDSA65(
		s.privateKey,
		message,
		signatureContext,
		true,
	)
	if err != nil {
		return nil, err
	}
	if s.corruptSignature {
		signature[0] ^= 0x01
	}
	return signature, nil
}

func mutateBundleSignDoc(
	t *testing.T,
	bundle *PQCSignBundleV1,
	mutate func(*types.PQCSignDocV1),
) {
	t.Helper()
	var signDoc types.PQCSignDocV1
	require.NoError(t, signDoc.Unmarshal(bundle.SignDoc))
	mutate(&signDoc)
	signBytes, err := types.MarshalPQCSignDocV1(signDoc)
	require.NoError(t, err)
	bundle.SignDoc = signBytes
	hash := sha256.Sum256(signBytes)
	bundle.SignDocSHA256 = hash[:]
}
