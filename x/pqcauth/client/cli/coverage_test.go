package cli

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"testing"

	rpcmock "github.com/cometbft/cometbft/rpc/client/mock"
	coretypes "github.com/cometbft/cometbft/rpc/core/types"
	tmtypes "github.com/cometbft/cometbft/types"
	"github.com/cosmos/cosmos-sdk/client"
	"github.com/cosmos/cosmos-sdk/client/flags"
	"github.com/cosmos/cosmos-sdk/codec"
	codectypes "github.com/cosmos/cosmos-sdk/codec/types"
	"github.com/cosmos/cosmos-sdk/crypto/hd"
	"github.com/cosmos/cosmos-sdk/crypto/keyring"
	"github.com/cosmos/cosmos-sdk/crypto/keys/secp256k1"
	"github.com/cosmos/cosmos-sdk/std"
	sdk "github.com/cosmos/cosmos-sdk/types"
	txtypes "github.com/cosmos/cosmos-sdk/types/tx"
	txsigning "github.com/cosmos/cosmos-sdk/types/tx/signing"
	authtx "github.com/cosmos/cosmos-sdk/x/auth/tx"
	banktypes "github.com/cosmos/cosmos-sdk/x/bank/types"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/test/bufconn"

	pqcauthclient "github.com/DoraFactory/doravota/x/pqcauth/client"
	pqccrypto "github.com/DoraFactory/doravota/x/pqcauth/crypto"
	"github.com/DoraFactory/doravota/x/pqcauth/types"
)

func TestCommandTreesExposeAllPQCOperations(t *testing.T) {
	txCommand := GetTxCmd()
	for _, name := range []string{
		"keygen",
		"create-key-proof",
		"prepare-bundle",
		"sign-bundle",
		"broadcast-bundle",
		"sign-recovery-bundle",
		"broadcast-recovery-bundle",
		"register-key",
		"rotate-key",
		"rotate-recovery-key",
		"set-protection",
		"revoke-key",
		"recover-key",
	} {
		command, _, err := txCommand.Find([]string{name})
		require.NoError(t, err)
		require.Equal(t, name, command.Name())
	}

	queryCommand := GetQueryCmd()
	for _, name := range []string{"params", "account", "key", "keys"} {
		command, _, err := queryCommand.Find([]string{name})
		require.NoError(t, err)
		require.Equal(t, name, command.Name())
	}

	setProtection := setProtectionCommand()
	setProtection.SetArgs([]string{"not-a-bool"})
	require.ErrorContains(t, setProtection.Execute(), "enabled must be true or false")

	revoke := revokeKeyCommand()
	revoke.SetArgs([]string{"0"})
	require.ErrorContains(t, revoke.Execute(), "positive integer")

	recover := recoverKeyCommand()
	recover.SetArgs([]string{"0", "1", "AA==", "AA=="})
	require.ErrorContains(t, recover.Execute(), "recovery key id")

	queryKey := queryKeyCommand()
	queryKey.SetArgs([]string{"owner", "0"})
	require.ErrorIs(t, queryKey.Execute(), types.ErrInvalidKey)
}

func TestKeyMaterialRoleAndProofContextParsingMatrix(t *testing.T) {
	publicKey := []byte{1, 2}
	proof := []byte{3, 4}
	keyID, decodedPublicKey, decodedProof, err := parseKeyMaterial([]string{
		"7",
		base64.StdEncoding.EncodeToString(publicKey),
		base64.StdEncoding.EncodeToString(proof),
	})
	require.NoError(t, err)
	require.Equal(t, uint64(7), keyID)
	require.Equal(t, publicKey, decodedPublicKey)
	require.Equal(t, proof, decodedProof)

	for _, args := range [][]string{
		{"0", "AA==", "AA=="},
		{"1", "!", "AA=="},
		{"1", "AA==", "!"},
	} {
		_, _, _, err = parseKeyMaterial(args)
		require.Error(t, err)
	}
	_, err = decodeBase64("test", "!")
	require.ErrorContains(t, err, "decode test as base64")

	signing, err := parseKeyRole("signing")
	require.NoError(t, err)
	require.Equal(t, types.KeyRole_KEY_ROLE_SIGNING, signing)
	recovery, err := parseKeyRole("recovery")
	require.NoError(t, err)
	require.Equal(t, types.KeyRole_KEY_ROLE_RECOVERY, recovery)
	_, err = parseKeyRole("unknown")
	require.Error(t, err)

	valid := []struct {
		purpose string
		role    types.KeyRole
		context []byte
	}{
		{types.PurposeRegisterSigning, types.KeyRole_KEY_ROLE_SIGNING, []byte(types.RegisterProofContext)},
		{types.PurposeRegisterRecovery, types.KeyRole_KEY_ROLE_RECOVERY, []byte(types.RegisterProofContext)},
		{types.PurposeRotateSigning, types.KeyRole_KEY_ROLE_SIGNING, []byte(types.RotateProofContext)},
		{types.PurposeRotateRecovery, types.KeyRole_KEY_ROLE_RECOVERY, []byte(types.RotateRecoveryContext)},
		{types.PurposeRecoverSigning, types.KeyRole_KEY_ROLE_SIGNING, []byte(types.RecoveryKeyProofContext)},
	}
	for _, testCase := range valid {
		actual, err := proofContext(testCase.purpose, testCase.role)
		require.NoError(t, err)
		require.Equal(t, testCase.context, actual)
		opposite := types.KeyRole_KEY_ROLE_SIGNING
		if testCase.role == opposite {
			opposite = types.KeyRole_KEY_ROLE_RECOVERY
		}
		_, err = proofContext(testCase.purpose, opposite)
		require.Error(t, err)
	}
	_, err = proofContext("unknown", types.KeyRole_KEY_ROLE_SIGNING)
	require.Error(t, err)
}

func TestRecoverySigningOptionsRequireOneSafePath(t *testing.T) {
	require.Error(t, validateRecoverySigningOptions(false, "", ""))
	require.NoError(t, validateRecoverySigningOptions(false, "recovery.key", ""))
	require.NoError(t, validateRecoverySigningOptions(false, "", "bundle.json"))
	require.NoError(t, validateRecoverySigningOptions(true, "", ""))
	require.Error(t, validateRecoverySigningOptions(false, "recovery.key", "bundle.json"))
}

func TestBundleFileAndOutputHelpers(t *testing.T) {
	directory := t.TempDir()
	validPath := filepath.Join(directory, "bundle.json")
	require.NoError(t, os.WriteFile(validPath, []byte("{}"), 0o600))
	encoded, err := readRegularFile(validPath, 10, "test file")
	require.NoError(t, err)
	require.Equal(t, []byte("{}"), encoded)
	encoded, err = readBundleFile(validPath)
	require.NoError(t, err)
	require.Equal(t, []byte("{}"), encoded)

	_, err = readRegularFile(filepath.Join(directory, "missing"), 10, "test file")
	require.ErrorContains(t, err, "open test file")
	_, err = readRegularFile(directory, 10, "test file")
	require.ErrorContains(t, err, "regular file")
	emptyPath := filepath.Join(directory, "empty")
	require.NoError(t, os.WriteFile(emptyPath, nil, 0o600))
	_, err = readRegularFile(emptyPath, 10, "test file")
	require.ErrorContains(t, err, "length must be between")
	_, err = readRegularFile(validPath, 1, "test file")
	require.ErrorContains(t, err, "length must be between")

	broadcast := broadcastBundleCommand()
	require.NoError(t, rejectBundledTxMutationFlags(broadcast.Flags()))
	require.NoError(t, broadcast.Flags().Set(flags.FlagGas, "123"))
	require.ErrorContains(t, rejectBundledTxMutationFlags(broadcast.Flags()), "cannot override")

	summary := pqcauthclient.PQCSignBundleSummary{
		ChainID:       "chain",
		NetworkID:     []byte{1},
		Signer:        "signer",
		AccountNumber: 2,
		Sequence:      3,
		KeyID:         4,
		Algorithm:     types.Algorithm_ALGORITHM_ML_DSA_65,
		PolicyVersion: 5,
		TxSHA256:      []byte{6},
		SignDocSHA256: []byte{7},
		Signed:        true,
	}
	var review bytes.Buffer
	printBundleReview(&review, summary, []byte(`{"body":{}}`))
	require.Contains(t, review.String(), "chain_id: chain")
	require.Contains(t, review.String(), "transaction_json:")

	var result bytes.Buffer
	require.NoError(t, printBundleResult(&result, "signed", validPath, summary))
	var decoded bundleCommandResult
	require.NoError(t, json.Unmarshal(result.Bytes(), &decoded))
	require.Equal(t, "signed", decoded.Status)
	require.True(t, decoded.Signed)
}

func TestProtectedBroadcastEarlyValidation(t *testing.T) {
	command := setProtectionCommand()
	message := &types.MsgSetProtection{
		Owner: sdk.AccAddress(bytes.Repeat([]byte{0x84}, 20)).String(),
	}

	err := generateOrBroadcastProtectedTx(
		context.Background(),
		client.Context{},
		command.Flags(),
		"",
		message,
	)
	require.ErrorContains(t, err, "--"+flagPQCPrivateKey)

	require.NoError(t, command.Flags().Set(flagPQCSignBundleOutput, "bundle.out"))
	err = generateOrBroadcastProtectedTx(
		context.Background(),
		client.Context{},
		command.Flags(),
		"private.key",
		message,
	)
	require.ErrorContains(t, err, "mutually exclusive")

	err = generateOrBroadcastProtectedTx(
		context.Background(),
		client.Context{GenerateOnly: true},
		command.Flags(),
		"",
		message,
	)
	require.ErrorContains(t, err, "use --"+flagPQCSignBundleOutput)

	require.NoError(t, command.Flags().Set(flagPQCSignBundleOutput, ""))
	err = generateOrBroadcastProtectedTx(
		context.Background(),
		client.Context{},
		command.Flags(),
		"private.key",
		&types.MsgSetProtection{Owner: "invalid"},
	)
	require.Error(t, err)
}

type cliQueryServerStub struct {
	types.UnimplementedQueryServer
	owner  string
	params *types.QueryParamsResponse
	policy *types.AccountPolicy
	key    *types.PQCKeyRecord
	active *types.PQCKeyRecord
}

type cliRPCClient struct {
	rpcmock.Client
}

func (cliRPCClient) BroadcastTxSync(
	_ context.Context,
	tx tmtypes.Tx,
) (*coretypes.ResultBroadcastTx, error) {
	return &coretypes.ResultBroadcastTx{
		Code: 0,
		Hash: tx.Hash(),
	}, nil
}

func (s cliQueryServerStub) Params(
	context.Context,
	*types.QueryParamsRequest,
) (*types.QueryParamsResponse, error) {
	if s.params != nil {
		return s.params, nil
	}
	return &types.QueryParamsResponse{Params: types.DefaultParams()}, nil
}

func (s cliQueryServerStub) Account(
	context.Context,
	*types.QueryAccountRequest,
) (*types.QueryAccountResponse, error) {
	if s.policy != nil {
		return &types.QueryAccountResponse{
			Policy:           *s.policy,
			ActiveSigningKey: s.active,
		}, nil
	}
	return &types.QueryAccountResponse{
		Policy: types.AccountPolicy{Owner: s.owner, PolicyVersion: 1},
	}, nil
}

func (s cliQueryServerStub) Key(
	context.Context,
	*types.QueryKeyRequest,
) (*types.QueryKeyResponse, error) {
	if s.key != nil {
		return &types.QueryKeyResponse{Key: *s.key}, nil
	}
	return &types.QueryKeyResponse{
		Key: types.PQCKeyRecord{Owner: s.owner, KeyId: 1},
	}, nil
}

func (s cliQueryServerStub) Keys(
	context.Context,
	*types.QueryKeysRequest,
) (*types.QueryKeysResponse, error) {
	return &types.QueryKeysResponse{
		Keys: []types.PQCKeyRecord{{Owner: s.owner, KeyId: 1}},
	}, nil
}

func startCLIQueryServer(
	t testing.TB,
	server types.QueryServer,
) *grpc.ClientConn {
	t.Helper()
	listener := bufconn.Listen(1 << 20)
	grpcServer := grpc.NewServer()
	types.RegisterQueryServer(grpcServer, server)
	go func() {
		_ = grpcServer.Serve(listener)
	}()
	t.Cleanup(grpcServer.Stop)
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

func cliTestClientContext(
	t testing.TB,
	output *bytes.Buffer,
) client.Context {
	t.Helper()
	registry := codectypes.NewInterfaceRegistry()
	std.RegisterInterfaces(registry)
	banktypes.RegisterInterfaces(registry)
	types.RegisterInterfaces(registry)
	cdc := codec.NewProtoCodec(registry)
	txConfig := authtx.NewTxConfig(cdc, authtx.DefaultSignModes)
	owner := sdk.AccAddress(bytes.Repeat([]byte{0x85}, 20))
	connection := startCLIQueryServer(t, cliQueryServerStub{owner: owner.String()})
	return client.Context{}.
		WithCodec(cdc).
		WithInterfaceRegistry(registry).
		WithTxConfig(txConfig).
		WithFrom(owner.String()).
		WithFromAddress(owner).
		WithChainID("pqc-cli-query-test-1").
		WithGRPCClient(connection).
		WithOutput(output).
		WithOutputFormat("json")
}

func attachClientContext(commandContext context.Context, clientCtx *client.Context) context.Context {
	return context.WithValue(commandContext, client.ClientContextKey, clientCtx)
}

func TestQueryCommandsRoundTripOverGRPC(t *testing.T) {
	owner := sdk.AccAddress(bytes.Repeat([]byte{0x85}, 20)).String()
	for _, testCase := range []struct {
		name string
		args []string
		new  func() *cobra.Command
	}{
		{name: "params", new: queryParamsCommand},
		{name: "account", args: []string{owner}, new: queryAccountCommand},
		{name: "key", args: []string{owner, "1"}, new: queryKeyCommand},
		{name: "keys", args: []string{owner}, new: queryKeysCommand},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			var output bytes.Buffer
			clientCtx := cliTestClientContext(t, &output)
			command := testCase.new()
			command.SetContext(attachClientContext(context.Background(), &clientCtx))
			command.SetArgs(testCase.args)
			require.NoError(t, command.Execute())
			require.NotEmpty(t, output.Bytes())
		})
	}
}

func TestTransactionCommandsGenerateOnlyAndRejectMalformedArguments(t *testing.T) {
	publicKey, _, err := pqccrypto.GenerateMLDSA65Key(nil)
	require.NoError(t, err)
	recoveryPublicKey, _, err := pqccrypto.GenerateMLDSA65Key(nil)
	require.NoError(t, err)
	_, signatureSize, err := pqccrypto.Sizes(pqccrypto.AlgorithmMLDSA65)
	require.NoError(t, err)
	proof := make([]byte, signatureSize)
	encodedPublicKey := base64.StdEncoding.EncodeToString(publicKey)
	encodedRecoveryPublicKey := base64.StdEncoding.EncodeToString(recoveryPublicKey)
	encodedProof := base64.StdEncoding.EncodeToString(proof)

	var output bytes.Buffer
	clientCtx := cliTestClientContext(t, &output).WithGenerateOnly(true)
	register := registerKeyCommand()
	register.SetContext(attachClientContext(context.Background(), &clientCtx))
	register.SetArgs([]string{
		"1",
		encodedPublicKey,
		encodedProof,
		"--recovery-public-key-base64", encodedRecoveryPublicKey,
		"--recovery-proof-base64", encodedProof,
	})
	require.NoError(t, register.Execute())
	require.Contains(t, output.String(), "@type")

	output.Reset()
	recover := recoverKeyCommand()
	recover.SetContext(attachClientContext(context.Background(), &clientCtx))
	recover.SetArgs([]string{
		"2",
		"3",
		encodedPublicKey,
		encodedProof,
	})
	require.ErrorContains(
		t,
		recover.Execute(),
		"use --recovery-sign-bundle-output",
	)

	for _, newCommand := range []func() *cobra.Command{
		rotateKeyCommand,
		rotateRecoveryKeyCommand,
	} {
		command := newCommand()
		command.SetContext(attachClientContext(context.Background(), &clientCtx))
		command.SetArgs([]string{"0", encodedPublicKey, encodedProof})
		require.ErrorContains(t, command.Execute(), "positive integer")
	}

	register = registerKeyCommand()
	register.SetContext(attachClientContext(context.Background(), &clientCtx))
	register.SetArgs([]string{
		"1",
		encodedPublicKey,
		encodedProof,
		"--" + flagRecoveryPublicKey,
		encodedPublicKey,
	})
	require.ErrorContains(t, register.Execute(), "recovery public key and proof are required")
}

func TestRecoveryBundleCommandsPrepareAndSignRoundTrip(t *testing.T) {
	registry := codectypes.NewInterfaceRegistry()
	std.RegisterInterfaces(registry)
	types.RegisterInterfaces(registry)
	cdc := codec.NewProtoCodec(registry)
	txConfig := authtx.NewTxConfig(cdc, authtx.DefaultSignModes)

	classicalKeyring := keyring.NewInMemory(cdc)
	classicalRecord, _, err := classicalKeyring.NewMnemonic(
		"alice",
		keyring.English,
		sdk.FullFundraiserPath,
		keyring.DefaultBIP39Passphrase,
		hd.Secp256k1,
	)
	require.NoError(t, err)
	classicalPublicKey, err := classicalRecord.GetPubKey()
	require.NoError(t, err)
	owner := sdk.AccAddress(classicalPublicKey.Address())

	recoveryPublicKey, recoveryPrivateKey, err := pqccrypto.GenerateMLDSA65Key(nil)
	require.NoError(t, err)
	defer clear(recoveryPrivateKey)
	signingPublicKey, signingPrivateKey, err := pqccrypto.GenerateMLDSA65Key(nil)
	require.NoError(t, err)
	defer clear(signingPrivateKey)
	newPublicKey, _, err := pqccrypto.GenerateMLDSA65Key(nil)
	require.NoError(t, err)
	_, proofSize, err := pqccrypto.Sizes(pqccrypto.AlgorithmMLDSA65)
	require.NoError(t, err)

	params := types.DefaultParams()
	connection := startCLIQueryServer(t, cliQueryServerStub{
		owner: owner.String(),
		params: &types.QueryParamsResponse{
			Params:                 params,
			EffectiveEmergencyMode: types.EmergencyMode_EMERGENCY_MODE_NORMAL,
		},
		policy: &types.AccountPolicy{
			Owner:               owner.String(),
			CurrentSigningKeyId: 1,
			RecoveryKeyId:       2,
			PolicyVersion:       4,
			SelfEnforced:        true,
		},
		key: &types.PQCKeyRecord{
			Owner:     owner.String(),
			KeyId:     2,
			Algorithm: types.Algorithm_ALGORITHM_ML_DSA_65,
			PublicKey: recoveryPublicKey,
			Role:      types.KeyRole_KEY_ROLE_RECOVERY,
			Status:    types.KeyStatus_KEY_STATUS_LIVE,
		},
		active: &types.PQCKeyRecord{
			Owner:     owner.String(),
			KeyId:     1,
			Algorithm: types.Algorithm_ALGORITHM_ML_DSA_65,
			PublicKey: signingPublicKey,
			Role:      types.KeyRole_KEY_ROLE_SIGNING,
			Status:    types.KeyStatus_KEY_STATUS_LIVE,
		},
	})
	var output bytes.Buffer
	clientCtx := client.Context{}.
		WithCodec(cdc).
		WithInterfaceRegistry(registry).
		WithTxConfig(txConfig).
		WithKeyring(classicalKeyring).
		WithAccountRetriever(client.MockAccountRetriever{
			ReturnAccNum: 23,
			ReturnAccSeq: 17,
		}).
		WithFromName("alice").
		WithFromAddress(owner).
		WithChainID("pqc-cli-recovery-test-1").
		WithGRPCClient(connection).
		WithClient(cliRPCClient{}).
		WithBroadcastMode(flags.BroadcastSync).
		WithSkipConfirmation(true).
		WithOutput(&output).
		WithOutputFormat("json")

	directory := t.TempDir()
	preparedPath := filepath.Join(directory, "prepared.recovery-bundle")
	privateKeyPath := filepath.Join(directory, "recovery.mldsa65")
	signingKeyPath := filepath.Join(directory, "signing.mldsa65")
	signedPath := filepath.Join(directory, "signed.recovery-bundle")
	require.NoError(t, os.WriteFile(privateKeyPath, recoveryPrivateKey, 0o600))
	require.NoError(t, os.WriteFile(signingKeyPath, signingPrivateKey, 0o600))

	recover := recoverKeyCommand()
	recover.SetContext(attachClientContext(context.Background(), &clientCtx))
	recover.SetOut(&output)
	recover.SetArgs([]string{
		"2",
		"3",
		base64.StdEncoding.EncodeToString(newPublicKey),
		base64.StdEncoding.EncodeToString(make([]byte, proofSize)),
		"--" + flagRecoveryBundleOutput,
		preparedPath,
		"--" + flags.FlagFrom,
		"alice",
	})
	require.NoError(t, recover.Execute())
	require.Contains(t, output.String(), `"status":"prepared"`)

	preparedBytes, err := os.ReadFile(preparedPath)
	require.NoError(t, err)
	prepared, preparedSummary, err := pqcauthclient.UnmarshalRecoverySignBundle(
		txConfig,
		preparedBytes,
		false,
	)
	require.NoError(t, err)
	require.False(t, preparedSummary.Signed)
	require.Equal(t, uint64(2), preparedSummary.RecoveryKeyID)
	require.Empty(t, prepared.RecoverySignature)

	output.Reset()
	sign := signRecoveryBundleCommand()
	sign.SetContext(attachClientContext(context.Background(), &clientCtx))
	sign.SetOut(&output)
	sign.SetArgs([]string{
		preparedPath,
		privateKeyPath,
		signedPath,
		"--" + flags.FlagSkipConfirmation,
	})
	require.NoError(t, sign.Execute())
	require.Contains(t, output.String(), `"status":"signed"`)

	signedBytes, err := os.ReadFile(signedPath)
	require.NoError(t, err)
	_, signedSummary, err := pqcauthclient.UnmarshalRecoverySignBundle(
		txConfig,
		signedBytes,
		true,
	)
	require.NoError(t, err)
	require.True(t, signedSummary.Signed)

	output.Reset()
	broadcast := broadcastRecoveryBundleCommand()
	broadcast.SetContext(attachClientContext(context.Background(), &clientCtx))
	broadcast.SetOut(&output)
	broadcast.SetArgs([]string{
		signedPath,
		"--" + flags.FlagFrom,
		"alice",
		"--" + flags.FlagSkipConfirmation,
	})
	require.NoError(t, broadcast.Execute())
	require.Contains(t, output.String(), `"code":0`)

	output.Reset()
	direct := recoverKeyCommand()
	direct.SetContext(attachClientContext(context.Background(), &clientCtx))
	direct.SetOut(&output)
	direct.SetArgs([]string{
		"2",
		"3",
		base64.StdEncoding.EncodeToString(newPublicKey),
		base64.StdEncoding.EncodeToString(make([]byte, proofSize)),
		"--" + flagRecoveryPrivateKey,
		privateKeyPath,
		"--" + flags.FlagFrom,
		"alice",
		"--" + flags.FlagSkipConfirmation,
	})
	require.NoError(t, direct.Execute())
	require.Contains(t, output.String(), `"code":0`)

	output.Reset()
	protected := setProtectionCommand()
	protected.SetContext(attachClientContext(context.Background(), &clientCtx))
	protected.SetOut(&output)
	protected.SetArgs([]string{
		"true",
		"--" + flagPQCPrivateKey,
		signingKeyPath,
		"--" + flags.FlagFrom,
		"alice",
		"--" + flags.FlagSkipConfirmation,
	})
	require.NoError(t, protected.Execute())
	require.Contains(t, output.String(), `"code":0`)

	output.Reset()
	protectedBundlePath := filepath.Join(directory, "protected.pqc-bundle")
	protectedBundle := setProtectionCommand()
	protectedBundle.SetContext(attachClientContext(context.Background(), &clientCtx))
	protectedBundle.SetOut(&output)
	protectedBundle.SetArgs([]string{
		"true",
		"--" + flagPQCSignBundleOutput,
		protectedBundlePath,
		"--" + flags.FlagFrom,
		"alice",
	})
	require.NoError(t, protectedBundle.Execute())
	require.Contains(t, output.String(), `"status":"prepared"`)
	_, err = os.Stat(protectedBundlePath)
	require.NoError(t, err)

	var review bytes.Buffer
	printRecoveryBundleReview(&review, signedSummary, []byte(`{"body":{}}`))
	require.Contains(t, review.String(), "chain_id: pqc-cli-recovery-test-1")
	require.Contains(t, review.String(), "transaction_json:")

	var result bytes.Buffer
	require.NoError(t, printRecoveryBundleResult(
		&result,
		"signed",
		signedPath,
		signedSummary,
	))
	var decoded recoveryBundleCommandResult
	require.NoError(t, json.Unmarshal(result.Bytes(), &decoded))
	require.Equal(t, "signed", decoded.Status)
	require.True(t, decoded.Signed)
}

func TestRecoveryCommandsRejectUnsafeModesAndInputs(t *testing.T) {
	command := recoverKeyCommand()
	message := &types.MsgRecoverKey{
		Owner: sdk.AccAddress(bytes.Repeat([]byte{0x86}, 20)).String(),
	}

	err := generateOrBroadcastRecoveryTx(
		context.Background(),
		client.Context{GenerateOnly: true},
		command.Flags(),
		"",
		message,
	)
	require.ErrorContains(t, err, "use --"+flagRecoveryBundleOutput)

	err = generateOrBroadcastRecoveryTx(
		context.Background(),
		client.Context{},
		command.Flags(),
		"",
		message,
	)
	require.ErrorContains(t, err, "either --"+flagRecoveryPrivateKey)

	require.NoError(t, command.Flags().Set(flagRecoveryBundleOutput, "bundle.out"))
	err = generateOrBroadcastRecoveryTx(
		context.Background(),
		client.Context{},
		command.Flags(),
		"private.key",
		message,
	)
	require.ErrorContains(t, err, "mutually exclusive")

	var output bytes.Buffer
	clientCtx := cliTestClientContext(t, &output)
	directory := t.TempDir()
	missing := filepath.Join(directory, "missing")

	sign := signRecoveryBundleCommand()
	sign.SetContext(attachClientContext(context.Background(), &clientCtx))
	sign.SetArgs([]string{missing, missing, filepath.Join(directory, "signed")})
	require.ErrorContains(t, sign.Execute(), "open recovery sign bundle")

	broadcast := broadcastRecoveryBundleCommand()
	offline := clientCtx.WithOffline(true)
	broadcast.SetContext(attachClientContext(context.Background(), &offline))
	broadcast.SetArgs([]string{missing})
	require.ErrorContains(t, broadcast.Execute(), "online, non-simulation")

	broadcast = broadcastRecoveryBundleCommand()
	broadcast.SetContext(attachClientContext(context.Background(), &clientCtx))
	require.NoError(t, broadcast.Flags().Set(flags.FlagGas, "123"))
	broadcast.SetArgs([]string{missing})
	require.ErrorContains(t, broadcast.Execute(), "cannot override")
}

type cliProtoTxProvider interface {
	GetProtoTx() *txtypes.Tx
}

func TestSignBundleCommandOfflineRoundTrip(t *testing.T) {
	var output bytes.Buffer
	clientCtx := cliTestClientContext(t, &output)
	txConfig := clientCtx.TxConfig
	classicalPublicKey := secp256k1.GenPrivKey().PubKey()
	signer := sdk.AccAddress(classicalPublicKey.Address())
	builder := txConfig.NewTxBuilder()
	require.NoError(t, builder.SetMsgs(banktypes.NewMsgSend(
		signer,
		sdk.AccAddress(make([]byte, 20)),
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
	provider := builder.GetTx().(cliProtoTxProvider)
	params := types.DefaultParams()
	signDoc, err := types.NewPQCSignDocV1(
		provider.GetProtoTx(),
		params.NetworkId,
		"pqc-cli-bundle-test-1",
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
	bundle := &pqcauthclient.PQCSignBundleV1{
		Format:           pqcauthclient.PQCSignBundleFormatV1,
		UnsignedTx:       unsignedTx,
		UnsignedTxSHA256: txHash[:],
		SignDoc:          signBytes,
		SignDocSHA256:    signDocHash[:],
		OnChainPublicKey: publicKey,
	}
	encoded, err := pqcauthclient.MarshalPQCSignBundle(txConfig, bundle, false)
	require.NoError(t, err)
	directory := t.TempDir()
	preparedPath := filepath.Join(directory, "prepared.pqcbundle")
	privateKeyPath := filepath.Join(directory, "account.mldsa65")
	signedPath := filepath.Join(directory, "signed.pqcbundle")
	require.NoError(t, os.WriteFile(preparedPath, encoded, 0o600))
	require.NoError(t, os.WriteFile(privateKeyPath, privateKey, 0o600))

	command := signBundleCommand()
	command.SetContext(attachClientContext(context.Background(), &clientCtx))
	command.SetOut(&output)
	command.SetArgs([]string{
		preparedPath,
		privateKeyPath,
		signedPath,
		"--" + flags.FlagSkipConfirmation,
	})
	require.NoError(t, command.Execute())
	require.Contains(t, output.String(), `"status":"signed"`)

	signedBytes, err := os.ReadFile(signedPath)
	require.NoError(t, err)
	_, summary, err := pqcauthclient.UnmarshalPQCSignBundle(
		txConfig,
		signedBytes,
		true,
	)
	require.NoError(t, err)
	require.True(t, summary.Signed)
}

func TestOnlineBundleCommandsRejectModesMutationsAndMissingFiles(t *testing.T) {
	var output bytes.Buffer
	baseClientCtx := cliTestClientContext(t, &output)
	directory := t.TempDir()
	missing := filepath.Join(directory, "missing")
	outputPath := filepath.Join(directory, "prepared.pqcbundle")

	prepare := prepareBundleCommand()
	offline := baseClientCtx.WithOffline(true)
	prepare.SetContext(attachClientContext(context.Background(), &offline))
	prepare.SetArgs([]string{missing, outputPath})
	require.ErrorContains(t, prepare.Execute(), "online, non-simulation")

	prepare = prepareBundleCommand()
	prepare.SetContext(attachClientContext(context.Background(), &baseClientCtx))
	prepare.SetArgs([]string{missing, outputPath})
	require.ErrorContains(t, prepare.Execute(), "open unsigned transaction JSON")

	prepare = prepareBundleCommand()
	prepare.SetContext(attachClientContext(context.Background(), &baseClientCtx))
	require.NoError(t, prepare.Flags().Set(flags.FlagGas, "123"))
	prepare.SetArgs([]string{missing, outputPath})
	require.ErrorContains(t, prepare.Execute(), "cannot override")

	broadcast := broadcastBundleCommand()
	broadcast.SetContext(attachClientContext(context.Background(), &offline))
	broadcast.SetArgs([]string{missing})
	require.ErrorContains(t, broadcast.Execute(), "online, non-simulation")

	broadcast = broadcastBundleCommand()
	broadcast.SetContext(attachClientContext(context.Background(), &baseClientCtx))
	broadcast.SetArgs([]string{missing})
	require.ErrorContains(t, broadcast.Execute(), "open PQC sign bundle")
}
