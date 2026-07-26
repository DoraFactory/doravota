package ante

import (
	"bytes"
	"testing"

	dbm "github.com/cometbft/cometbft-db"
	"github.com/cometbft/cometbft/libs/log"
	tmproto "github.com/cometbft/cometbft/proto/tendermint/types"
	"github.com/cosmos/cosmos-sdk/client"
	"github.com/cosmos/cosmos-sdk/codec"
	codectypes "github.com/cosmos/cosmos-sdk/codec/types"
	"github.com/cosmos/cosmos-sdk/crypto/keys/secp256k1"
	"github.com/cosmos/cosmos-sdk/store"
	storetypes "github.com/cosmos/cosmos-sdk/store/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
	txsigning "github.com/cosmos/cosmos-sdk/types/tx/signing"
	authante "github.com/cosmos/cosmos-sdk/x/auth/ante"
	authtx "github.com/cosmos/cosmos-sdk/x/auth/tx"
	authtypes "github.com/cosmos/cosmos-sdk/x/auth/types"
	"github.com/cosmos/cosmos-sdk/x/authz"
	"github.com/stretchr/testify/require"

	pqccrypto "github.com/DoraFactory/doravota/x/pqcauth/crypto"
	pqckeeper "github.com/DoraFactory/doravota/x/pqcauth/keeper"
	"github.com/DoraFactory/doravota/x/pqcauth/types"
)

type accountKeeperMock struct {
	account authtypes.AccountI
}

type gasCharge struct {
	amount     storetypes.Gas
	descriptor string
}

type recordingGasMeter struct {
	storetypes.GasMeter
	charges []gasCharge
}

func newRecordingGasMeter() *recordingGasMeter {
	return &recordingGasMeter{GasMeter: sdk.NewInfiniteGasMeter()}
}

func (m *recordingGasMeter) ConsumeGas(amount storetypes.Gas, descriptor string) {
	m.charges = append(m.charges, gasCharge{
		amount:     amount,
		descriptor: descriptor,
	})
	m.GasMeter.ConsumeGas(amount, descriptor)
}

func (m *recordingGasMeter) chargesFor(descriptor string) []gasCharge {
	var matches []gasCharge
	for _, charge := range m.charges {
		if charge.descriptor == descriptor {
			matches = append(matches, charge)
		}
	}
	return matches
}

var _ authante.AccountKeeper = accountKeeperMock{}

func (m accountKeeperMock) GetParams(sdk.Context) authtypes.Params { return authtypes.DefaultParams() }
func (m accountKeeperMock) GetAccount(_ sdk.Context, address sdk.AccAddress) authtypes.AccountI {
	if m.account != nil && m.account.GetAddress().Equals(address) {
		return m.account
	}
	return nil
}
func (m accountKeeperMock) SetAccount(sdk.Context, authtypes.AccountI) {}
func (m accountKeeperMock) GetModuleAddress(string) sdk.AccAddress     { return nil }

func setupAnteTest(
	t testing.TB,
) (sdk.Context, pqckeeper.Keeper, accountKeeperMock, client.TxConfig, []byte) {
	t.Helper()
	registry := codectypes.NewInterfaceRegistry()
	types.RegisterInterfaces(registry)
	authz.RegisterInterfaces(registry)
	cdc := codec.NewProtoCodec(registry)
	txConfig := authtx.NewTxConfig(cdc, authtx.DefaultSignModes)

	storeKey := sdk.NewKVStoreKey(types.StoreKey)
	database := dbm.NewMemDB()
	multiStore := store.NewCommitMultiStore(database)
	multiStore.MountStoreWithDB(storeKey, storetypes.StoreTypeIAVL, nil)
	require.NoError(t, multiStore.LoadLatestVersion())
	ctx := sdk.NewContext(
		multiStore,
		tmproto.Header{Height: 10},
		false,
		log.NewNopLogger(),
	).WithChainID("pqcauth-ante-test-1")

	classicalPrivateKey := secp256k1.GenPrivKey()
	address := sdk.AccAddress(classicalPrivateKey.PubKey().Address())
	account := authtypes.NewBaseAccountWithAddress(address)
	require.NoError(t, account.SetPubKey(classicalPrivateKey.PubKey()))
	require.NoError(t, account.SetAccountNumber(9))
	require.NoError(t, account.SetSequence(7))

	moduleKeeper := pqckeeper.NewKeeper(cdc, storeKey, address.String())
	require.NoError(t, moduleKeeper.SetParams(ctx, types.DefaultParams()))
	publicKey, privateKey, err := pqccrypto.GenerateMLDSA65Key(nil)
	require.NoError(t, err)
	require.NoError(t, moduleKeeper.SetKey(ctx, address, types.PQCKeyRecord{
		Owner:           address.String(),
		KeyId:           1,
		Algorithm:       types.Algorithm_ALGORITHM_ML_DSA_65,
		PublicKey:       publicKey,
		Role:            types.KeyRole_KEY_ROLE_SIGNING,
		Status:          types.KeyStatus_KEY_STATUS_LIVE,
		EffectiveHeight: 1,
	}))
	require.NoError(t, moduleKeeper.SetAccountPolicy(ctx, address, types.AccountPolicy{
		Owner:               address.String(),
		CurrentSigningKeyId: 1,
		SelfEnforced:        true,
		PolicyVersion:       1,
	}))
	return ctx, moduleKeeper, accountKeeperMock{account: account}, txConfig, privateKey
}

func buildProtectedTx(
	t testing.TB,
	ctx sdk.Context,
	moduleKeeper pqckeeper.Keeper,
	accountKeeper accountKeeperMock,
	txConfig client.TxConfig,
	privateKey []byte,
) (client.TxBuilder, sdk.Tx) {
	t.Helper()
	account := accountKeeper.account
	builder := txConfig.NewTxBuilder()
	require.NoError(t, builder.SetMsgs(&types.MsgSetProtection{
		Owner:   account.GetAddress().String(),
		Enabled: false,
	}))
	builder.SetGasLimit(1_000_000)
	require.NoError(t, builder.SetSignatures(txsigning.SignatureV2{
		PubKey: account.GetPubKey(),
		Data: &txsigning.SingleSignatureData{
			SignMode:  txsigning.SignMode_SIGN_MODE_DIRECT,
			Signature: bytes.Repeat([]byte{0x01}, 64),
		},
		Sequence: account.GetSequence(),
	}))

	provider := builder.GetTx().(protoTxProvider)
	key, policy, active := moduleKeeper.GetActiveSigningKey(ctx, account.GetAddress())
	require.True(t, active)
	signDoc, err := types.NewPQCSignDocV1(
		provider.GetProtoTx(),
		moduleKeeper.GetParams(ctx).NetworkId,
		ctx.ChainID(),
		account.GetAccountNumber(),
		account.GetSequence(),
		0,
		account.GetAddress().String(),
		key.KeyId,
		key.Algorithm,
		policy.PolicyVersion,
	)
	require.NoError(t, err)
	signBytes, err := types.MarshalPQCSignDocV1(signDoc)
	require.NoError(t, err)
	signature, err := pqccrypto.SignMLDSA65(
		privateKey,
		signBytes,
		[]byte(types.TxSignatureContext),
		false,
	)
	require.NoError(t, err)
	extension := &types.ExtensionPQCAuth{
		FormatVersion: types.FormatVersionV1,
		Signatures: []types.SignerPQCSignature{{
			Signer:        account.GetAddress().String(),
			SignerIndex:   0,
			KeyId:         key.KeyId,
			Algorithm:     key.Algorithm,
			PolicyVersion: policy.PolicyVersion,
			Signature:     signature,
		}},
	}
	anyExtension, err := codectypes.NewAnyWithValue(extension)
	require.NoError(t, err)
	require.Equal(t, types.ExtensionPQCAuthTypeURL, anyExtension.TypeUrl)
	extensionBuilder := builder.(authtx.ExtensionOptionsTxBuilder)
	extensionBuilder.SetExtensionOptions(anyExtension)
	return builder, builder.GetTx()
}

func TestVerifyPQCDecoratorAcceptsValidHybridAuthorization(t *testing.T) {
	ctx, moduleKeeper, accountKeeper, txConfig, privateKey := setupAnteTest(t)
	_, tx := buildProtectedTx(t, ctx, moduleKeeper, accountKeeper, txConfig, privateKey)
	decorator := NewVerifyPQCDecorator(moduleKeeper, accountKeeper)
	called := false

	_, err := decorator.AnteHandle(ctx, tx, false, func(
		nextCtx sdk.Context,
		_ sdk.Tx,
		_ bool,
	) (sdk.Context, error) {
		called = true
		return nextCtx, nil
	})
	require.NoError(t, err)
	require.True(t, called)
}

func TestSimulationWithoutExtensionConsumesRequiredSignatureGas(t *testing.T) {
	ctx, moduleKeeper, accountKeeper, txConfig, _ := setupAnteTest(t)
	gasMeter := newRecordingGasMeter()
	ctx = ctx.WithGasMeter(gasMeter)
	builder := txConfig.NewTxBuilder()
	message := &types.MsgSetProtection{
		Owner:   accountKeeper.account.GetAddress().String(),
		Enabled: false,
	}
	require.NoError(t, builder.SetMsgs(message))
	builder.SetGasLimit(1_000_000)
	require.NoError(t, builder.SetSignatures(txsigning.SignatureV2{
		PubKey: accountKeeper.account.GetPubKey(),
		Data: &txsigning.SingleSignatureData{
			SignMode: txsigning.SignMode_SIGN_MODE_DIRECT,
		},
		Sequence: accountKeeper.account.GetSequence(),
	}))

	called := false
	_, err := NewVerifyPQCDecorator(moduleKeeper, accountKeeper).AnteHandle(
		ctx,
		builder.GetTx(),
		true,
		func(nextCtx sdk.Context, _ sdk.Tx, _ bool) (sdk.Context, error) {
			called = true
			return nextCtx, nil
		},
	)
	require.NoError(t, err)
	require.True(t, called)
	charges := gasMeter.chargesFor("simulated pqcauth signature verification")
	require.Equal(t, []gasCharge{{
		amount:     moduleKeeper.GetParams(ctx).EffectiveSignatureVerificationGas(),
		descriptor: "simulated pqcauth signature verification",
	}}, charges)

	_, err = NewVerifyPQCDecorator(moduleKeeper, accountKeeper).AnteHandle(
		ctx.WithGasMeter(sdk.NewInfiniteGasMeter()),
		builder.GetTx(),
		false,
		func(nextCtx sdk.Context, _ sdk.Tx, _ bool) (sdk.Context, error) {
			return nextCtx, nil
		},
	)
	require.ErrorIs(t, err, types.ErrPQCRequired)
}

func TestSimulationSkipsPQCSignatureCryptoButDeliveryRejectsPlaceholder(t *testing.T) {
	ctx, moduleKeeper, accountKeeper, txConfig, privateKey := setupAnteTest(t)
	builder, tx := buildProtectedTx(
		t,
		ctx,
		moduleKeeper,
		accountKeeper,
		txConfig,
		privateKey,
	)
	provider := tx.(protoTxProvider)
	var extension types.ExtensionPQCAuth
	require.NoError(
		t,
		extension.Unmarshal(provider.GetProtoTx().Body.ExtensionOptions[0].Value),
	)
	require.Len(t, extension.Signatures, 1)
	clear(extension.Signatures[0].Signature)
	encoded, err := extension.Marshal()
	require.NoError(t, err)
	provider.GetProtoTx().Body.ExtensionOptions[0].Value = encoded
	tx = builder.GetTx()

	gasMeter := newRecordingGasMeter()
	simulationCtx := ctx.WithGasMeter(gasMeter)
	_, err = NewVerifyPQCDecorator(moduleKeeper, accountKeeper).AnteHandle(
		simulationCtx,
		tx,
		true,
		func(nextCtx sdk.Context, _ sdk.Tx, _ bool) (sdk.Context, error) {
			return nextCtx, nil
		},
	)
	require.NoError(t, err)
	charges := gasMeter.chargesFor("simulated pqcauth signature verification")
	require.Equal(t, []gasCharge{{
		amount:     moduleKeeper.GetParams(ctx).EffectiveSignatureVerificationGas(),
		descriptor: "simulated pqcauth signature verification",
	}}, charges)

	_, err = NewVerifyPQCDecorator(moduleKeeper, accountKeeper).AnteHandle(
		ctx.WithGasMeter(sdk.NewInfiniteGasMeter()),
		tx,
		false,
		func(nextCtx sdk.Context, _ sdk.Tx, _ bool) (sdk.Context, error) {
			return nextCtx, nil
		},
	)
	require.ErrorIs(t, err, types.ErrUnauthorized)
}

func TestLifecycleSimulationChargesProofAndRequiredSignatureGas(t *testing.T) {
	ctx, moduleKeeper, accountKeeper, txConfig, _ := setupAnteTest(t)
	address := accountKeeper.account.GetAddress()
	require.NoError(t, moduleKeeper.SetKeySequence(ctx, address, types.AccountKeySequence{
		Owner:     address.String(),
		NextKeyId: 2,
	}))
	newPublicKey, _, err := pqccrypto.GenerateMLDSA65Key(nil)
	require.NoError(t, err)
	algorithm, err := types.CryptoAlgorithm(types.Algorithm_ALGORITHM_ML_DSA_65)
	require.NoError(t, err)
	_, signatureSize, err := pqccrypto.Sizes(algorithm)
	require.NoError(t, err)
	message := &types.MsgRotateKey{
		Owner:            address.String(),
		ExpectedNewKeyId: 2,
		NewAlgorithm:     types.Algorithm_ALGORITHM_ML_DSA_65,
		NewPublicKey:     newPublicKey,
		NewKeyProof:      make([]byte, signatureSize),
	}
	builder := txConfig.NewTxBuilder()
	require.NoError(t, builder.SetMsgs(message))
	builder.SetGasLimit(1_000_000)
	require.NoError(t, builder.SetSignatures(txsigning.SignatureV2{
		PubKey: accountKeeper.account.GetPubKey(),
		Data: &txsigning.SingleSignatureData{
			SignMode: txsigning.SignMode_SIGN_MODE_DIRECT,
		},
		Sequence: accountKeeper.account.GetSequence(),
	}))

	gasMeter := newRecordingGasMeter()
	simulationCtx := ctx.WithGasMeter(gasMeter)
	_, err = NewVerifyPQCDecorator(moduleKeeper, accountKeeper).AnteHandle(
		simulationCtx,
		builder.GetTx(),
		true,
		func(nextCtx sdk.Context, _ sdk.Tx, _ bool) (sdk.Context, error) {
			return nextCtx, nil
		},
	)
	require.NoError(t, err)
	params := moduleKeeper.GetParams(ctx)
	require.Equal(t, []gasCharge{{
		amount:     params.EffectiveProofVerificationGas(),
		descriptor: "simulated pqcauth key proof verification",
	}}, gasMeter.chargesFor("simulated pqcauth key proof verification"))
	require.Equal(t, []gasCharge{{
		amount:     params.EffectiveSignatureVerificationGas(),
		descriptor: "simulated pqcauth signature verification",
	}}, gasMeter.chargesFor("simulated pqcauth signature verification"))

	_, err = NewVerifyPQCDecorator(moduleKeeper, accountKeeper).AnteHandle(
		ctx.WithGasMeter(sdk.NewInfiniteGasMeter()),
		builder.GetTx(),
		false,
		func(nextCtx sdk.Context, _ sdk.Tx, _ bool) (sdk.Context, error) {
			return nextCtx, nil
		},
	)
	require.ErrorIs(t, err, types.ErrInvalidKeyProof)
}

func TestRecoverySimulationChargesProofsWithoutSubstitutedTransactionSignature(t *testing.T) {
	ctx, moduleKeeper, accountKeeper, txConfig, _ := setupAnteTest(t)
	address := accountKeeper.account.GetAddress()
	recoveryPublicKey, _, err := pqccrypto.GenerateMLDSA65Key(nil)
	require.NoError(t, err)
	require.NoError(t, moduleKeeper.SetKey(ctx, address, types.PQCKeyRecord{
		Owner:           address.String(),
		KeyId:           2,
		Algorithm:       types.Algorithm_ALGORITHM_ML_DSA_65,
		PublicKey:       recoveryPublicKey,
		Role:            types.KeyRole_KEY_ROLE_RECOVERY,
		Status:          types.KeyStatus_KEY_STATUS_LIVE,
		EffectiveHeight: 1,
	}))
	policy, found := moduleKeeper.GetEffectiveAccountPolicy(ctx, address)
	require.True(t, found)
	policy.RecoveryKeyId = 2
	require.NoError(t, moduleKeeper.SetAccountPolicy(ctx, address, policy))
	require.NoError(t, moduleKeeper.SetKeySequence(ctx, address, types.AccountKeySequence{
		Owner:     address.String(),
		NextKeyId: 3,
	}))
	newPublicKey, _, err := pqccrypto.GenerateMLDSA65Key(nil)
	require.NoError(t, err)
	algorithm, err := types.CryptoAlgorithm(types.Algorithm_ALGORITHM_ML_DSA_65)
	require.NoError(t, err)
	_, signatureSize, err := pqccrypto.Sizes(algorithm)
	require.NoError(t, err)
	message := &types.MsgRecoverKey{
		Owner:                   address.String(),
		RecoveryKeyId:           2,
		RecoverySignature:       make([]byte, signatureSize),
		ExpectedNewSigningKeyId: 3,
		NewSigningAlgorithm:     types.Algorithm_ALGORITHM_ML_DSA_65,
		NewSigningPublicKey:     newPublicKey,
		NewSigningKeyProof:      make([]byte, signatureSize),
	}
	builder := txConfig.NewTxBuilder()
	require.NoError(t, builder.SetMsgs(message))
	builder.SetGasLimit(1_000_000)
	require.NoError(t, builder.SetSignatures(txsigning.SignatureV2{
		PubKey: accountKeeper.account.GetPubKey(),
		Data: &txsigning.SingleSignatureData{
			SignMode: txsigning.SignMode_SIGN_MODE_DIRECT,
		},
		Sequence: accountKeeper.account.GetSequence(),
	}))

	gasMeter := newRecordingGasMeter()
	simulationCtx := ctx.WithGasMeter(gasMeter)
	_, err = NewVerifyPQCDecorator(moduleKeeper, accountKeeper).AnteHandle(
		simulationCtx,
		builder.GetTx(),
		true,
		func(nextCtx sdk.Context, _ sdk.Tx, _ bool) (sdk.Context, error) {
			return nextCtx, nil
		},
	)
	require.NoError(t, err)
	params := moduleKeeper.GetParams(ctx)
	require.Equal(t, []gasCharge{{
		amount:     params.EffectiveProofVerificationGas(),
		descriptor: "simulated pqcauth key proof verification",
	}}, gasMeter.chargesFor("simulated pqcauth key proof verification"))
	require.Equal(t, []gasCharge{{
		amount:     params.EffectiveProofVerificationGas(),
		descriptor: "simulated pqcauth recovery signature verification",
	}}, gasMeter.chargesFor("simulated pqcauth recovery signature verification"))
	require.Empty(t, gasMeter.chargesFor("simulated pqcauth signature verification"))

	_, err = NewVerifyPQCDecorator(moduleKeeper, accountKeeper).AnteHandle(
		ctx.WithGasMeter(sdk.NewInfiniteGasMeter()),
		builder.GetTx(),
		false,
		func(nextCtx sdk.Context, _ sdk.Tx, _ bool) (sdk.Context, error) {
			return nextCtx, nil
		},
	)
	require.ErrorIs(t, err, types.ErrInvalidKeyProof)
}

func TestVerifyPQCDecoratorRejectsMissingOrFeeTamperedAuthorization(t *testing.T) {
	ctx, moduleKeeper, accountKeeper, txConfig, privateKey := setupAnteTest(t)
	decorator := NewVerifyPQCDecorator(moduleKeeper, accountKeeper)

	unprotectedBuilder := txConfig.NewTxBuilder()
	require.NoError(t, unprotectedBuilder.SetMsgs(&types.MsgSetProtection{
		Owner: accountKeeper.account.GetAddress().String(),
	}))
	unprotectedBuilder.SetGasLimit(1_000_000)
	require.NoError(t, unprotectedBuilder.SetSignatures(txsigning.SignatureV2{
		PubKey: accountKeeper.account.GetPubKey(),
		Data: &txsigning.SingleSignatureData{
			SignMode:  txsigning.SignMode_SIGN_MODE_DIRECT,
			Signature: bytes.Repeat([]byte{0x01}, 64),
		},
		Sequence: accountKeeper.account.GetSequence(),
	}))
	_, err := decorator.AnteHandle(
		ctx,
		unprotectedBuilder.GetTx(),
		false,
		func(nextCtx sdk.Context, _ sdk.Tx, _ bool) (sdk.Context, error) { return nextCtx, nil },
	)
	require.ErrorIs(t, err, types.ErrPQCRequired)

	protectedBuilder, protectedTx := buildProtectedTx(
		t,
		ctx,
		moduleKeeper,
		accountKeeper,
		txConfig,
		privateKey,
	)
	protectedBuilder.SetFeeAmount(sdk.NewCoins(sdk.NewInt64Coin("peaka", 1)))
	_, err = decorator.AnteHandle(
		ctx,
		protectedTx,
		false,
		func(nextCtx sdk.Context, _ sdk.Tx, _ bool) (sdk.Context, error) { return nextCtx, nil },
	)
	require.ErrorIs(t, err, types.ErrUnauthorized)
}

func TestExtractExtensionRejectsUnknownFields(t *testing.T) {
	ctx, moduleKeeper, accountKeeper, txConfig, privateKey := setupAnteTest(t)
	_, protectedTx := buildProtectedTx(
		t,
		ctx,
		moduleKeeper,
		accountKeeper,
		txConfig,
		privateKey,
	)
	provider := protectedTx.(protoTxProvider)
	encoded := provider.GetProtoTx().Body.ExtensionOptions[0].Value
	provider.GetProtoTx().Body.ExtensionOptions[0].Value = append(
		append([]byte(nil), encoded...),
		0x98, 0x06, 0x01, // unknown field 99, varint 1
	)
	_, _, err := ExtractExtension(protectedTx, moduleKeeper.GetParams(ctx))
	require.ErrorIs(t, err, types.ErrInvalidExtension)
}

func TestValidatedExtensionCacheIsBoundToExtensionOptions(t *testing.T) {
	ctx, moduleKeeper, accountKeeper, txConfig, privateKey := setupAnteTest(t)
	structureDecorator := NewValidatePQCStructureDecorator(moduleKeeper)
	verifyDecorator := NewVerifyPQCDecorator(moduleKeeper, accountKeeper)

	_, unchangedTx := buildProtectedTx(
		t,
		ctx,
		moduleKeeper,
		accountKeeper,
		txConfig,
		privateKey,
	)
	called := false
	_, err := structureDecorator.AnteHandle(
		ctx,
		unchangedTx,
		false,
		func(structureCtx sdk.Context, tx sdk.Tx, simulate bool) (sdk.Context, error) {
			return verifyDecorator.AnteHandle(
				structureCtx,
				tx,
				simulate,
				func(nextCtx sdk.Context, _ sdk.Tx, _ bool) (sdk.Context, error) {
					called = true
					return nextCtx, nil
				},
			)
		},
	)
	require.NoError(t, err)
	require.True(t, called)

	_, mutatedTx := buildProtectedTx(
		t,
		ctx,
		moduleKeeper,
		accountKeeper,
		txConfig,
		privateKey,
	)
	_, err = structureDecorator.AnteHandle(
		ctx,
		mutatedTx,
		false,
		func(structureCtx sdk.Context, tx sdk.Tx, simulate bool) (sdk.Context, error) {
			provider := tx.(protoTxProvider)
			encoded := provider.GetProtoTx().Body.ExtensionOptions[0].Value
			provider.GetProtoTx().Body.ExtensionOptions[0].Value = append(
				append([]byte(nil), encoded...),
				0x98, 0x06, 0x01,
			)
			return verifyDecorator.AnteHandle(
				structureCtx,
				tx,
				simulate,
				func(nextCtx sdk.Context, _ sdk.Tx, _ bool) (sdk.Context, error) {
					return nextCtx, nil
				},
			)
		},
	)
	require.ErrorIs(t, err, types.ErrInvalidExtension)
}

func TestSelfEnforcementAndLifecycleCannotBeDisabledByGlobalOptionalMode(t *testing.T) {
	selfPolicy := types.AccountPolicy{SelfEnforced: true}
	require.True(t, pqcRequired(
		types.EnforcementMode_ENFORCEMENT_MODE_DISABLED,
		selfPolicy,
		true,
	))

	ctx, moduleKeeper, accountKeeper, txConfig, _ := setupAnteTest(t)
	address := accountKeeper.account.GetAddress()
	policy, found := moduleKeeper.GetEffectiveAccountPolicy(ctx, address)
	require.True(t, found)
	policy.SelfEnforced = false
	require.NoError(t, moduleKeeper.SetAccountPolicy(ctx, address, policy))

	builder := txConfig.NewTxBuilder()
	require.NoError(t, builder.SetMsgs(&types.MsgSetProtection{
		Owner:   address.String(),
		Enabled: true,
	}))
	builder.SetGasLimit(1_000_000)
	require.NoError(t, builder.SetSignatures(txsigning.SignatureV2{
		PubKey: accountKeeper.account.GetPubKey(),
		Data: &txsigning.SingleSignatureData{
			SignMode:  txsigning.SignMode_SIGN_MODE_DIRECT,
			Signature: bytes.Repeat([]byte{0x01}, 64),
		},
		Sequence: accountKeeper.account.GetSequence(),
	}))
	_, err := NewVerifyPQCDecorator(moduleKeeper, accountKeeper).AnteHandle(
		ctx,
		builder.GetTx(),
		false,
		func(nextCtx sdk.Context, _ sdk.Tx, _ bool) (sdk.Context, error) { return nextCtx, nil },
	)
	require.ErrorIs(t, err, types.ErrPQCRequired)
}

func TestRecoveryKeyRotationRequiresActivePQCWhenGlobalModeIsDisabled(t *testing.T) {
	ctx, moduleKeeper, accountKeeper, txConfig, _ := setupAnteTest(t)
	address := accountKeeper.account.GetAddress()
	params := moduleKeeper.GetParams(ctx)
	params.EnforcementMode = types.EnforcementMode_ENFORCEMENT_MODE_DISABLED
	require.NoError(t, moduleKeeper.SetParams(ctx, params))

	recoveryPublicKey, _, err := pqccrypto.GenerateMLDSA65Key(nil)
	require.NoError(t, err)
	require.NoError(t, moduleKeeper.SetKey(ctx, address, types.PQCKeyRecord{
		Owner:           address.String(),
		KeyId:           2,
		Algorithm:       types.Algorithm_ALGORITHM_ML_DSA_65,
		PublicKey:       recoveryPublicKey,
		Role:            types.KeyRole_KEY_ROLE_RECOVERY,
		Status:          types.KeyStatus_KEY_STATUS_LIVE,
		EffectiveHeight: 1,
	}))
	policy, found := moduleKeeper.GetEffectiveAccountPolicy(ctx, address)
	require.True(t, found)
	policy.SelfEnforced = false
	policy.RecoveryKeyId = 2
	require.NoError(t, moduleKeeper.SetAccountPolicy(ctx, address, policy))
	require.NoError(t, moduleKeeper.SetKeySequence(ctx, address, types.AccountKeySequence{
		Owner:     address.String(),
		NextKeyId: 3,
	}))

	newPublicKey, newPrivateKey, err := pqccrypto.GenerateMLDSA65Key(nil)
	require.NoError(t, err)
	proofBytes, err := types.MarshalKeyProofDocV1(types.KeyProofDocV1{
		FormatVersion:        types.FormatVersionV1,
		NetworkId:            params.NetworkId,
		ChainId:              ctx.ChainID(),
		Owner:                address.String(),
		ProposedKeyId:        3,
		Algorithm:            types.Algorithm_ALGORITHM_ML_DSA_65,
		PublicKey:            newPublicKey,
		Role:                 types.KeyRole_KEY_ROLE_RECOVERY,
		Purpose:              types.PurposeRotateRecovery,
		CurrentPolicyVersion: policy.PolicyVersion,
	})
	require.NoError(t, err)
	proof, err := pqccrypto.SignMLDSA65(
		newPrivateKey,
		proofBytes,
		[]byte(types.RotateRecoveryContext),
		false,
	)
	require.NoError(t, err)

	builder := txConfig.NewTxBuilder()
	require.NoError(t, builder.SetMsgs(&types.MsgRotateRecoveryKey{
		Owner:            address.String(),
		ExpectedNewKeyId: 3,
		NewAlgorithm:     types.Algorithm_ALGORITHM_ML_DSA_65,
		NewPublicKey:     newPublicKey,
		NewKeyProof:      proof,
	}))
	builder.SetGasLimit(1_000_000)
	require.NoError(t, builder.SetSignatures(txsigning.SignatureV2{
		PubKey: accountKeeper.account.GetPubKey(),
		Data: &txsigning.SingleSignatureData{
			SignMode:  txsigning.SignMode_SIGN_MODE_DIRECT,
			Signature: bytes.Repeat([]byte{0x01}, 64),
		},
		Sequence: accountKeeper.account.GetSequence(),
	}))

	_, err = NewVerifyPQCDecorator(moduleKeeper, accountKeeper).AnteHandle(
		ctx,
		builder.GetTx(),
		false,
		func(nextCtx sdk.Context, _ sdk.Tx, _ bool) (sdk.Context, error) {
			return nextCtx, nil
		},
	)
	require.ErrorIs(t, err, types.ErrPQCRequired)
}

func TestAuthzNestedLifecycleMessageCannotInheritAnteAuthorization(t *testing.T) {
	ctx, moduleKeeper, accountKeeper, txConfig, _ := setupAnteTest(t)
	address := accountKeeper.account.GetAddress()
	policy, found := moduleKeeper.GetEffectiveAccountPolicy(ctx, address)
	require.True(t, found)
	policy.SelfEnforced = false
	require.NoError(t, moduleKeeper.SetAccountPolicy(ctx, address, policy))

	innerMessage := &types.MsgSetProtection{
		Owner:   address.String(),
		Enabled: true,
	}
	execMessage := authz.NewMsgExec(address, []sdk.Msg{innerMessage})
	builder := txConfig.NewTxBuilder()
	require.NoError(t, builder.SetMsgs(&execMessage))
	builder.SetGasLimit(1_000_000)
	require.NoError(t, builder.SetSignatures(txsigning.SignatureV2{
		PubKey: accountKeeper.account.GetPubKey(),
		Data: &txsigning.SingleSignatureData{
			SignMode:  txsigning.SignMode_SIGN_MODE_DIRECT,
			Signature: bytes.Repeat([]byte{0x01}, 64),
		},
		Sequence: accountKeeper.account.GetSequence(),
	}))

	server := pqckeeper.NewMsgServer(moduleKeeper)
	_, err := NewVerifyPQCDecorator(moduleKeeper, accountKeeper).AnteHandle(
		ctx,
		builder.GetTx(),
		false,
		func(nextCtx sdk.Context, _ sdk.Tx, _ bool) (sdk.Context, error) {
			_, routeErr := server.SetProtection(
				sdk.WrapSDKContext(nextCtx),
				innerMessage,
			)
			return nextCtx, routeErr
		},
	)
	require.ErrorIs(t, err, types.ErrNestedLifecycle)
}

func TestRegisteredPolicyWithUnavailableSigningKeyFailsClosed(t *testing.T) {
	for _, mode := range []types.EnforcementMode{
		types.EnforcementMode_ENFORCEMENT_MODE_DISABLED,
		types.EnforcementMode_ENFORCEMENT_MODE_OPTIONAL,
		types.EnforcementMode_ENFORCEMENT_MODE_REQUIRED_FOR_REGISTERED,
		types.EnforcementMode_ENFORCEMENT_MODE_REQUIRED,
	} {
		t.Run(mode.String(), func(t *testing.T) {
			ctx, moduleKeeper, accountKeeper, txConfig, _ := setupAnteTest(t)
			address := accountKeeper.account.GetAddress()
			key, found := moduleKeeper.GetKey(ctx, address, 1)
			require.True(t, found)
			key.Status = types.KeyStatus_KEY_STATUS_REVOKED
			require.NoError(t, moduleKeeper.SetKey(ctx, address, key))
			params := moduleKeeper.GetParams(ctx)
			params.EnforcementMode = mode
			require.NoError(t, moduleKeeper.SetParams(ctx, params))

			builder := txConfig.NewTxBuilder()
			require.NoError(t, builder.SetMsgs(&types.MsgSetProtection{
				Owner:   address.String(),
				Enabled: false,
			}))
			builder.SetGasLimit(1_000_000)
			require.NoError(t, builder.SetSignatures(txsigning.SignatureV2{
				PubKey: accountKeeper.account.GetPubKey(),
				Data: &txsigning.SingleSignatureData{
					SignMode:  txsigning.SignMode_SIGN_MODE_DIRECT,
					Signature: bytes.Repeat([]byte{0x01}, 64),
				},
				Sequence: accountKeeper.account.GetSequence(),
			}))

			_, err := NewVerifyPQCDecorator(moduleKeeper, accountKeeper).AnteHandle(
				ctx,
				builder.GetTx(),
				false,
				func(nextCtx sdk.Context, _ sdk.Tx, _ bool) (sdk.Context, error) {
					return nextCtx, nil
				},
			)
			require.ErrorIs(t, err, types.ErrInconsistentState)
		})
	}
}

func TestRecoveryAuthorizationBindsCompleteTransactionIntent(t *testing.T) {
	type mutation struct {
		name   string
		mutate func(client.TxBuilder, accountKeeperMock)
	}
	testCases := []mutation{
		{name: "valid"},
		{
			name: "fee",
			mutate: func(builder client.TxBuilder, _ accountKeeperMock) {
				builder.SetFeeAmount(sdk.NewCoins(sdk.NewInt64Coin("peaka", 1)))
			},
		},
		{
			name: "gas",
			mutate: func(builder client.TxBuilder, _ accountKeeperMock) {
				builder.SetGasLimit(1_000_001)
			},
		},
		{
			name: "memo",
			mutate: func(builder client.TxBuilder, _ accountKeeperMock) {
				builder.SetMemo("tampered")
			},
		},
		{
			name: "timeout",
			mutate: func(builder client.TxBuilder, _ accountKeeperMock) {
				builder.SetTimeoutHeight(99)
			},
		},
		{
			name: "sequence",
			mutate: func(builder client.TxBuilder, accounts accountKeeperMock) {
				require.NoError(t, builder.SetSignatures(txsigning.SignatureV2{
					PubKey: accounts.account.GetPubKey(),
					Data: &txsigning.SingleSignatureData{
						SignMode:  txsigning.SignMode_SIGN_MODE_DIRECT,
						Signature: bytes.Repeat([]byte{0x01}, 64),
					},
					Sequence: accounts.account.GetSequence() + 1,
				}))
			},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			ctx, moduleKeeper, accountKeeper, txConfig, _ := setupAnteTest(t)
			address := accountKeeper.account.GetAddress()
			params := moduleKeeper.GetParams(ctx)
			recoveryPublicKey, recoveryPrivateKey, err := pqccrypto.GenerateMLDSA65Key(nil)
			require.NoError(t, err)
			require.NoError(t, moduleKeeper.SetKey(ctx, address, types.PQCKeyRecord{
				Owner:           address.String(),
				KeyId:           2,
				Algorithm:       types.Algorithm_ALGORITHM_ML_DSA_65,
				PublicKey:       recoveryPublicKey,
				Role:            types.KeyRole_KEY_ROLE_RECOVERY,
				Status:          types.KeyStatus_KEY_STATUS_LIVE,
				EffectiveHeight: 1,
			}))
			policy, found := moduleKeeper.GetEffectiveAccountPolicy(ctx, address)
			require.True(t, found)
			policy.RecoveryKeyId = 2
			require.NoError(t, moduleKeeper.SetAccountPolicy(ctx, address, policy))
			require.NoError(t, moduleKeeper.SetKeySequence(ctx, address, types.AccountKeySequence{
				Owner:     address.String(),
				NextKeyId: 3,
			}))

			newPublicKey, newPrivateKey, err := pqccrypto.GenerateMLDSA65Key(nil)
			require.NoError(t, err)
			proofDoc, err := types.MarshalKeyProofDocV1(types.KeyProofDocV1{
				FormatVersion:        types.FormatVersionV1,
				NetworkId:            params.NetworkId,
				ChainId:              ctx.ChainID(),
				Owner:                address.String(),
				ProposedKeyId:        3,
				Algorithm:            types.Algorithm_ALGORITHM_ML_DSA_65,
				PublicKey:            newPublicKey,
				Role:                 types.KeyRole_KEY_ROLE_SIGNING,
				Purpose:              types.PurposeRecoverSigning,
				CurrentPolicyVersion: policy.PolicyVersion,
			})
			require.NoError(t, err)
			newKeyProof, err := pqccrypto.SignMLDSA65(
				newPrivateKey,
				proofDoc,
				[]byte(types.RecoveryKeyProofContext),
				false,
			)
			require.NoError(t, err)
			_, signatureSize, err := pqccrypto.Sizes(pqccrypto.AlgorithmMLDSA65)
			require.NoError(t, err)
			message := &types.MsgRecoverKey{
				Owner:                   address.String(),
				RecoveryKeyId:           2,
				RecoverySignature:       make([]byte, signatureSize),
				ExpectedNewSigningKeyId: 3,
				NewSigningAlgorithm:     types.Algorithm_ALGORITHM_ML_DSA_65,
				NewSigningPublicKey:     newPublicKey,
				NewSigningKeyProof:      newKeyProof,
			}
			builder := txConfig.NewTxBuilder()
			require.NoError(t, builder.SetMsgs(message))
			builder.SetGasLimit(1_000_000)
			require.NoError(t, builder.SetSignatures(txsigning.SignatureV2{
				PubKey: accountKeeper.account.GetPubKey(),
				Data: &txsigning.SingleSignatureData{
					SignMode:  txsigning.SignMode_SIGN_MODE_DIRECT,
					Signature: bytes.Repeat([]byte{0x01}, 64),
				},
				Sequence: accountKeeper.account.GetSequence(),
			}))
			provider := builder.GetTx().(protoTxProvider)
			recoveryDoc, err := types.NewRecoverySignDocV1(
				provider.GetProtoTx(),
				params.NetworkId,
				ctx.ChainID(),
				accountKeeper.account.GetAccountNumber(),
				accountKeeper.account.GetSequence(),
				0,
				address.String(),
				address.String(),
				2,
				3,
				types.Algorithm_ALGORITHM_ML_DSA_65,
				newPublicKey,
				policy.PolicyVersion,
			)
			require.NoError(t, err)
			recoverySignBytes, err := types.MarshalRecoverySignDocV1(recoveryDoc)
			require.NoError(t, err)
			message.RecoverySignature, err = pqccrypto.SignMLDSA65(
				recoveryPrivateKey,
				recoverySignBytes,
				[]byte(types.RecoverySignatureContext),
				false,
			)
			require.NoError(t, err)
			require.NoError(t, builder.SetMsgs(message))

			if testCase.mutate != nil {
				testCase.mutate(builder, accountKeeper)
			}
			called := false
			_, err = NewVerifyPQCDecorator(moduleKeeper, accountKeeper).AnteHandle(
				ctx,
				builder.GetTx(),
				false,
				func(nextCtx sdk.Context, _ sdk.Tx, _ bool) (sdk.Context, error) {
					called = true
					return nextCtx, nil
				},
			)
			if testCase.mutate == nil {
				require.NoError(t, err)
				require.True(t, called)
			} else {
				require.ErrorIs(t, err, types.ErrUnauthorized)
				require.False(t, called)
			}
		})
	}
}
