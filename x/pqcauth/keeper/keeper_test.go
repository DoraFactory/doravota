package keeper

import (
	"bytes"
	"context"
	"testing"

	"cosmossdk.io/log/v2"
	tmproto "github.com/cometbft/cometbft/proto/tendermint/types"
	dbm "github.com/cosmos/cosmos-db"
	"github.com/cosmos/cosmos-sdk/codec"
	codectypes "github.com/cosmos/cosmos-sdk/codec/types"
	"github.com/cosmos/cosmos-sdk/crypto/keys/secp256k1"
	"github.com/cosmos/cosmos-sdk/store/v2"
	storetypes "github.com/cosmos/cosmos-sdk/store/v2/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
	authtypes "github.com/cosmos/cosmos-sdk/x/auth/types"
	"github.com/stretchr/testify/require"

	cmtmldsa65 "github.com/cometbft/cometbft/crypto/mldsa65"
	sdkmldsa65 "github.com/cosmos/cosmos-sdk/crypto/keys/mldsa65"

	pqccrypto "github.com/DoraFactory/doravota/x/pqcauth/crypto"
	"github.com/DoraFactory/doravota/x/pqcauth/internal/execution"
	"github.com/DoraFactory/doravota/x/pqcauth/types"
)

type classicAccountKeeperStub struct{}

func (classicAccountKeeperStub) GetAccount(
	_ context.Context,
	address sdk.AccAddress,
) sdk.AccountI {
	return authtypes.NewBaseAccount(address, secp256k1.GenPrivKey().PubKey(), 0, 0)
}

type fixedAccountKeeperStub struct {
	account sdk.AccountI
}

func (stub fixedAccountKeeperStub) GetAccount(
	_ context.Context,
	address sdk.AccAddress,
) sdk.AccountI {
	if stub.account != nil && stub.account.GetAddress().Equals(address) {
		return stub.account
	}
	return nil
}

func setupKeeper(t testing.TB, height int64) (Keeper, sdk.Context) {
	t.Helper()
	registry := codectypes.NewInterfaceRegistry()
	types.RegisterInterfaces(registry)
	cdc := codec.NewProtoCodec(registry)
	storeKey := storetypes.NewKVStoreKey(types.StoreKey)
	database := dbm.NewMemDB()
	multiStore := store.NewCommitMultiStore(database, log.NewNopLogger())
	multiStore.MountStoreWithDB(storeKey, storetypes.StoreTypeIAVL, nil)
	require.NoError(t, multiStore.LoadLatestVersion())
	ctx := sdk.NewContext(
		multiStore,
		tmproto.Header{Height: height, ChainID: "pqcauth-test-1"},
		false,
		log.NewNopLogger(),
	)
	authority := sdk.AccAddress(bytes.Repeat([]byte{0x42}, 20)).String()
	return NewKeeper(cdc, storeKey, authority, classicAccountKeeperStub{}), ctx
}

func keyPair(seedByte byte) ([]byte, []byte) {
	seed := make([]byte, cmtmldsa65.SeedSize)
	for i := range seed {
		seed[i] = seedByte + byte(i)
	}
	privateKey, err := sdkmldsa65.GenPrivKeyFromSeed(seed)
	if err != nil {
		panic(err)
	}
	return privateKey.PubKey().Bytes(), privateKey.Bytes()
}

func keyProof(
	t testing.TB,
	ctx sdk.Context,
	params types.Params,
	owner string,
	keyID uint64,
	algorithm types.Algorithm,
	publicKey, privateKey []byte,
	role types.KeyRole,
	purpose string,
	policyVersion uint64,
	signatureContext []byte,
) []byte {
	t.Helper()
	doc := types.KeyProofDocV1{
		FormatVersion:        types.FormatVersionV1,
		NetworkId:            params.NetworkId,
		ChainId:              ctx.ChainID(),
		Owner:                owner,
		ProposedKeyId:        keyID,
		Algorithm:            algorithm,
		PublicKey:            publicKey,
		Role:                 role,
		Purpose:              purpose,
		CurrentPolicyVersion: policyVersion,
	}
	signBytes, err := types.MarshalKeyProofDocV1(doc)
	require.NoError(t, err)
	proof, err := pqccrypto.SignMLDSA65(privateKey, signBytes, signatureContext, false)
	require.NoError(t, err)
	return proof
}

func authorizedLifecycleContext(
	t testing.TB,
	ctx sdk.Context,
	msg sdk.Msg,
) sdk.Context {
	t.Helper()
	authorized, err := execution.AuthorizeLifecycleMessage(ctx, msg)
	require.NoError(t, err)
	return authorized
}

func TestKeeperStorageValidationAndIteration(t *testing.T) {
	moduleKeeper, ctx := setupKeeper(t, 10)
	owner := sdk.AccAddress(bytes.Repeat([]byte{0x09}, 20))
	other := sdk.AccAddress(bytes.Repeat([]byte{0x0a}, 20))

	require.NotNil(t, moduleKeeper.Logger(ctx))
	require.Same(t, moduleKeeper.cdc, moduleKeeper.Codec())
	require.Equal(t, moduleKeeper.authority, moduleKeeper.Authority())
	require.Equal(t, types.DefaultParams(), moduleKeeper.GetParams(ctx))

	invalidParams := types.DefaultParams()
	invalidParams.NetworkId = nil
	require.Error(t, moduleKeeper.SetParams(ctx, invalidParams))
	effective, err := moduleKeeper.NormalizeParams(ctx)
	require.NoError(t, err)
	require.Equal(t, types.DefaultParams(), effective)

	_, found := moduleKeeper.GetEffectiveAccountPolicy(ctx, owner)
	require.False(t, found)
	require.ErrorIs(t, moduleKeeper.SetAccountPolicy(ctx, owner, types.AccountPolicy{
		Owner: other.String(),
	}), types.ErrInvalidKey)
	require.ErrorIs(t, moduleKeeper.SetKey(ctx, owner, types.PQCKeyRecord{
		Owner: other.String(),
		KeyId: 1,
	}), types.ErrInvalidKey)
	require.ErrorIs(t, moduleKeeper.SetKey(ctx, owner, types.PQCKeyRecord{
		Owner: owner.String(),
	}), types.ErrInvalidKey)
	require.ErrorIs(t, moduleKeeper.SetKeySequence(ctx, owner, types.AccountKeySequence{
		Owner:     owner.String(),
		NextKeyId: 0,
	}), types.ErrInvalidKey)

	require.NoError(t, moduleKeeper.SetAccountPolicy(ctx, owner, types.AccountPolicy{
		Owner:         owner.String(),
		PolicyVersion: 1,
	}))
	require.NoError(t, moduleKeeper.SetKey(ctx, owner, types.PQCKeyRecord{
		Owner:  owner.String(),
		KeyId:  1,
		Status: types.KeyStatus_KEY_STATUS_LIVE,
	}))
	require.NoError(t, moduleKeeper.SetKeySequence(ctx, owner, types.AccountKeySequence{
		Owner:     owner.String(),
		NextKeyId: 2,
	}))

	keyCalls := 0
	moduleKeeper.IterateAllKeys(ctx, func(types.PQCKeyRecord) bool {
		keyCalls++
		return true
	})
	require.Equal(t, 1, keyCalls)
	policyCalls := 0
	moduleKeeper.IterateAllPolicies(ctx, func(types.AccountPolicy) bool {
		policyCalls++
		return true
	})
	require.Equal(t, 1, policyCalls)
	sequenceCalls := 0
	moduleKeeper.IterateAllSequences(ctx, func(types.AccountKeySequence) bool {
		sequenceCalls++
		return true
	})
	require.Equal(t, 1, sequenceCalls)

	_, _, err = moduleKeeper.ReserveKeyIDs(ctx, owner, 0, 1)
	require.ErrorIs(t, err, types.ErrUnexpectedKeyID)
	_, _, err = moduleKeeper.ReserveKeyIDs(ctx, owner, 2, 0)
	require.ErrorIs(t, err, types.ErrKeyLimit)
}

func TestKeeperCorruptStatePanicsFailClosed(t *testing.T) {
	testCases := []struct {
		name string
		key  func(sdk.AccAddress) []byte
		read func(Keeper, sdk.Context, sdk.AccAddress)
	}{
		{
			name: "params",
			key:  func(sdk.AccAddress) []byte { return types.ParamsKey },
			read: func(moduleKeeper Keeper, ctx sdk.Context, _ sdk.AccAddress) {
				moduleKeeper.GetParams(ctx)
			},
		},
		{
			name: "policy",
			key:  types.AccountPolicyKey,
			read: func(moduleKeeper Keeper, ctx sdk.Context, owner sdk.AccAddress) {
				moduleKeeper.GetAccountPolicy(ctx, owner)
			},
		},
		{
			name: "key",
			key: func(owner sdk.AccAddress) []byte {
				return types.PQCKeyRecordKey(owner, 1)
			},
			read: func(moduleKeeper Keeper, ctx sdk.Context, owner sdk.AccAddress) {
				moduleKeeper.GetKey(ctx, owner, 1)
			},
		},
		{
			name: "sequence",
			key:  types.AccountSequenceKey,
			read: func(moduleKeeper Keeper, ctx sdk.Context, owner sdk.AccAddress) {
				moduleKeeper.GetKeySequence(ctx, owner)
			},
		},
		{
			name: "key history",
			key: func(owner sdk.AccAddress) []byte {
				return types.AccountKeyHistoryKey(owner, types.KeyRole_KEY_ROLE_SIGNING)
			},
			read: func(moduleKeeper Keeper, ctx sdk.Context, owner sdk.AccAddress) {
				moduleKeeper.GetKeyHistory(ctx, owner, types.KeyRole_KEY_ROLE_SIGNING)
			},
		},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			moduleKeeper, ctx := setupKeeper(t, 10)
			owner := sdk.AccAddress(bytes.Repeat([]byte{0x0b}, 20))
			ctx.KVStore(moduleKeeper.storeKey).Set(testCase.key(owner), []byte{0xff})
			require.Panics(t, func() {
				testCase.read(moduleKeeper, ctx, owner)
			})
		})
	}
}

func TestEmergencyModesFailClosed(t *testing.T) {
	_, ctx := setupKeeper(t, 10)
	params := types.DefaultParams()

	params.EmergencyMode = types.EmergencyMode_EMERGENCY_MODE_PAUSE_NEW_KEYS
	require.ErrorIs(t, ensureKeyChangeAllowed(ctx, params, false), types.ErrEmergencyPause)
	require.NoError(t, ensurePQCTransactionAllowed(params))
	require.NoError(t, ensureRecoveryAllowed(params))

	params.EmergencyMode = types.EmergencyMode_EMERGENCY_MODE_PAUSE_PQC_TRANSACTIONS
	require.ErrorIs(t, ensureKeyChangeAllowed(ctx, params, false), types.ErrEmergencyPause)
	require.ErrorIs(t, ensurePQCTransactionAllowed(params), types.ErrEmergencyPause)
	require.NoError(t, ensureRecoveryAllowed(params))
}

func TestRegisterAndRotateActivateAtHPlusOne(t *testing.T) {
	moduleKeeper, ctx := setupKeeper(t, 10)
	require.NoError(t, moduleKeeper.SetParams(ctx, types.DefaultParams()))
	server := NewMsgServer(moduleKeeper)
	params := moduleKeeper.GetParams(ctx)
	owner := sdk.AccAddress(bytes.Repeat([]byte{0x11}, 20)).String()

	publicKey1, privateKey1 := keyPair(1)
	recoveryPublicKey, recoveryPrivateKey := keyPair(2)
	registerProof := keyProof(
		t,
		ctx,
		params,
		owner,
		1,
		types.Algorithm_ALGORITHM_ML_DSA_65,
		publicKey1,
		privateKey1,
		types.KeyRole_KEY_ROLE_SIGNING,
		types.PurposeRegisterSigning,
		0,
		[]byte(types.RegisterProofContext),
	)
	registerMessage := &types.MsgRegisterKey{
		Owner:                owner,
		ExpectedSigningKeyId: 1,
		SigningAlgorithm:     types.Algorithm_ALGORITHM_ML_DSA_65,
		SigningPublicKey:     publicKey1,
		SigningKeyProof:      registerProof,
		RecoveryAlgorithm:    types.Algorithm_ALGORITHM_ML_DSA_65,
		RecoveryPublicKey:    recoveryPublicKey,
		RecoveryKeyProof: keyProof(
			t,
			ctx,
			params,
			owner,
			2,
			types.Algorithm_ALGORITHM_ML_DSA_65,
			recoveryPublicKey,
			recoveryPrivateKey,
			types.KeyRole_KEY_ROLE_RECOVERY,
			types.PurposeRegisterRecovery,
			0,
			[]byte(types.RegisterProofContext),
		),
		SelfEnforce: true,
	}
	registerResponse, err := server.RegisterKey(
		sdk.WrapSDKContext(authorizedLifecycleContext(t, ctx, registerMessage)),
		registerMessage,
	)
	require.NoError(t, err)
	require.Equal(t, uint64(1), registerResponse.SigningKeyId)
	require.Equal(t, uint64(2), registerResponse.RecoveryKeyId)
	require.Equal(t, uint64(11), registerResponse.EffectiveHeight)

	ownerAddress, err := sdk.AccAddressFromBech32(owner)
	require.NoError(t, err)
	_, _, active := moduleKeeper.GetActiveSigningKey(ctx, ownerAddress)
	require.False(t, active)
	pendingPolicy, found := moduleKeeper.GetEffectiveAccountPolicy(ctx, ownerAddress)
	require.True(t, found)
	require.Zero(t, pendingPolicy.CurrentSigningKeyId)
	require.Zero(t, pendingPolicy.RecoveryKeyId)
	require.Equal(t, uint64(1), pendingPolicy.PendingSigningKeyId)
	require.Equal(t, uint64(2), pendingPolicy.PendingRecoveryKeyId)
	require.True(t, pendingPolicy.PendingSelfEnforced)

	ctx = ctx.WithBlockHeight(11)
	activeKey, policy, active := moduleKeeper.GetActiveSigningKey(ctx, ownerAddress)
	require.True(t, active)
	require.Equal(t, uint64(1), activeKey.KeyId)
	require.Equal(t, uint64(2), policy.RecoveryKeyId)
	require.True(t, policy.SelfEnforced)
	require.Equal(t, uint64(1), policy.PolicyVersion)

	publicKey2, privateKey2 := keyPair(3)
	rotateProof := keyProof(
		t,
		ctx,
		params,
		owner,
		3,
		types.Algorithm_ALGORITHM_ML_DSA_65,
		publicKey2,
		privateKey2,
		types.KeyRole_KEY_ROLE_SIGNING,
		types.PurposeRotateSigning,
		1,
		[]byte(types.RotateProofContext),
	)
	rotateMessage := &types.MsgRotateKey{
		Owner:            owner,
		ExpectedNewKeyId: 3,
		NewAlgorithm:     types.Algorithm_ALGORITHM_ML_DSA_65,
		NewPublicKey:     publicKey2,
		NewKeyProof:      rotateProof,
	}
	rotateResponse, err := server.RotateKey(
		sdk.WrapSDKContext(authorizedLifecycleContext(t, ctx, rotateMessage)),
		rotateMessage,
	)
	require.NoError(t, err)
	require.Equal(t, uint64(12), rotateResponse.EffectiveHeight)

	activeKey, _, active = moduleKeeper.GetActiveSigningKey(ctx, ownerAddress)
	require.True(t, active)
	require.Equal(t, uint64(1), activeKey.KeyId)

	ctx = ctx.WithBlockHeight(12)
	activeKey, policy, active = moduleKeeper.GetActiveSigningKey(ctx, ownerAddress)
	require.True(t, active)
	require.Equal(t, uint64(3), activeKey.KeyId)
	require.Equal(t, uint64(2), policy.PolicyVersion)
	oldKey, found := moduleKeeper.GetKey(ctx, ownerAddress, 1)
	require.True(t, found)
	require.False(t, oldKey.IsEffective(ctx.BlockHeight()))
}

func TestMsgServerRejectsNativeMLDSARegistration(t *testing.T) {
	moduleKeeper, ctx := setupKeeper(t, 10)
	require.NoError(t, moduleKeeper.SetParams(ctx, types.DefaultParams()))

	nativePrivateKey, err := sdkmldsa65.GenPrivKey()
	require.NoError(t, err)
	ownerAddress := sdk.AccAddress(nativePrivateKey.PubKey().Address())
	moduleKeeper.accountKeeper = fixedAccountKeeperStub{account: authtypes.NewBaseAccount(
		ownerAddress,
		nativePrivateKey.PubKey(),
		1,
		0,
	)}

	signingPublicKey, signingPrivateKey := keyPair(31)
	recoveryPublicKey, recoveryPrivateKey := keyPair(32)
	params := moduleKeeper.GetParams(ctx)
	message := &types.MsgRegisterKey{
		Owner:                ownerAddress.String(),
		ExpectedSigningKeyId: 1,
		SigningAlgorithm:     types.Algorithm_ALGORITHM_ML_DSA_65,
		SigningPublicKey:     signingPublicKey,
		SigningKeyProof: keyProof(
			t,
			ctx,
			params,
			ownerAddress.String(),
			1,
			types.Algorithm_ALGORITHM_ML_DSA_65,
			signingPublicKey,
			signingPrivateKey,
			types.KeyRole_KEY_ROLE_SIGNING,
			types.PurposeRegisterSigning,
			0,
			[]byte(types.RegisterProofContext),
		),
		RecoveryAlgorithm: types.Algorithm_ALGORITHM_ML_DSA_65,
		RecoveryPublicKey: recoveryPublicKey,
		RecoveryKeyProof: keyProof(
			t,
			ctx,
			params,
			ownerAddress.String(),
			2,
			types.Algorithm_ALGORITHM_ML_DSA_65,
			recoveryPublicKey,
			recoveryPrivateKey,
			types.KeyRole_KEY_ROLE_RECOVERY,
			types.PurposeRegisterRecovery,
			0,
			[]byte(types.RegisterProofContext),
		),
		SelfEnforce: true,
	}

	_, err = NewMsgServer(moduleKeeper).RegisterKey(
		authorizedLifecycleContext(t, ctx, message),
		message,
	)
	require.ErrorIs(t, err, types.ErrIneligibleAccount)
	_, found := moduleKeeper.GetAccountPolicy(ctx, ownerAddress)
	require.False(t, found)
}

func TestStateInvariantRejectsNativeMLDSAOwner(t *testing.T) {
	moduleKeeper, ctx := setupKeeper(t, 10)
	require.NoError(t, moduleKeeper.SetParams(ctx, types.DefaultParams()))
	nativePrivateKey, err := sdkmldsa65.GenPrivKey()
	require.NoError(t, err)
	owner := sdk.AccAddress(nativePrivateKey.PubKey().Address())
	moduleKeeper.accountKeeper = fixedAccountKeeperStub{account: authtypes.NewBaseAccount(
		owner,
		nativePrivateKey.PubKey(),
		1,
		0,
	)}

	signingPublicKey, _ := keyPair(41)
	recoveryPublicKey, _ := keyPair(42)
	require.NoError(t, moduleKeeper.SetKey(ctx, owner, types.PQCKeyRecord{
		Owner:           owner.String(),
		KeyId:           1,
		Algorithm:       types.Algorithm_ALGORITHM_ML_DSA_65,
		PublicKey:       signingPublicKey,
		Role:            types.KeyRole_KEY_ROLE_SIGNING,
		Status:          types.KeyStatus_KEY_STATUS_LIVE,
		EffectiveHeight: 1,
	}))
	require.NoError(t, moduleKeeper.SetKey(ctx, owner, types.PQCKeyRecord{
		Owner:           owner.String(),
		KeyId:           2,
		Algorithm:       types.Algorithm_ALGORITHM_ML_DSA_65,
		PublicKey:       recoveryPublicKey,
		Role:            types.KeyRole_KEY_ROLE_RECOVERY,
		Status:          types.KeyStatus_KEY_STATUS_LIVE,
		EffectiveHeight: 1,
	}))
	require.NoError(t, moduleKeeper.SetAccountPolicy(ctx, owner, types.AccountPolicy{
		Owner:               owner.String(),
		CurrentSigningKeyId: 1,
		RecoveryKeyId:       2,
		SelfEnforced:        true,
		PolicyVersion:       1,
	}))
	require.NoError(t, moduleKeeper.SetKeySequence(ctx, owner, types.AccountKeySequence{
		Owner:     owner.String(),
		NextKeyId: 3,
	}))

	message, broken := StateInvariant(moduleKeeper)(ctx)
	require.True(t, broken)
	require.Contains(t, message, "ineligible pqcauth state owner")
}

func TestRegisterRejectsProofBoundToWrongChain(t *testing.T) {
	moduleKeeper, ctx := setupKeeper(t, 10)
	require.NoError(t, moduleKeeper.SetParams(ctx, types.DefaultParams()))
	params := moduleKeeper.GetParams(ctx)
	owner := sdk.AccAddress(bytes.Repeat([]byte{0x22}, 20)).String()
	publicKey, privateKey := keyPair(3)
	wrongChainCtx := ctx.WithChainID("other-chain")
	proof := keyProof(
		t,
		wrongChainCtx,
		params,
		owner,
		1,
		types.Algorithm_ALGORITHM_ML_DSA_65,
		publicKey,
		privateKey,
		types.KeyRole_KEY_ROLE_SIGNING,
		types.PurposeRegisterSigning,
		0,
		[]byte(types.RegisterProofContext),
	)

	err := VerifyKeyProof(
		ctx,
		params,
		owner,
		1,
		types.Algorithm_ALGORITHM_ML_DSA_65,
		publicKey,
		types.KeyRole_KEY_ROLE_SIGNING,
		types.PurposeRegisterSigning,
		0,
		proof,
		[]byte(types.RegisterProofContext),
	)
	require.ErrorIs(t, err, types.ErrInvalidKeyProof)
}

func TestRotateRecoveryKeyActivatesAtHPlusOne(t *testing.T) {
	moduleKeeper, ctx := setupKeeper(t, 10)
	require.NoError(t, moduleKeeper.SetParams(ctx, types.DefaultParams()))
	server := NewMsgServer(moduleKeeper)
	params := moduleKeeper.GetParams(ctx)
	owner := sdk.AccAddress(bytes.Repeat([]byte{0x35}, 20)).String()
	ownerAddress := sdk.MustAccAddressFromBech32(owner)

	signingPublicKey, signingPrivateKey := keyPair(7)
	recoveryPublicKey, recoveryPrivateKey := keyPair(8)
	registerMessage := &types.MsgRegisterKey{
		Owner:                owner,
		ExpectedSigningKeyId: 1,
		SigningAlgorithm:     types.Algorithm_ALGORITHM_ML_DSA_65,
		SigningPublicKey:     signingPublicKey,
		SigningKeyProof: keyProof(
			t,
			ctx,
			params,
			owner,
			1,
			types.Algorithm_ALGORITHM_ML_DSA_65,
			signingPublicKey,
			signingPrivateKey,
			types.KeyRole_KEY_ROLE_SIGNING,
			types.PurposeRegisterSigning,
			0,
			[]byte(types.RegisterProofContext),
		),
		RecoveryAlgorithm: types.Algorithm_ALGORITHM_ML_DSA_65,
		RecoveryPublicKey: recoveryPublicKey,
		RecoveryKeyProof: keyProof(
			t,
			ctx,
			params,
			owner,
			2,
			types.Algorithm_ALGORITHM_ML_DSA_65,
			recoveryPublicKey,
			recoveryPrivateKey,
			types.KeyRole_KEY_ROLE_RECOVERY,
			types.PurposeRegisterRecovery,
			0,
			[]byte(types.RegisterProofContext),
		),
		SelfEnforce: true,
	}
	_, err := server.RegisterKey(
		sdk.WrapSDKContext(authorizedLifecycleContext(t, ctx, registerMessage)),
		registerMessage,
	)
	require.NoError(t, err)

	ctx = ctx.WithBlockHeight(11)
	newRecoveryPublicKey, newRecoveryPrivateKey := keyPair(9)
	rotateProof := keyProof(
		t,
		ctx,
		params,
		owner,
		3,
		types.Algorithm_ALGORITHM_ML_DSA_65,
		newRecoveryPublicKey,
		newRecoveryPrivateKey,
		types.KeyRole_KEY_ROLE_RECOVERY,
		types.PurposeRotateRecovery,
		1,
		[]byte(types.RotateRecoveryContext),
	)
	rotateRecoveryMessage := &types.MsgRotateRecoveryKey{
		Owner:            owner,
		ExpectedNewKeyId: 3,
		NewAlgorithm:     types.Algorithm_ALGORITHM_ML_DSA_65,
		NewPublicKey:     newRecoveryPublicKey,
		NewKeyProof:      rotateProof,
	}
	response, err := server.RotateRecoveryKey(
		sdk.WrapSDKContext(authorizedLifecycleContext(t, ctx, rotateRecoveryMessage)),
		rotateRecoveryMessage,
	)
	require.NoError(t, err)
	require.Equal(t, uint64(12), response.EffectiveHeight)
	require.Equal(t, uint64(2), response.PolicyVersion)

	before, found := moduleKeeper.GetEffectiveAccountPolicy(ctx, ownerAddress)
	require.True(t, found)
	require.Equal(t, uint64(2), before.RecoveryKeyId)
	require.Equal(t, uint64(3), before.PendingRecoveryKeyId)
	oldRecoveryKey, found := moduleKeeper.GetKey(ctx, ownerAddress, 2)
	require.True(t, found)
	require.True(t, oldRecoveryKey.IsEffective(ctx.BlockHeight()))
	newRecoveryKey, found := moduleKeeper.GetKey(ctx, ownerAddress, 3)
	require.True(t, found)
	require.False(t, newRecoveryKey.IsEffective(ctx.BlockHeight()))
	_, broken := StateInvariant(moduleKeeper)(ctx)
	require.False(t, broken)

	revokeMessage := &types.MsgRevokeKey{Owner: owner, KeyId: 2}
	_, err = server.RevokeKey(
		sdk.WrapSDKContext(authorizedLifecycleContext(t, ctx, revokeMessage)),
		revokeMessage,
	)
	require.ErrorIs(t, err, types.ErrActiveKey)

	ctx = ctx.WithBlockHeight(12)
	after, found := moduleKeeper.GetEffectiveAccountPolicy(ctx, ownerAddress)
	require.True(t, found)
	require.Equal(t, uint64(3), after.RecoveryKeyId)
	require.Zero(t, after.PendingRecoveryKeyId)
	require.Equal(t, uint64(2), after.PolicyVersion)
	require.Equal(t, uint64(1), after.CurrentSigningKeyId)
	oldRecoveryKey, _ = moduleKeeper.GetKey(ctx, ownerAddress, 2)
	newRecoveryKey, _ = moduleKeeper.GetKey(ctx, ownerAddress, 3)
	require.False(t, oldRecoveryKey.IsEffective(ctx.BlockHeight()))
	require.True(t, newRecoveryKey.IsEffective(ctx.BlockHeight()))

	_, err = server.RevokeKey(
		sdk.WrapSDKContext(authorizedLifecycleContext(t, ctx, revokeMessage)),
		revokeMessage,
	)
	require.NoError(t, err)
	oldRecoveryKey, _ = moduleKeeper.GetKey(ctx, ownerAddress, 2)
	require.Equal(t, types.KeyStatus_KEY_STATUS_REVOKED, oldRecoveryKey.Status)
}

func TestRecoveryStateTransitionActivatesAtHPlusOneAfterAnteAuthorization(t *testing.T) {
	moduleKeeper, ctx := setupKeeper(t, 20)
	require.NoError(t, moduleKeeper.SetParams(ctx, types.DefaultParams()))
	server := NewMsgServer(moduleKeeper)
	params := moduleKeeper.GetParams(ctx)
	owner := sdk.AccAddress(bytes.Repeat([]byte{0x44}, 20)).String()

	signingPublicKey, signingPrivateKey := keyPair(4)
	recoveryPublicKey, recoveryPrivateKey := keyPair(5)
	registerMessage := &types.MsgRegisterKey{
		Owner:                owner,
		ExpectedSigningKeyId: 1,
		SigningAlgorithm:     types.Algorithm_ALGORITHM_ML_DSA_65,
		SigningPublicKey:     signingPublicKey,
		SigningKeyProof: keyProof(
			t,
			ctx,
			params,
			owner,
			1,
			types.Algorithm_ALGORITHM_ML_DSA_65,
			signingPublicKey,
			signingPrivateKey,
			types.KeyRole_KEY_ROLE_SIGNING,
			types.PurposeRegisterSigning,
			0,
			[]byte(types.RegisterProofContext),
		),
		RecoveryAlgorithm: types.Algorithm_ALGORITHM_ML_DSA_65,
		RecoveryPublicKey: recoveryPublicKey,
		RecoveryKeyProof: keyProof(
			t,
			ctx,
			params,
			owner,
			2,
			types.Algorithm_ALGORITHM_ML_DSA_65,
			recoveryPublicKey,
			recoveryPrivateKey,
			types.KeyRole_KEY_ROLE_RECOVERY,
			types.PurposeRegisterRecovery,
			0,
			[]byte(types.RegisterProofContext),
		),
		SelfEnforce: true,
	}
	_, err := server.RegisterKey(
		sdk.WrapSDKContext(authorizedLifecycleContext(t, ctx, registerMessage)),
		registerMessage,
	)
	require.NoError(t, err)

	ctx = ctx.WithBlockHeight(21)
	newPublicKey, newPrivateKey := keyPair(6)
	newKeyProof := keyProof(
		t,
		ctx,
		params,
		owner,
		3,
		types.Algorithm_ALGORITHM_ML_DSA_65,
		newPublicKey,
		newPrivateKey,
		types.KeyRole_KEY_ROLE_SIGNING,
		types.PurposeRecoverSigning,
		1,
		[]byte(types.RecoveryKeyProofContext),
	)
	_, recoverySignatureSize, err := pqccrypto.Sizes(pqccrypto.AlgorithmMLDSA65)
	require.NoError(t, err)

	recoveryMessage := &types.MsgRecoverKey{
		Owner:                   owner,
		RecoveryKeyId:           2,
		RecoverySignature:       make([]byte, recoverySignatureSize),
		ExpectedNewSigningKeyId: 3,
		NewSigningAlgorithm:     types.Algorithm_ALGORITHM_ML_DSA_65,
		NewSigningPublicKey:     newPublicKey,
		NewSigningKeyProof:      newKeyProof,
	}
	ownerAddress := sdk.MustAccAddressFromBech32(owner)
	unavailableKey, found := moduleKeeper.GetKey(ctx, ownerAddress, 1)
	require.True(t, found)
	unavailableKey.Status = types.KeyStatus_KEY_STATUS_REVOKED
	require.NoError(t, moduleKeeper.SetKey(ctx, ownerAddress, unavailableKey))
	paused := params
	paused.EmergencyMode = types.EmergencyMode_EMERGENCY_MODE_PAUSE_PQC_TRANSACTIONS
	paused.EmergencyExpiresHeight = 100
	require.NoError(t, moduleKeeper.SetParams(ctx, paused))
	response, err := server.RecoverKey(
		sdk.WrapSDKContext(authorizedLifecycleContext(t, ctx, recoveryMessage)),
		recoveryMessage,
	)
	require.NoError(t, err)
	require.Equal(t, uint64(22), response.EffectiveHeight)

	_, policyBeforeActivation, active := moduleKeeper.GetActiveSigningKey(ctx, ownerAddress)
	require.False(t, active)
	require.Equal(t, uint64(1), policyBeforeActivation.CurrentSigningKeyId)
	require.Equal(t, uint64(3), policyBeforeActivation.PendingSigningKeyId)
	activeKey, policy, active := moduleKeeper.GetActiveSigningKey(ctx.WithBlockHeight(22), ownerAddress)
	require.True(t, active)
	require.Equal(t, uint64(3), activeKey.KeyId)
	require.Equal(t, uint64(2), policy.PolicyVersion)
}

func TestLifecycleMessagesRequireExactAnteAuthorization(t *testing.T) {
	moduleKeeper, ctx := setupKeeper(t, 10)
	require.NoError(t, moduleKeeper.SetParams(ctx, types.DefaultParams()))
	server := NewMsgServer(moduleKeeper)
	owner := sdk.AccAddress(bytes.Repeat([]byte{0x55}, 20)).String()
	message := &types.MsgSetProtection{Owner: owner, Enabled: true}

	_, err := server.SetProtection(sdk.WrapSDKContext(ctx), message)
	require.ErrorIs(t, err, types.ErrNestedLifecycle)

	differentMessage := &types.MsgSetProtection{Owner: owner, Enabled: false}
	wrongContext := authorizedLifecycleContext(t, ctx, differentMessage)
	_, err = server.SetProtection(sdk.WrapSDKContext(wrongContext), message)
	require.ErrorIs(t, err, types.ErrNestedLifecycle)

	exactContext := authorizedLifecycleContext(t, ctx, message)
	_, err = server.SetProtection(sdk.WrapSDKContext(exactContext), message)
	require.ErrorIs(t, err, types.ErrPolicyNotFound)
}

func TestUpdateParamsDelaysRestrictiveBundleAndBoundsEmergency(t *testing.T) {
	moduleKeeper, ctx := setupKeeper(t, 30)
	current := types.DefaultParams()
	current.GovernanceSafetyDelayBlocks = 5
	current.MaxEmergencyDurationBlocks = 7
	require.NoError(t, moduleKeeper.SetParams(ctx, current))
	requested := current
	requested.EnforcementMode = types.EnforcementMode_ENFORCEMENT_MODE_REQUIRED_FOR_REGISTERED
	requested.EmergencyMode = types.EmergencyMode_EMERGENCY_MODE_PAUSE_NEW_KEYS
	requested.MaxPqcSigners = 4
	requested.RegistrationCutoffHeight = 100

	response, err := NewMsgServer(moduleKeeper).UpdateParams(
		sdk.WrapSDKContext(ctx),
		&types.MsgUpdateParams{
			Authority: moduleKeeper.Authority(),
			Params:    requested,
		},
	)
	require.NoError(t, err)
	require.Equal(t, uint64(35), response.ActivationHeight)

	stored := moduleKeeper.GetParams(ctx)
	require.NotNil(t, stored.Pending)
	require.Equal(t, uint64(42), stored.Pending.EmergencyExpiresHeight)
	before := stored.Effective(34)
	require.Equal(t, types.EnforcementMode_ENFORCEMENT_MODE_OPTIONAL, before.EnforcementMode)
	require.Equal(t, types.EmergencyMode_EMERGENCY_MODE_NORMAL, before.EmergencyMode)
	require.Equal(t, types.DefaultMaxPQCSigners, before.MaxPqcSigners)

	after := stored.Effective(35)
	require.Equal(t, requested.EnforcementMode, after.EnforcementMode)
	require.Equal(t, requested.EmergencyMode, after.EmergencyMode)
	require.Equal(t, requested.MaxPqcSigners, after.MaxPqcSigners)
	require.Equal(t, requested.RegistrationCutoffHeight, after.RegistrationCutoffHeight)
	require.Nil(t, after.Pending)
	require.Equal(
		t,
		types.EmergencyMode_EMERGENCY_MODE_PAUSE_NEW_KEYS,
		stored.Effective(41).EmergencyMode,
	)
	require.Equal(
		t,
		types.EmergencyMode_EMERGENCY_MODE_NORMAL,
		stored.Effective(42).EmergencyMode,
	)

	requested.RegistrationCutoffHeight = 0
	_, err = NewMsgServer(moduleKeeper).UpdateParams(
		sdk.WrapSDKContext(ctx),
		&types.MsgUpdateParams{
			Authority: moduleKeeper.Authority(),
			Params:    requested,
		},
	)
	require.Error(t, err)
}

func TestEmergencyOnlyUpdateActivatesAtHPlusOneAndCanBeCancelled(t *testing.T) {
	moduleKeeper, ctx := setupKeeper(t, 30)
	current := types.DefaultParams()
	current.GovernanceSafetyDelayBlocks = 5
	current.MaxEmergencyDurationBlocks = 7
	require.NoError(t, moduleKeeper.SetParams(ctx, current))
	server := NewMsgServer(moduleKeeper)

	requested := current
	requested.EmergencyMode = types.EmergencyMode_EMERGENCY_MODE_PAUSE_PQC_TRANSACTIONS
	response, err := server.UpdateParams(sdk.WrapSDKContext(ctx), &types.MsgUpdateParams{
		Authority: moduleKeeper.Authority(),
		Params:    requested,
	})
	require.NoError(t, err)
	require.Equal(t, uint64(31), response.ActivationHeight)
	stored := moduleKeeper.GetParams(ctx)
	require.Equal(t, uint64(38), stored.Pending.EmergencyExpiresHeight)

	response, err = server.UpdateParams(sdk.WrapSDKContext(ctx), &types.MsgUpdateParams{
		Authority: moduleKeeper.Authority(),
		Params:    current,
	})
	require.NoError(t, err)
	require.Zero(t, response.ActivationHeight)
	require.Nil(t, moduleKeeper.GetParams(ctx).Pending)
}

func TestGovernanceSafetyDelayClassification(t *testing.T) {
	base := types.DefaultParams().AsScheduled()
	testCases := []struct {
		name        string
		current     types.ScheduledParams
		mutate      func(*types.ScheduledParams)
		restrictive bool
	}{
		{
			name: "enforcement escalation",
			mutate: func(requested *types.ScheduledParams) {
				requested.EnforcementMode = types.EnforcementMode_ENFORCEMENT_MODE_REQUIRED
			},
			restrictive: true,
		},
		{
			name: "registration cutoff",
			mutate: func(requested *types.ScheduledParams) {
				requested.RegistrationCutoffHeight = 100
			},
			restrictive: true,
		},
		{
			name: "signature gas increase",
			mutate: func(requested *types.ScheduledParams) {
				requested.SignatureVerificationGas++
			},
			restrictive: true,
		},
		{
			name: "proof gas increase",
			mutate: func(requested *types.ScheduledParams) {
				requested.ProofVerificationGas++
			},
			restrictive: true,
		},
		{
			name:        "signer limit reduction",
			mutate:      func(requested *types.ScheduledParams) { requested.MaxPqcSigners-- },
			restrictive: true,
		},
		{
			name:        "byte limit reduction",
			mutate:      func(requested *types.ScheduledParams) { requested.MaxPqcAuthBytes-- },
			restrictive: true,
		},
		{
			name:        "algorithm removal",
			mutate:      func(requested *types.ScheduledParams) { requested.AllowedAlgorithms = nil },
			restrictive: true,
		},
		{
			name: "emergency activation remains fast",
			mutate: func(requested *types.ScheduledParams) {
				requested.EmergencyMode = types.EmergencyMode_EMERGENCY_MODE_PAUSE_NEW_KEYS
			},
		},
		{
			name: "enforcement relaxation",
			current: func() types.ScheduledParams {
				value := base
				value.EnforcementMode = types.EnforcementMode_ENFORCEMENT_MODE_REQUIRED
				return value
			}(),
			mutate: func(requested *types.ScheduledParams) {
				requested.EnforcementMode = types.EnforcementMode_ENFORCEMENT_MODE_OPTIONAL
			},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			current := testCase.current
			if current.EnforcementMode == types.EnforcementMode_ENFORCEMENT_MODE_UNSPECIFIED {
				current = base
			}
			requested := current
			requested.AllowedAlgorithms = append(
				[]types.Algorithm(nil),
				current.AllowedAlgorithms...,
			)
			testCase.mutate(&requested)
			require.Equal(
				t,
				testCase.restrictive,
				requiresGovernanceSafetyDelay(current, requested),
			)
		})
	}
}

func TestActivatedParamsAreNormalizedForQueriesAndStore(t *testing.T) {
	moduleKeeper, ctx := setupKeeper(t, 30)
	params := types.DefaultParams()
	scheduled := params.AsScheduled()
	scheduled.EnforcementMode = types.EnforcementMode_ENFORCEMENT_MODE_REQUIRED
	scheduled.EmergencyMode = types.EmergencyMode_EMERGENCY_MODE_PAUSE_NEW_KEYS
	scheduled.EmergencyExpiresHeight = 40
	scheduled.MaxPqcSigners = 4
	params.Pending = &scheduled
	params.PendingActivationHeight = 31
	require.NoError(t, moduleKeeper.SetParams(ctx, params))

	activationCtx := ctx.WithBlockHeight(31)
	response, err := NewQueryServer(moduleKeeper).Params(
		sdk.WrapSDKContext(activationCtx),
		&types.QueryParamsRequest{},
	)
	require.NoError(t, err)
	require.Equal(t, scheduled.EnforcementMode, response.Params.EnforcementMode)
	require.Equal(t, scheduled.EmergencyMode, response.Params.EmergencyMode)
	require.Equal(t, scheduled.MaxPqcSigners, response.Params.MaxPqcSigners)
	require.Nil(t, response.Params.Pending)
	require.Zero(t, response.Params.PendingActivationHeight)

	raw := moduleKeeper.GetParams(activationCtx)
	require.NotNil(t, raw.Pending)
	normalized, err := moduleKeeper.NormalizeParams(activationCtx)
	require.NoError(t, err)
	require.Nil(t, normalized.Pending)
	require.Nil(t, moduleKeeper.GetParams(activationCtx).Pending)
}

func TestReserveKeyIDsRemainMonotonicWithoutLifetimeQuota(t *testing.T) {
	moduleKeeper, ctx := setupKeeper(t, 10)
	owner := sdk.AccAddress(bytes.Repeat([]byte{0x66}, 20))

	ids, sequence, err := moduleKeeper.ReserveKeyIDs(ctx, owner, 1, 2)
	require.NoError(t, err)
	require.Equal(t, []uint64{1, 2}, ids)
	require.NoError(t, moduleKeeper.SetKeySequence(ctx, owner, sequence))

	for expectedID := uint64(3); expectedID <= 100; expectedID++ {
		reserved, next, reserveErr := moduleKeeper.ReserveKeyIDs(ctx, owner, expectedID, 1)
		require.NoError(t, reserveErr)
		require.Equal(t, []uint64{expectedID}, reserved)
		require.NoError(t, moduleKeeper.SetKeySequence(ctx, owner, next))
	}

	_, _, err = moduleKeeper.ReserveKeyIDs(ctx, owner, 101, 3)
	require.ErrorIs(t, err, types.ErrKeyLimit)
}

func TestSetProtectionSchedulesOnlyRealChanges(t *testing.T) {
	moduleKeeper, ctx := setupKeeper(t, 10)
	require.NoError(t, moduleKeeper.SetParams(ctx, types.DefaultParams()))
	server := NewMsgServer(moduleKeeper)
	owner := sdk.AccAddress(bytes.Repeat([]byte{0x67}, 20))
	publicKey, _ := keyPair(20)
	require.NoError(t, moduleKeeper.SetKey(ctx, owner, types.PQCKeyRecord{
		Owner:           owner.String(),
		KeyId:           1,
		Algorithm:       types.Algorithm_ALGORITHM_ML_DSA_65,
		PublicKey:       publicKey,
		Role:            types.KeyRole_KEY_ROLE_SIGNING,
		Status:          types.KeyStatus_KEY_STATUS_LIVE,
		EffectiveHeight: 1,
	}))
	require.NoError(t, moduleKeeper.SetAccountPolicy(ctx, owner, types.AccountPolicy{
		Owner:               owner.String(),
		CurrentSigningKeyId: 1,
		PolicyVersion:       1,
	}))

	noChange := &types.MsgSetProtection{Owner: owner.String(), Enabled: false}
	response, err := server.SetProtection(
		sdk.WrapSDKContext(authorizedLifecycleContext(t, ctx, noChange)),
		noChange,
	)
	require.NoError(t, err)
	require.Equal(t, uint64(10), response.EffectiveHeight)
	require.Equal(t, uint64(1), response.PolicyVersion)

	enable := &types.MsgSetProtection{Owner: owner.String(), Enabled: true}
	response, err = server.SetProtection(
		sdk.WrapSDKContext(authorizedLifecycleContext(t, ctx, enable)),
		enable,
	)
	require.NoError(t, err)
	require.Equal(t, uint64(11), response.EffectiveHeight)
	require.Equal(t, uint64(2), response.PolicyVersion)

	policy, found := moduleKeeper.GetAccountPolicy(ctx, owner)
	require.True(t, found)
	require.True(t, policy.PendingSelfEnforced)
	require.Equal(t, uint64(11), policy.PendingEffectiveHeight)
	_, err = server.SetProtection(
		sdk.WrapSDKContext(authorizedLifecycleContext(t, ctx, enable)),
		enable,
	)
	require.ErrorIs(t, err, types.ErrPendingChange)

	activationCtx := ctx.WithBlockHeight(11)
	response, err = server.SetProtection(
		sdk.WrapSDKContext(authorizedLifecycleContext(t, activationCtx, enable)),
		enable,
	)
	require.NoError(t, err)
	require.Equal(t, uint64(11), response.EffectiveHeight)
	require.Equal(t, uint64(2), response.PolicyVersion)
}

func TestSetProtectionAndRevokeFailClosedStateMatrix(t *testing.T) {
	moduleKeeper, ctx := setupKeeper(t, 10)
	params := types.DefaultParams()
	require.NoError(t, moduleKeeper.SetParams(ctx, params))
	server := NewMsgServer(moduleKeeper)
	owner := sdk.AccAddress(bytes.Repeat([]byte{0x68}, 20))

	setProtection := &types.MsgSetProtection{Owner: owner.String(), Enabled: true}
	_, err := server.SetProtection(
		sdk.WrapSDKContext(authorizedLifecycleContext(t, ctx, setProtection)),
		setProtection,
	)
	require.ErrorIs(t, err, types.ErrPolicyNotFound)

	revoke := &types.MsgRevokeKey{Owner: owner.String(), KeyId: 2}
	_, err = server.RevokeKey(
		sdk.WrapSDKContext(authorizedLifecycleContext(t, ctx, revoke)),
		revoke,
	)
	require.ErrorIs(t, err, types.ErrPolicyNotFound)

	require.NoError(t, moduleKeeper.SetAccountPolicy(ctx, owner, types.AccountPolicy{
		Owner:               owner.String(),
		CurrentSigningKeyId: 1,
		PolicyVersion:       1,
	}))
	_, err = server.RevokeKey(
		sdk.WrapSDKContext(authorizedLifecycleContext(t, ctx, revoke)),
		revoke,
	)
	require.ErrorIs(t, err, types.ErrKeyNotFound)

	params.EmergencyMode = types.EmergencyMode_EMERGENCY_MODE_PAUSE_PQC_TRANSACTIONS
	params.EmergencyExpiresHeight = 100
	require.NoError(t, moduleKeeper.SetParams(ctx, params))
	_, err = server.SetProtection(
		sdk.WrapSDKContext(authorizedLifecycleContext(t, ctx, setProtection)),
		setProtection,
	)
	require.ErrorIs(t, err, types.ErrEmergencyPause)
	_, err = server.RevokeKey(
		sdk.WrapSDKContext(authorizedLifecycleContext(t, ctx, revoke)),
		revoke,
	)
	require.ErrorIs(t, err, types.ErrEmergencyPause)
}

func TestUpdateParamsRejectsAuthorityNetworkAndNestedSchedule(t *testing.T) {
	moduleKeeper, ctx := setupKeeper(t, 10)
	current := types.DefaultParams()
	require.NoError(t, moduleKeeper.SetParams(ctx, current))
	server := NewMsgServer(moduleKeeper)

	_, err := server.UpdateParams(sdk.WrapSDKContext(ctx), &types.MsgUpdateParams{
		Authority: sdk.AccAddress(bytes.Repeat([]byte{0x01}, 20)).String(),
		Params:    current,
	})
	require.ErrorIs(t, err, types.ErrInvalidAuthority)

	differentNetwork := current
	differentNetwork.NetworkId = bytes.Repeat([]byte{0x99}, len(current.NetworkId))
	_, err = server.UpdateParams(sdk.WrapSDKContext(ctx), &types.MsgUpdateParams{
		Authority: moduleKeeper.Authority(),
		Params:    differentNetwork,
	})
	require.ErrorIs(t, err, types.ErrInvalidParams)

	differentDelay := current
	differentDelay.GovernanceSafetyDelayBlocks++
	_, err = server.UpdateParams(sdk.WrapSDKContext(ctx), &types.MsgUpdateParams{
		Authority: moduleKeeper.Authority(),
		Params:    differentDelay,
	})
	require.ErrorIs(t, err, types.ErrInvalidParams)

	differentEmergencyLimit := current
	differentEmergencyLimit.MaxEmergencyDurationBlocks++
	_, err = server.UpdateParams(sdk.WrapSDKContext(ctx), &types.MsgUpdateParams{
		Authority: moduleKeeper.Authority(),
		Params:    differentEmergencyLimit,
	})
	require.ErrorIs(t, err, types.ErrInvalidParams)

	nested := current
	pending := current.AsScheduled()
	nested.Pending = &pending
	nested.PendingActivationHeight = 11
	_, err = server.UpdateParams(sdk.WrapSDKContext(ctx), &types.MsgUpdateParams{
		Authority: moduleKeeper.Authority(),
		Params:    nested,
	})
	require.ErrorIs(t, err, types.ErrInvalidParams)

	response, err := server.UpdateParams(sdk.WrapSDKContext(ctx), &types.MsgUpdateParams{
		Authority: moduleKeeper.Authority(),
		Params:    current,
	})
	require.NoError(t, err)
	require.Zero(t, response.ActivationHeight)
}

func TestUpdateParamsCanLowerHistoryRetentionIndependentlyOfKeySequence(t *testing.T) {
	moduleKeeper, ctx := setupKeeper(t, 10)
	current := types.DefaultParams()
	require.NoError(t, moduleKeeper.SetParams(ctx, current))
	owner := sdk.AccAddress(bytes.Repeat([]byte{0x42}, 20))
	require.NoError(t, moduleKeeper.SetKeySequence(ctx, owner, types.AccountKeySequence{
		Owner:     owner.String(),
		NextKeyId: 7,
	}))

	requested := current
	requested.MaxRetainedKeyRecordsPerRole = 5
	response, err := NewMsgServer(moduleKeeper).UpdateParams(
		sdk.WrapSDKContext(ctx),
		&types.MsgUpdateParams{Authority: moduleKeeper.Authority(), Params: requested},
	)
	require.NoError(t, err)
	require.Equal(t, uint64(11), response.ActivationHeight)
}
