package keeper

import (
	"bytes"
	"testing"

	dbm "github.com/cometbft/cometbft-db"
	"github.com/cometbft/cometbft/libs/log"
	tmproto "github.com/cometbft/cometbft/proto/tendermint/types"
	"github.com/cosmos/cosmos-sdk/codec"
	codectypes "github.com/cosmos/cosmos-sdk/codec/types"
	"github.com/cosmos/cosmos-sdk/store"
	storetypes "github.com/cosmos/cosmos-sdk/store/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/stretchr/testify/require"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"

	pqccrypto "github.com/DoraFactory/doravota/x/pqcauth/crypto"
	"github.com/DoraFactory/doravota/x/pqcauth/internal/execution"
	"github.com/DoraFactory/doravota/x/pqcauth/types"
)

func setupKeeper(t testing.TB, height int64) (Keeper, sdk.Context) {
	t.Helper()
	registry := codectypes.NewInterfaceRegistry()
	types.RegisterInterfaces(registry)
	cdc := codec.NewProtoCodec(registry)
	storeKey := sdk.NewKVStoreKey(types.StoreKey)
	database := dbm.NewMemDB()
	multiStore := store.NewCommitMultiStore(database)
	multiStore.MountStoreWithDB(storeKey, storetypes.StoreTypeIAVL, nil)
	require.NoError(t, multiStore.LoadLatestVersion())
	ctx := sdk.NewContext(
		multiStore,
		tmproto.Header{Height: height, ChainID: "pqcauth-test-1"},
		false,
		log.NewNopLogger(),
	)
	authority := sdk.AccAddress(bytes.Repeat([]byte{0x42}, 20)).String()
	return NewKeeper(cdc, storeKey, authority), ctx
}

func keyPair(seedByte byte) ([]byte, []byte) {
	var seed [mldsa65.SeedSize]byte
	for i := range seed {
		seed[i] = seedByte + byte(i)
	}
	publicKey, privateKey := mldsa65.NewKeyFromSeed(&seed)
	return publicKey.Bytes(), privateKey.Bytes()
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

	_, _, err = moduleKeeper.ReserveKeyIDs(ctx, owner, 0, 1, 8)
	require.ErrorIs(t, err, types.ErrUnexpectedKeyID)
	_, _, err = moduleKeeper.ReserveKeyIDs(ctx, owner, 2, 0, 8)
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

	params.EmergencyMode = types.EmergencyMode_EMERGENCY_MODE_PAUSE_PQC_TRANSACTIONS
	require.ErrorIs(t, ensureKeyChangeAllowed(ctx, params, false), types.ErrEmergencyPause)
	require.ErrorIs(t, ensurePQCTransactionAllowed(params), types.ErrEmergencyPause)
}

func TestRegisterAndRotateActivateAtHPlusOne(t *testing.T) {
	moduleKeeper, ctx := setupKeeper(t, 10)
	require.NoError(t, moduleKeeper.SetParams(ctx, types.DefaultParams()))
	server := NewMsgServer(moduleKeeper)
	params := moduleKeeper.GetParams(ctx)
	owner := sdk.AccAddress(bytes.Repeat([]byte{0x11}, 20)).String()

	publicKey1, privateKey1 := keyPair(1)
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
		SelfEnforce:          true,
	}
	registerResponse, err := server.RegisterKey(
		sdk.WrapSDKContext(authorizedLifecycleContext(t, ctx, registerMessage)),
		registerMessage,
	)
	require.NoError(t, err)
	require.Equal(t, uint64(11), registerResponse.EffectiveHeight)

	ownerAddress, err := sdk.AccAddressFromBech32(owner)
	require.NoError(t, err)
	_, _, active := moduleKeeper.GetActiveSigningKey(ctx, ownerAddress)
	require.False(t, active)

	ctx = ctx.WithBlockHeight(11)
	activeKey, policy, active := moduleKeeper.GetActiveSigningKey(ctx, ownerAddress)
	require.True(t, active)
	require.Equal(t, uint64(1), activeKey.KeyId)
	require.True(t, policy.SelfEnforced)
	require.Equal(t, uint64(1), policy.PolicyVersion)

	publicKey2, privateKey2 := keyPair(2)
	rotateProof := keyProof(
		t,
		ctx,
		params,
		owner,
		2,
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
		ExpectedNewKeyId: 2,
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
	require.Equal(t, uint64(2), activeKey.KeyId)
	require.Equal(t, uint64(2), policy.PolicyVersion)
	oldKey, found := moduleKeeper.GetKey(ctx, ownerAddress, 1)
	require.True(t, found)
	require.False(t, oldKey.IsEffective(ctx.BlockHeight()))
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
	response, err := server.RecoverKey(
		sdk.WrapSDKContext(authorizedLifecycleContext(t, ctx, recoveryMessage)),
		recoveryMessage,
	)
	require.NoError(t, err)
	require.Equal(t, uint64(22), response.EffectiveHeight)

	ownerAddress := sdk.MustAccAddressFromBech32(owner)
	activeKey, _, active := moduleKeeper.GetActiveSigningKey(ctx, ownerAddress)
	require.True(t, active)
	require.Equal(t, uint64(1), activeKey.KeyId)
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

func TestUpdateParamsSchedulesAtomicHPlusOneBundle(t *testing.T) {
	moduleKeeper, ctx := setupKeeper(t, 30)
	require.NoError(t, moduleKeeper.SetParams(ctx, types.DefaultParams()))
	requested := types.DefaultParams()
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
	require.Equal(t, uint64(31), response.ActivationHeight)

	stored := moduleKeeper.GetParams(ctx)
	require.NotNil(t, stored.Pending)
	before := stored.Effective(30)
	require.Equal(t, types.EnforcementMode_ENFORCEMENT_MODE_OPTIONAL, before.EnforcementMode)
	require.Equal(t, types.EmergencyMode_EMERGENCY_MODE_NORMAL, before.EmergencyMode)
	require.Equal(t, types.DefaultMaxPQCSigners, before.MaxPqcSigners)

	after := stored.Effective(31)
	require.Equal(t, requested.EnforcementMode, after.EnforcementMode)
	require.Equal(t, requested.EmergencyMode, after.EmergencyMode)
	require.Equal(t, requested.MaxPqcSigners, after.MaxPqcSigners)
	require.Equal(t, requested.RegistrationCutoffHeight, after.RegistrationCutoffHeight)
	require.Nil(t, after.Pending)

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

func TestActivatedParamsAreNormalizedForQueriesAndStore(t *testing.T) {
	moduleKeeper, ctx := setupKeeper(t, 30)
	params := types.DefaultParams()
	scheduled := params.AsScheduled()
	scheduled.EnforcementMode = types.EnforcementMode_ENFORCEMENT_MODE_REQUIRED
	scheduled.EmergencyMode = types.EmergencyMode_EMERGENCY_MODE_PAUSE_NEW_KEYS
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

func TestReserveKeyIDsUsesLifetimeQuota(t *testing.T) {
	moduleKeeper, ctx := setupKeeper(t, 10)
	owner := sdk.AccAddress(bytes.Repeat([]byte{0x66}, 20))

	ids, sequence, err := moduleKeeper.ReserveKeyIDs(ctx, owner, 1, 3, 3)
	require.NoError(t, err)
	require.Equal(t, []uint64{1, 2, 3}, ids)
	require.NoError(t, moduleKeeper.SetKeySequence(ctx, owner, sequence))

	for _, keyID := range ids {
		require.NoError(t, moduleKeeper.SetKey(ctx, owner, types.PQCKeyRecord{
			Owner:  owner.String(),
			KeyId:  keyID,
			Status: types.KeyStatus_KEY_STATUS_REVOKED,
		}))
	}

	_, _, err = moduleKeeper.ReserveKeyIDs(ctx, owner, 4, 1, 3)
	require.ErrorIs(t, err, types.ErrKeyLimit)
	require.Contains(t, err.Error(), "lifetime key-record quota 3 exhausted")
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
