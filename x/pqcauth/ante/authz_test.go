package ante

import (
	"context"
	"errors"
	"testing"

	"github.com/cosmos/cosmos-sdk/codec"
	sdkmldsa65 "github.com/cosmos/cosmos-sdk/crypto/keys/mldsa65"
	"github.com/cosmos/cosmos-sdk/crypto/keys/secp256k1"
	cryptotypes "github.com/cosmos/cosmos-sdk/crypto/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
	authtypes "github.com/cosmos/cosmos-sdk/x/auth/types"
	"github.com/cosmos/cosmos-sdk/x/authz"
	banktypes "github.com/cosmos/cosmos-sdk/x/bank/types"
	"github.com/stretchr/testify/require"

	pqccrypto "github.com/DoraFactory/doravota/x/pqcauth/crypto"
	pqckeeper "github.com/DoraFactory/doravota/x/pqcauth/keeper"
	"github.com/DoraFactory/doravota/x/pqcauth/types"
)

type authzGrantReaderMock struct {
	grants  map[string][]*authz.GrantAuthorization
	err     error
	request *authz.QueryGranterGrantsRequest
}

func (m *authzGrantReaderMock) GranterGrants(
	_ context.Context,
	request *authz.QueryGranterGrantsRequest,
) (*authz.QueryGranterGrantsResponse, error) {
	m.request = request
	if m.err != nil {
		return nil, m.err
	}
	return &authz.QueryGranterGrantsResponse{Grants: m.grants[request.Granter]}, nil
}

func authzDecorator(
	moduleKeeper pqckeeper.Keeper,
	accountKeeper accountKeeperMock,
	reader AuthzGrantReader,
	appCodec codec.Codec,
) AuthzPQCDecorator {
	return NewAuthzPQCDecorator(moduleKeeper, accountKeeper, reader, appCodec)
}

func runAuthzDecorator(
	ctx sdk.Context,
	decorator AuthzPQCDecorator,
	messages ...sdk.Msg,
) error {
	_, err := decorator.AnteHandle(
		ctx,
		extensionOptionsTxStub{messages: messages},
		false,
		func(nextCtx sdk.Context, _ sdk.Tx, _ bool) (sdk.Context, error) {
			return nextCtx, nil
		},
	)
	return err
}

func addClassicAccount(accountKeeper *accountKeeperMock) sdk.AccAddress {
	privateKey := secp256k1.GenPrivKey()
	address := sdk.AccAddress(privateKey.PubKey().Address())
	account := authtypesBaseAccount(address, privateKey.PubKey())
	accountKeeper.accounts[address.String()] = account
	return address
}

func addNativePQCAccount(t testing.TB, accountKeeper *accountKeeperMock) sdk.AccAddress {
	t.Helper()
	privateKey, err := sdkmldsa65.GenPrivKey()
	require.NoError(t, err)
	address := sdk.AccAddress(privateKey.PubKey().Address())
	account := authtypesBaseAccount(address, privateKey.PubKey())
	accountKeeper.accounts[address.String()] = account
	return address
}

func authtypesBaseAccount(address sdk.AccAddress, publicKey cryptotypes.PubKey) sdk.AccountI {
	account := authtypes.NewBaseAccountWithAddress(address)
	if err := account.SetPubKey(publicKey); err != nil {
		panic(err)
	}
	return account
}

func protectClassicAccount(
	t testing.TB,
	ctx sdk.Context,
	moduleKeeper pqckeeper.Keeper,
	address sdk.AccAddress,
) {
	t.Helper()
	publicKey, _, err := pqccrypto.GenerateMLDSA65Key(nil)
	require.NoError(t, err)
	require.NoError(t, moduleKeeper.SetKey(ctx, address, types.PQCKeyRecord{
		Owner:           address.String(),
		KeyId:           10,
		Algorithm:       types.Algorithm_ALGORITHM_ML_DSA_65,
		PublicKey:       publicKey,
		Role:            types.KeyRole_KEY_ROLE_SIGNING,
		Status:          types.KeyStatus_KEY_STATUS_LIVE,
		EffectiveHeight: 1,
	}))
	require.NoError(t, moduleKeeper.SetAccountPolicy(ctx, address, types.AccountPolicy{
		Owner:               address.String(),
		CurrentSigningKeyId: 10,
		SelfEnforced:        true,
		PolicyVersion:       1,
	}))
}

func TestAuthzProtectionRejectsActivationWithExistingGrant(t *testing.T) {
	ctx, moduleKeeper, accountKeeper, _, _ := setupAnteTest(t)
	owner := accountKeeper.account.GetAddress().String()
	reader := &authzGrantReaderMock{grants: map[string][]*authz.GrantAuthorization{
		owner: []*authz.GrantAuthorization{{}},
	}}
	decorator := authzDecorator(moduleKeeper, accountKeeper, reader, newAnteTestCodec(t))

	err := runAuthzDecorator(ctx, decorator, &types.MsgRegisterKey{Owner: owner})
	require.ErrorIs(t, err, types.ErrUnsafeAuthorization)
	require.NotNil(t, reader.request)
	require.Equal(t, uint64(1), reader.request.Pagination.Limit)

	policy, found := moduleKeeper.GetAccountPolicy(ctx, accountKeeper.account.GetAddress())
	require.True(t, found)
	policy.SelfEnforced = false
	require.NoError(t, moduleKeeper.SetAccountPolicy(ctx, accountKeeper.account.GetAddress(), policy))
	err = runAuthzDecorator(ctx, decorator, &types.MsgSetProtection{Owner: owner, Enabled: true})
	require.ErrorIs(t, err, types.ErrUnsafeAuthorization)
}

func TestAuthzProtectionFailsClosedWhenGrantQueryFails(t *testing.T) {
	ctx, moduleKeeper, accountKeeper, _, _ := setupAnteTest(t)
	reader := &authzGrantReaderMock{err: errors.New("store unavailable")}
	decorator := authzDecorator(moduleKeeper, accountKeeper, reader, newAnteTestCodec(t))

	err := runAuthzDecorator(ctx, decorator, &types.MsgRegisterKey{
		Owner: accountKeeper.account.GetAddress().String(),
	})
	require.ErrorIs(t, err, types.ErrUnsafeAuthorization)
}

func TestAuthzGrantFreezesPendingProtectionAndRequiresSafeGrantee(t *testing.T) {
	ctx, moduleKeeper, accountKeeper, _, _ := setupAnteTest(t)
	reader := &authzGrantReaderMock{}
	decorator := authzDecorator(moduleKeeper, accountKeeper, reader, newAnteTestCodec(t))
	granter := accountKeeper.account.GetAddress()
	unsafeGrantee := addClassicAccount(&accountKeeper)
	grant, err := authz.NewMsgGrant(
		granter,
		unsafeGrantee,
		authz.NewGenericAuthorization(sdk.MsgTypeURL(&banktypes.MsgSend{})),
		nil,
	)
	require.NoError(t, err)

	err = runAuthzDecorator(ctx, decorator, grant)
	require.ErrorIs(t, err, types.ErrUnsafeAuthorization)

	nativeGrantee := addNativePQCAccount(t, &accountKeeper)
	grant, err = authz.NewMsgGrant(
		granter,
		nativeGrantee,
		authz.NewGenericAuthorization(sdk.MsgTypeURL(&banktypes.MsgSend{})),
		nil,
	)
	require.NoError(t, err)
	require.NoError(t, runAuthzDecorator(ctx, decorator, grant))

	policy, found := moduleKeeper.GetAccountPolicy(ctx, granter)
	require.True(t, found)
	policy.SelfEnforced = false
	policy.PendingSelfEnforced = true
	policy.PendingEffectiveHeight = uint64(ctx.BlockHeight()) + 1
	policy.PendingPolicyVersion = policy.PolicyVersion + 1
	require.NoError(t, moduleKeeper.SetAccountPolicy(ctx, granter, policy))
	err = runAuthzDecorator(ctx, decorator, grant)
	require.ErrorIs(t, err, types.ErrUnsafeAuthorization)
	require.Contains(t, err.Error(), "frozen")
}

func TestAuthzExecRequiresPQCEnforcedExecutor(t *testing.T) {
	ctx, moduleKeeper, accountKeeper, _, _ := setupAnteTest(t)
	reader := &authzGrantReaderMock{}
	appCodec := newAnteTestCodec(t)
	granter := accountKeeper.account.GetAddress()
	unsafeExecutor := addClassicAccount(&accountKeeper)
	inner := banktypes.NewMsgSend(granter, unsafeExecutor, sdk.NewCoins(sdk.NewInt64Coin("stake", 1)))
	exec := authz.NewMsgExec(unsafeExecutor, []sdk.Msg{inner})

	err := runAuthzDecorator(
		ctx,
		authzDecorator(moduleKeeper, accountKeeper, reader, appCodec),
		&exec,
	)
	require.ErrorIs(t, err, types.ErrUnsafeAuthorization)

	protectClassicAccount(t, ctx, moduleKeeper, unsafeExecutor)
	require.NoError(t, runAuthzDecorator(
		ctx,
		authzDecorator(moduleKeeper, accountKeeper, reader, appCodec),
		&exec,
	))
}

func TestAuthzExecAllowsUnprotectedGranterAndNativeExecutor(t *testing.T) {
	ctx, moduleKeeper, accountKeeper, _, _ := setupAnteTest(t)
	reader := &authzGrantReaderMock{}
	appCodec := newAnteTestCodec(t)
	granter := addClassicAccount(&accountKeeper)
	unsafeExecutor := addClassicAccount(&accountKeeper)
	inner := banktypes.NewMsgSend(granter, unsafeExecutor, sdk.NewCoins(sdk.NewInt64Coin("stake", 1)))
	exec := authz.NewMsgExec(unsafeExecutor, []sdk.Msg{inner})
	require.NoError(t, runAuthzDecorator(
		ctx,
		authzDecorator(moduleKeeper, accountKeeper, reader, appCodec),
		&exec,
	))

	protectedGranter := accountKeeper.account.GetAddress()
	nativeExecutor := addNativePQCAccount(t, &accountKeeper)
	inner = banktypes.NewMsgSend(protectedGranter, nativeExecutor, sdk.NewCoins(sdk.NewInt64Coin("stake", 1)))
	exec = authz.NewMsgExec(nativeExecutor, []sdk.Msg{inner})
	require.NoError(t, runAuthzDecorator(
		ctx,
		authzDecorator(moduleKeeper, accountKeeper, reader, appCodec),
		&exec,
	))
}

func TestAuthzExecRejectsExcessiveNesting(t *testing.T) {
	ctx, moduleKeeper, accountKeeper, _, _ := setupAnteTest(t)
	executor := addNativePQCAccount(t, &accountKeeper)
	var message sdk.Msg = banktypes.NewMsgSend(
		accountKeeper.account.GetAddress(),
		executor,
		sdk.NewCoins(sdk.NewInt64Coin("stake", 1)),
	)
	for range maxNestedAuthzDepth + 2 {
		nested := authz.NewMsgExec(executor, []sdk.Msg{message})
		message = &nested
	}
	top := message.(*authz.MsgExec)

	err := runAuthzDecorator(
		ctx,
		authzDecorator(moduleKeeper, accountKeeper, &authzGrantReaderMock{}, newAnteTestCodec(t)),
		top,
	)
	require.ErrorIs(t, err, types.ErrUnsafeAuthorization)
	require.Contains(t, err.Error(), "depth")
}

func TestAuthzExecCannotCreateUnsafeNestedGrant(t *testing.T) {
	ctx, moduleKeeper, accountKeeper, _, _ := setupAnteTest(t)
	protectedGranter := accountKeeper.account.GetAddress()
	secureExecutor := addNativePQCAccount(t, &accountKeeper)
	unsafeTarget := addClassicAccount(&accountKeeper)
	nestedGrant, err := authz.NewMsgGrant(
		protectedGranter,
		unsafeTarget,
		authz.NewGenericAuthorization(sdk.MsgTypeURL(&banktypes.MsgSend{})),
		nil,
	)
	require.NoError(t, err)
	exec := authz.NewMsgExec(secureExecutor, []sdk.Msg{nestedGrant})

	err = runAuthzDecorator(
		ctx,
		authzDecorator(moduleKeeper, accountKeeper, &authzGrantReaderMock{}, newAnteTestCodec(t)),
		&exec,
	)
	require.ErrorIs(t, err, types.ErrUnsafeAuthorization)
	require.Contains(t, err.Error(), "cannot delegate")
}
