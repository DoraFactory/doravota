package ante

import (
	"context"
	"errors"
	"testing"

	wasmtypes "github.com/CosmWasm/wasmd/x/wasm/types"
	"github.com/cosmos/cosmos-sdk/codec"
	codectypes "github.com/cosmos/cosmos-sdk/codec/types"
	sdkmldsa65 "github.com/cosmos/cosmos-sdk/crypto/keys/mldsa65"
	"github.com/cosmos/cosmos-sdk/crypto/keys/secp256k1"
	cryptotypes "github.com/cosmos/cosmos-sdk/crypto/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
	authtypes "github.com/cosmos/cosmos-sdk/x/auth/types"
	"github.com/cosmos/cosmos-sdk/x/authz"
	banktypes "github.com/cosmos/cosmos-sdk/x/bank/types"
	"github.com/cosmos/cosmos-sdk/x/feegrant"
	govv1 "github.com/cosmos/cosmos-sdk/x/gov/types/v1"
	"github.com/stretchr/testify/require"

	group "github.com/DoraFactory/doravota/third_party/cosmos-sdk-x-group-v055-compat"
	pqccrypto "github.com/DoraFactory/doravota/x/pqcauth/crypto"
	pqckeeper "github.com/DoraFactory/doravota/x/pqcauth/keeper"
	"github.com/DoraFactory/doravota/x/pqcauth/types"
)

type authzGrantReaderMock struct {
	grants  map[string][]*authz.GrantAuthorization
	err     error
	request *authz.QueryGranterGrantsRequest
}

type delegatedFeeTxStub struct {
	extensionOptionsTxStub
	feePayer   sdk.AccAddress
	feeGranter sdk.AccAddress
}

func (delegatedFeeTxStub) GetGas() uint64        { return 1_000_000 }
func (delegatedFeeTxStub) GetFee() sdk.Coins     { return nil }
func (tx delegatedFeeTxStub) FeePayer() []byte   { return tx.feePayer }
func (tx delegatedFeeTxStub) FeeGranter() []byte { return tx.feeGranter }

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

func runAuthzTx(ctx sdk.Context, decorator AuthzPQCDecorator, tx sdk.Tx) error {
	_, err := decorator.AnteHandle(
		ctx,
		tx,
		false,
		func(nextCtx sdk.Context, _ sdk.Tx, _ bool) (sdk.Context, error) {
			return nextCtx, nil
		},
	)
	return err
}

func runPQCStructureDecorator(
	ctx sdk.Context,
	decorator ValidatePQCStructureDecorator,
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

func TestFeegrantProtectedGranterRequiresPQCGranteeAndFreezesPending(t *testing.T) {
	ctx, moduleKeeper, accountKeeper, _, _ := setupAnteTest(t)
	decorator := authzDecorator(
		moduleKeeper,
		accountKeeper,
		&authzGrantReaderMock{},
		newAnteTestCodec(t),
	)
	granter := accountKeeper.account.GetAddress()
	unsafeGrantee := addClassicAccount(&accountKeeper)
	grant, err := feegrant.NewMsgGrantAllowance(
		&feegrant.BasicAllowance{},
		granter,
		unsafeGrantee,
	)
	require.NoError(t, err)
	require.ErrorIs(t, runAuthzDecorator(ctx, decorator, grant), types.ErrUnsafeAuthorization)

	nativeGrantee := addNativePQCAccount(t, &accountKeeper)
	grant, err = feegrant.NewMsgGrantAllowance(
		&feegrant.BasicAllowance{},
		granter,
		nativeGrantee,
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

func TestFeegrantUseChecksCurrentPayerProtection(t *testing.T) {
	ctx, moduleKeeper, accountKeeper, _, _ := setupAnteTest(t)
	decorator := authzDecorator(
		moduleKeeper,
		accountKeeper,
		&authzGrantReaderMock{},
		newAnteTestCodec(t),
	)
	protectedGranter := accountKeeper.account.GetAddress()
	unsafePayer := addClassicAccount(&accountKeeper)
	recipient := addClassicAccount(&accountKeeper)
	tx := delegatedFeeTxStub{
		extensionOptionsTxStub: extensionOptionsTxStub{messages: []sdk.Msg{
			banktypes.NewMsgSend(
				unsafePayer,
				recipient,
				sdk.NewCoins(sdk.NewInt64Coin("stake", 1)),
			),
		}},
		feePayer:   unsafePayer,
		feeGranter: protectedGranter,
	}
	err := runAuthzTx(ctx, decorator, tx)
	require.ErrorIs(t, err, types.ErrUnsafeAuthorization)
	require.Contains(t, err.Error(), "fee granter")

	protectClassicAccount(t, ctx, moduleKeeper, unsafePayer)
	require.NoError(t, runAuthzTx(ctx, decorator, tx))

	unprotectedGranter := addClassicAccount(&accountKeeper)
	tx.feeGranter = unprotectedGranter
	require.NoError(t, runAuthzTx(ctx, decorator, tx))
}

func TestNestedAuthzChecksEveryDelegationLayer(t *testing.T) {
	ctx, moduleKeeper, accountKeeper, _, _ := setupAnteTest(t)
	protectedGranter := accountKeeper.account.GetAddress()
	unsafeMiddleGrantee := addClassicAccount(&accountKeeper)
	secureOuterGrantee := addNativePQCAccount(t, &accountKeeper)
	recipient := addClassicAccount(&accountKeeper)
	innerMessage := banktypes.NewMsgSend(
		protectedGranter,
		recipient,
		sdk.NewCoins(sdk.NewInt64Coin("stake", 1)),
	)
	innerExec := authz.NewMsgExec(unsafeMiddleGrantee, []sdk.Msg{innerMessage})
	outerExec := authz.NewMsgExec(secureOuterGrantee, []sdk.Msg{&innerExec})
	decorator := authzDecorator(
		moduleKeeper,
		accountKeeper,
		&authzGrantReaderMock{},
		newAnteTestCodec(t),
	)

	err := runAuthzDecorator(ctx, decorator, &outerExec)
	require.ErrorIs(t, err, types.ErrUnsafeAuthorization)
	require.Contains(t, err.Error(), unsafeMiddleGrantee.String())

	protectClassicAccount(t, ctx, moduleKeeper, unsafeMiddleGrantee)
	require.NoError(t, runAuthzDecorator(ctx, decorator, &outerExec))
}

func TestNestedAuthzCannotCreateUnsafeFeeGrant(t *testing.T) {
	ctx, moduleKeeper, accountKeeper, _, _ := setupAnteTest(t)
	protectedGranter := accountKeeper.account.GetAddress()
	secureExecutor := addNativePQCAccount(t, &accountKeeper)
	unsafeFeeGrantee := addClassicAccount(&accountKeeper)
	nestedGrant, err := feegrant.NewMsgGrantAllowance(
		&feegrant.BasicAllowance{},
		protectedGranter,
		unsafeFeeGrantee,
	)
	require.NoError(t, err)
	exec := authz.NewMsgExec(secureExecutor, []sdk.Msg{nestedGrant})

	err = runAuthzDecorator(
		ctx,
		authzDecorator(
			moduleKeeper,
			accountKeeper,
			&authzGrantReaderMock{},
			newAnteTestCodec(t),
		),
		&exec,
	)
	require.ErrorIs(t, err, types.ErrUnsafeAuthorization)
	require.Contains(t, err.Error(), "fee granter")
}

func TestAuthzProtectionCoversWasmAndGroupMessageSigners(t *testing.T) {
	ctx, moduleKeeper, accountKeeper, _, _ := setupAnteTest(t)
	protectedSigner := accountKeeper.account.GetAddress()
	unsafeExecutor := addClassicAccount(&accountKeeper)
	decorator := authzDecorator(
		moduleKeeper,
		accountKeeper,
		&authzGrantReaderMock{},
		newAnteTestCodec(t),
	)

	wasmMessage := &wasmtypes.MsgExecuteContract{
		Sender:   protectedSigner.String(),
		Contract: addClassicAccount(&accountKeeper).String(),
		Msg:      []byte(`{}`),
	}
	wasmExec := authz.NewMsgExec(unsafeExecutor, []sdk.Msg{wasmMessage})
	require.ErrorIs(
		t,
		runAuthzDecorator(ctx, decorator, &wasmExec),
		types.ErrUnsafeAuthorization,
	)

	groupMessage := &group.MsgVote{
		ProposalId: 1,
		Voter:      protectedSigner.String(),
		Option:     group.VOTE_OPTION_YES,
	}
	groupExec := authz.NewMsgExec(unsafeExecutor, []sdk.Msg{groupMessage})
	require.ErrorIs(
		t,
		runAuthzDecorator(ctx, decorator, &groupExec),
		types.ErrUnsafeAuthorization,
	)

	protectClassicAccount(t, ctx, moduleKeeper, unsafeExecutor)
	require.NoError(t, runAuthzDecorator(ctx, decorator, &wasmExec))
	require.NoError(t, runAuthzDecorator(ctx, decorator, &groupExec))
}

func TestIndirectExecutionContainersRejectPQCAuthLifecycleMessages(t *testing.T) {
	ctx, moduleKeeper, accountKeeper, _, _ := setupAnteTest(t)
	decorator := NewValidatePQCStructureDecorator(moduleKeeper)
	owner := accountKeeper.account.GetAddress()
	lifecycle := &types.MsgSetProtection{Owner: owner.String(), Enabled: false}

	authzMessage := authz.NewMsgExec(owner, []sdk.Msg{lifecycle})
	groupMessage := &group.MsgSubmitProposal{
		GroupPolicyAddress: owner.String(),
		Proposers:          []string{owner.String()},
		Title:              "unsafe lifecycle proposal",
		Summary:            "must be rejected during transaction admission",
	}
	require.NoError(t, groupMessage.SetMsgs([]sdk.Msg{lifecycle}))
	govMessage, err := govv1.NewMsgSubmitProposal(
		[]sdk.Msg{lifecycle},
		nil,
		owner.String(),
		"",
		"unsafe lifecycle proposal",
		"must be rejected during transaction admission",
		false,
	)
	require.NoError(t, err)

	for name, message := range map[string]sdk.Msg{
		"authz": &authzMessage,
		"group": groupMessage,
		"gov":   govMessage,
	} {
		t.Run(name, func(t *testing.T) {
			err := runPQCStructureDecorator(ctx, decorator, message)
			require.ErrorIs(t, err, types.ErrNestedLifecycle)
			require.Contains(t, err.Error(), "cannot be embedded")
		})
	}

	// Direct lifecycle messages remain valid inputs to the dedicated lifecycle
	// Ante path. This decorator only rejects indirect execution.
	require.NoError(t, runPQCStructureDecorator(ctx, decorator, lifecycle))
}

func TestIndirectExecutionInspectionRecursesAndPreservesOrdinaryMessages(t *testing.T) {
	ctx, moduleKeeper, accountKeeper, _, _ := setupAnteTest(t)
	decorator := NewValidatePQCStructureDecorator(moduleKeeper)
	owner := addClassicAccount(&accountKeeper)
	recipient := addClassicAccount(&accountKeeper)
	bankMessage := banktypes.NewMsgSend(
		owner,
		recipient,
		sdk.NewCoins(sdk.NewInt64Coin("stake", 1)),
	)
	groupMessage := &group.MsgSubmitProposal{
		GroupPolicyAddress: owner.String(),
		Proposers:          []string{owner.String()},
		Title:              "ordinary proposal",
		Summary:            "ordinary SDK messages remain supported",
	}
	require.NoError(t, groupMessage.SetMsgs([]sdk.Msg{bankMessage}))
	govMessage, err := govv1.NewMsgSubmitProposal(
		[]sdk.Msg{groupMessage},
		nil,
		owner.String(),
		"",
		"nested ordinary proposal",
		"recursive inspection must not reject ordinary messages",
		false,
	)
	require.NoError(t, err)
	require.NoError(t, runPQCStructureDecorator(ctx, decorator, govMessage))

	lifecycle := &types.MsgSetProtection{Owner: owner.String(), Enabled: false}
	require.NoError(t, groupMessage.SetMsgs([]sdk.Msg{lifecycle}))
	govMessage, err = govv1.NewMsgSubmitProposal(
		[]sdk.Msg{groupMessage},
		nil,
		owner.String(),
		"",
		"nested unsafe proposal",
		"recursive inspection must find the lifecycle message",
		false,
	)
	require.NoError(t, err)
	require.ErrorIs(
		t,
		runPQCStructureDecorator(ctx, decorator, govMessage),
		types.ErrNestedLifecycle,
	)
}

func TestIndirectExecutionInspectionFailsClosedOnMalformedContainer(t *testing.T) {
	ctx, moduleKeeper, accountKeeper, _, _ := setupAnteTest(t)
	decorator := NewValidatePQCStructureDecorator(moduleKeeper)
	malformed := &group.MsgSubmitProposal{
		GroupPolicyAddress: accountKeeper.account.GetAddress().String(),
		Messages: []*codectypes.Any{{
			TypeUrl: "/unknown.security.Message",
			Value:   []byte{0xff},
		}},
	}

	err := runPQCStructureDecorator(ctx, decorator, malformed)
	require.ErrorIs(t, err, types.ErrUnsafeAuthorization)
	require.Contains(t, err.Error(), "cannot inspect group proposal")
}

func TestAuthzDecoratorLeavesOrdinaryMultiSignerRejectionToAuthz(t *testing.T) {
	ctx, moduleKeeper, accountKeeper, _, _ := setupAnteTest(t)
	first := addClassicAccount(&accountKeeper)
	second := addClassicAccount(&accountKeeper)
	multiSignerMessage := &group.MsgSubmitProposal{
		GroupPolicyAddress: addClassicAccount(&accountKeeper).String(),
		Proposers:          []string{first.String(), second.String()},
		Title:              "ordinary group proposal",
		Summary:            "cardinality remains an x/authz decision",
	}
	executor := addClassicAccount(&accountKeeper)
	exec := authz.NewMsgExec(executor, []sdk.Msg{multiSignerMessage})

	require.NoError(t, runAuthzDecorator(
		ctx,
		authzDecorator(
			moduleKeeper,
			accountKeeper,
			&authzGrantReaderMock{},
			newAnteTestCodec(t),
		),
		&exec,
	))
}
