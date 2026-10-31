package ante

import (
	group "github.com/DoraFactory/doravota/third_party/cosmos-sdk-x-group-v055-compat"
	"github.com/DoraFactory/doravota/x/pqcauth/types"
	codectypes "github.com/cosmos/cosmos-sdk/codec/types"
	"github.com/cosmos/cosmos-sdk/crypto/keys/secp256k1"
	cryptotypes "github.com/cosmos/cosmos-sdk/crypto/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
	authtypes "github.com/cosmos/cosmos-sdk/x/auth/types"
	"github.com/cosmos/cosmos-sdk/x/authz"
	banktypes "github.com/cosmos/cosmos-sdk/x/bank/types"
	govv1 "github.com/cosmos/cosmos-sdk/x/gov/types/v1"
	"github.com/stretchr/testify/require"
	"testing"
)

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

func authtypesBaseAccount(address sdk.AccAddress, publicKey cryptotypes.PubKey) sdk.AccountI {
	account := authtypes.NewBaseAccountWithAddress(address)
	if err := account.SetPubKey(publicKey); err != nil {
		panic(err)
	}
	return account
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
