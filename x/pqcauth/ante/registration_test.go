package ante

import (
	"testing"
	"time"

	"github.com/cosmos/cosmos-sdk/crypto/keys/secp256k1"
	sdk "github.com/cosmos/cosmos-sdk/types"
	authtypes "github.com/cosmos/cosmos-sdk/x/auth/types"
	"github.com/stretchr/testify/require"

	"github.com/DoraFactory/doravota/x/pqcauth/internal/execution"
	"github.com/DoraFactory/doravota/x/pqcauth/types"
)

type unorderedRegistrationTx struct {
	extensionOptionsTxStub
}

func (unorderedRegistrationTx) GetTimeoutTimeStamp() time.Time { return time.Unix(1, 0) }
func (unorderedRegistrationTx) GetUnordered() bool             { return true }

func TestCaptureRegistrationStateBeforeSetPubKey(t *testing.T) {
	ctx, _, accountKeeper, _, _ := setupAnteTest(t)
	privateKey := secp256k1.GenPrivKey()
	owner := sdk.AccAddress(privateKey.PubKey().Address())
	message := &types.MsgRegisterKey{Owner: owner.String()}
	tx := extensionOptionsTxStub{messages: []sdk.Msg{message}}

	accountKeeper.accounts[owner.String()] = authtypes.NewBaseAccount(owner, nil, 17, 0)
	decorator := NewCaptureRegistrationStateDecorator(accountKeeper)
	_, err := decorator.AnteHandle(ctx, tx, false, func(
		captured sdk.Context,
		_ sdk.Tx,
		_ bool,
	) (sdk.Context, error) {
		require.True(t, execution.IsFreshRegistrationCandidate(captured, message))
		return captured, nil
	})
	require.NoError(t, err)

	for name, account := range map[string]sdk.AccountI{
		"public key already stored": authtypes.NewBaseAccount(owner, privateKey.PubKey(), 17, 0),
		"sequence already consumed": authtypes.NewBaseAccount(owner, nil, 17, 1),
	} {
		t.Run(name, func(t *testing.T) {
			keeper := accountKeeper
			keeper.accounts = map[string]sdk.AccountI{owner.String(): account}
			_, err := NewCaptureRegistrationStateDecorator(keeper).AnteHandle(
				ctx,
				tx,
				false,
				func(captured sdk.Context, _ sdk.Tx, _ bool) (sdk.Context, error) {
					require.False(t, execution.IsFreshRegistrationCandidate(captured, message))
					return captured, nil
				},
			)
			require.NoError(t, err)
		})
	}

	accountKeeper.accounts[owner.String()] = authtypes.NewBaseAccount(owner, nil, 17, 0)
	_, err = decorator.AnteHandle(
		ctx,
		unorderedRegistrationTx{extensionOptionsTxStub: tx},
		false,
		func(captured sdk.Context, _ sdk.Tx, _ bool) (sdk.Context, error) {
			require.False(t, execution.IsFreshRegistrationCandidate(captured, message))
			return captured, nil
		},
	)
	require.NoError(t, err)
}
