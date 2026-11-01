package ante

import (
	"testing"

	"github.com/DoraFactory/doravota/x/pqcauth/types"
	"github.com/cosmos/cosmos-sdk/crypto/keys/mldsa65"
	"github.com/cosmos/cosmos-sdk/crypto/keys/secp256k1"
	cryptotypes "github.com/cosmos/cosmos-sdk/crypto/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
	authtypes "github.com/cosmos/cosmos-sdk/x/auth/types"
	"github.com/stretchr/testify/require"
)

func TestBudgetSimulationPlaceholderIsolation(t *testing.T) {
	ctx, keeper, _, _, _ := setupAnteTest(t)
	native, err := mldsa65.GenPrivKey()
	require.NoError(t, err)
	owner := sdk.AccAddress(native.PubKey().Address())
	account := authtypes.NewBaseAccountWithAddress(owner)
	ak := accountKeeperMock{accounts: map[string]sdk.AccountI{owner.String(): account}}
	placeholderTx := nativeBudgetTestTx(owner, &secp256k1.PubKey{})
	tracker := NewPQCVerificationBudgetTracker(ak)
	inspection, err := tracker.inspect(ctx, placeholderTx, types.DefaultParams(), true)
	require.NoError(t, err)
	require.Zero(t, inspection.Cost.Total())
	require.Empty(t, inspection.discovered)
	tracker.Commit(inspection)
	require.Empty(t, tracker.knownKeys)
	_, err = tracker.Inspect(ctx, placeholderTx, types.DefaultParams())
	require.ErrorContains(t, err, "public key does not match signer address")

	for _, key := range []cryptotypes.PubKey{
		secp256k1.GenPrivKey().PubKey(),
		&secp256k1.PubKey{Key: []byte{1}},
		&mldsa65.PubKey{Key: []byte{1}},
	} {
		_, err := tracker.inspect(ctx, nativeBudgetTestTx(owner, key), types.DefaultParams(), true)
		require.Error(t, err, "simulation exception is only the SDK empty classic placeholder")
	}

	decorator := NewValidatePQCVerificationBudgetDecorator(keeper, ak)
	for _, simulate := range []bool{false, true} {
		called := false
		_, err := decorator.AnteHandle(ctx, placeholderTx, simulate, func(ctx sdk.Context, _ sdk.Tx, _ bool) (sdk.Context, error) {
			called = true
			return ctx, nil
		})
		if simulate {
			require.NoError(t, err)
		} else {
			require.Error(t, err)
		}
		require.Equal(t, simulate, called)
	}

	inspection, err = tracker.inspect(ctx, nativeBudgetTestTx(owner, native.PubKey()), types.DefaultParams(), true)
	require.NoError(t, err)
	require.EqualValues(t, 1, inspection.Cost.NativeSignatures)
	tracker.Commit(inspection)
	inspection, err = tracker.inspect(ctx, placeholderTx, types.DefaultParams(), true)
	require.NoError(t, err)
	require.EqualValues(t, 1, inspection.Cost.NativeSignatures, "tracked native key overrides placeholder")
	require.NoError(t, account.SetPubKey(native.PubKey()))
	inspection, err = NewPQCVerificationBudgetTracker(ak).inspect(ctx, placeholderTx, types.DefaultParams(), true)
	require.NoError(t, err)
	require.EqualValues(t, 1, inspection.Cost.NativeSignatures, "persisted native key overrides placeholder")
	params := types.DefaultParams()
	params.MaxPqcSigners = types.MinimumMaxPQCSigners
	params.MaxPqcVerificationsPerTx = types.MinimumMaxPQCVerificationsPerTx
	require.NoError(t, keeper.SetParams(ctx, params))
	overBudget := nativeBudgetTestTx(owner, &secp256k1.PubKey{})
	overBudget.messages = []sdk.Msg{&types.MsgRegisterKey{}, &types.MsgRegisterKey{}}
	called := false
	_, err = decorator.AnteHandle(ctx, overBudget, true, func(ctx sdk.Context, _ sdk.Tx, _ bool) (sdk.Context, error) {
		called = true
		return ctx, nil
	})
	require.ErrorIs(t, err, types.ErrVerificationBudget, "simulation must still enforce verification limits")
	require.False(t, called)
}
