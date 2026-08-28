package ante

import (
	"testing"

	"github.com/cosmos/cosmos-sdk/crypto/keys/mldsa65"
	"github.com/cosmos/cosmos-sdk/crypto/keys/multisig"
	"github.com/cosmos/cosmos-sdk/crypto/keys/secp256k1"
	cryptotypes "github.com/cosmos/cosmos-sdk/crypto/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
	txsigning "github.com/cosmos/cosmos-sdk/types/tx/signing"
	authtypes "github.com/cosmos/cosmos-sdk/x/auth/types"
	"github.com/stretchr/testify/require"

	"github.com/DoraFactory/doravota/x/pqcauth/types"
)

func TestPQCVerificationBudgetCountsHybridAndLifecycleWork(t *testing.T) {
	ctx, moduleKeeper, accountKeeper, txConfig, privateKey := setupAnteTest(t)
	_, hybridTx := buildProtectedTx(t, ctx, moduleKeeper, accountKeeper, txConfig, privateKey)
	tracker := NewPQCVerificationBudgetTracker(accountKeeper)
	inspection, err := tracker.Inspect(ctx, hybridTx, types.DefaultParams())
	require.NoError(t, err)
	require.Equal(t, PQCVerificationCost{PQCAuthSignatures: 1}, inspection.Cost)

	registerTx := sigVerifiableTxStub{
		extensionOptionsTxStub: extensionOptionsTxStub{
			messages: []sdk.Msg{&types.MsgRegisterKey{}},
		},
		signers: []sdk.AccAddress{accountKeeper.account.GetAddress()},
		signatures: []txsigning.SignatureV2{{
			PubKey: accountKeeper.account.GetPubKey(),
			Data:   &txsigning.SingleSignatureData{},
		}},
	}
	inspection, err = tracker.Inspect(ctx, registerTx, types.DefaultParams())
	require.NoError(t, err)
	require.Equal(t, PQCVerificationCost{LifecycleProofs: 2}, inspection.Cost)
}

func TestPQCVerificationBudgetTracksFreshNativeAccountWithinProposal(t *testing.T) {
	ctx, _, _, _, _ := setupAnteTest(t)
	privateKey, err := mldsa65.GenPrivKey()
	require.NoError(t, err)
	address := sdk.AccAddress(privateKey.PubKey().Address())
	account := authtypes.NewBaseAccountWithAddress(address)
	accountKeeper := accountKeeperMock{
		accounts: map[string]sdk.AccountI{address.String(): account},
	}
	tracker := NewPQCVerificationBudgetTracker(accountKeeper)
	first := nativeBudgetTestTx(address, privateKey.PubKey())
	inspection, err := tracker.Inspect(ctx, first, types.DefaultParams())
	require.NoError(t, err)
	require.Equal(t, uint64(1), inspection.Cost.NativeSignatures)
	tracker.Commit(inspection)

	second := nativeBudgetTestTx(address, nil)
	inspection, err = tracker.Inspect(ctx, second, types.DefaultParams())
	require.NoError(t, err)
	require.Equal(t, uint64(1), inspection.Cost.NativeSignatures)

	// Once the account store has a key, transaction-controlled signer metadata
	// cannot disguise the persisted native ML-DSA authentication type.
	require.NoError(t, account.SetPubKey(privateKey.PubKey()))
	spoofedClassic := nativeBudgetTestTx(address, secp256k1.GenPrivKey().PubKey())
	inspection, err = NewPQCVerificationBudgetTracker(accountKeeper).Inspect(
		ctx,
		spoofedClassic,
		types.DefaultParams(),
	)
	require.NoError(t, err)
	require.Equal(t, uint64(1), inspection.Cost.NativeSignatures)
}

func TestPQCVerificationBudgetCountsNativeMLDSALeavesInMultisig(t *testing.T) {
	nativeKey, err := mldsa65.GenPrivKey()
	require.NoError(t, err)
	classicKey := secp256k1.GenPrivKey()
	publicKey := multisig.NewLegacyAminoPubKey(
		2,
		[]cryptotypes.PubKey{nativeKey.PubKey(), classicKey.PubKey()},
	)
	bitArray := cryptotypes.NewCompactBitArray(2)
	bitArray.SetIndex(0, true)
	bitArray.SetIndex(1, true)
	signature := &txsigning.MultiSignatureData{
		BitArray: bitArray,
		Signatures: []txsigning.SignatureData{
			&txsigning.SingleSignatureData{},
			&txsigning.SingleSignatureData{},
		},
	}
	require.Equal(t, uint64(1), countNativeMLDSAVerifications(publicKey, signature))
}

func TestPQCVerificationBudgetDecoratorRejectsBeforeNextHandler(t *testing.T) {
	ctx, moduleKeeper, accountKeeper, _, _ := setupAnteTest(t)
	params := types.DefaultParams()
	params.MaxPqcVerificationsPerTx = 1
	require.NoError(t, moduleKeeper.SetParams(ctx, params))
	tx := sigVerifiableTxStub{
		extensionOptionsTxStub: extensionOptionsTxStub{
			messages: []sdk.Msg{&types.MsgRegisterKey{}},
		},
		signers: []sdk.AccAddress{accountKeeper.account.GetAddress()},
		signatures: []txsigning.SignatureV2{{
			PubKey: accountKeeper.account.GetPubKey(),
			Data:   &txsigning.SingleSignatureData{},
		}},
	}
	called := false
	_, err := NewValidatePQCVerificationBudgetDecorator(moduleKeeper, accountKeeper).AnteHandle(
		ctx,
		tx,
		false,
		func(ctx sdk.Context, _ sdk.Tx, _ bool) (sdk.Context, error) {
			called = true
			return ctx, nil
		},
	)
	require.ErrorIs(t, err, types.ErrVerificationBudget)
	require.False(t, called)
}

func nativeBudgetTestTx(address sdk.AccAddress, publicKey cryptotypes.PubKey) sigVerifiableTxStub {
	return sigVerifiableTxStub{
		extensionOptionsTxStub: extensionOptionsTxStub{},
		signers:                []sdk.AccAddress{address},
		signatures: []txsigning.SignatureV2{{
			PubKey: publicKey,
			Data:   &txsigning.SingleSignatureData{},
		}},
	}
}
