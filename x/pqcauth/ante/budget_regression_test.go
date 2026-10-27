package ante

import (
	"testing"

	"github.com/DoraFactory/doravota/x/pqcauth/types"
	"github.com/cosmos/cosmos-sdk/crypto/keys/mldsa65"
	"github.com/cosmos/cosmos-sdk/crypto/keys/multisig"
	"github.com/cosmos/cosmos-sdk/crypto/keys/secp256k1"
	cryptotypes "github.com/cosmos/cosmos-sdk/crypto/types"
	storetypes "github.com/cosmos/cosmos-sdk/store/v2/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
	signing "github.com/cosmos/cosmos-sdk/types/tx/signing"
	authtypes "github.com/cosmos/cosmos-sdk/x/auth/types"
	"github.com/stretchr/testify/require"
)

func TestBudgetRejectsFreshKeyPoisoning(t *testing.T) {
	ctx, _, _, _, _ := setupAnteTest(t)
	native, err := mldsa65.GenPrivKey()
	require.NoError(t, err)
	owner := sdk.AccAddress(native.PubKey().Address())
	ak := accountKeeperMock{accounts: map[string]sdk.AccountI{owner.String(): authtypes.NewBaseAccountWithAddress(owner)}}
	tracker := NewPQCVerificationBudgetTracker(ak)
	_, err = tracker.Inspect(ctx, nativeBudgetTestTx(owner, secp256k1.GenPrivKey().PubKey()), types.DefaultParams())
	require.ErrorContains(t, err, "public key does not match signer address")
	require.Empty(t, tracker.knownKeys)
	good, err := tracker.Inspect(ctx, nativeBudgetTestTx(owner, native.PubKey()), types.DefaultParams())
	require.NoError(t, err)
	require.Equal(t, uint64(1), good.Cost.NativeSignatures, "an invalid preceding key must not hide a native verification")
	tracker.Commit(good)
	followup, err := tracker.Inspect(ctx, nativeBudgetTestTx(owner, nil), types.DefaultParams())
	require.NoError(t, err)
	require.Equal(t, uint64(1), followup.Cost.NativeSignatures)
}

func TestMultisigNativeGasFloor(t *testing.T) {
	native, err := mldsa65.GenPrivKey()
	require.NoError(t, err)
	key := multisig.NewLegacyAminoPubKey(1, []cryptotypes.PubKey{native.PubKey()})
	bits := cryptotypes.NewCompactBitArray(1)
	bits.SetIndex(0, true)
	sig := signing.SignatureV2{PubKey: key, Data: &signing.MultiSignatureData{BitArray: bits, Signatures: []signing.SignatureData{&signing.SingleSignatureData{}}}}
	params := authtypes.DefaultParams()
	params.SigVerifyCostMlDsa65 = 1
	meter := storetypes.NewInfiniteGasMeter()
	require.NoError(t, PQCSafeSigVerificationGasConsumer(meter, sig, params))
	require.Equal(t, MinimumNativeMLDSAVerificationGas, meter.GasConsumed())
}

func TestBudgetRejectsMalformedFreshKeyWithoutPanic(t *testing.T) {
	ctx, _, _, _, _ := setupAnteTest(t)
	owner := sdk.AccAddress(secp256k1.GenPrivKey().PubKey().Address())
	for _, key := range []cryptotypes.PubKey{
		&mldsa65.PubKey{Key: []byte{1}},
		&secp256k1.PubKey{Key: []byte{1}},
	} {
		tracker := NewPQCVerificationBudgetTracker(nil)
		require.NotPanics(t, func() {
			_, err := tracker.Inspect(ctx, nativeBudgetTestTx(owner, key), types.DefaultParams())
			require.Error(t, err)
		})
		require.Empty(t, tracker.knownKeys)
	}
}

func TestNestedMultisigNativeGasFloorAndHigherCost(t *testing.T) {
	native, err := mldsa65.GenPrivKey()
	require.NoError(t, err)
	classic := secp256k1.GenPrivKey().PubKey()
	inner := multisig.NewLegacyAminoPubKey(1, []cryptotypes.PubKey{native.PubKey()})
	outer := multisig.NewLegacyAminoPubKey(2, []cryptotypes.PubKey{classic, inner})
	innerBits := cryptotypes.NewCompactBitArray(1)
	innerBits.SetIndex(0, true)
	outerBits := cryptotypes.NewCompactBitArray(2)
	outerBits.SetIndex(0, true)
	outerBits.SetIndex(1, true)
	sig := signing.SignatureV2{PubKey: outer, Data: &signing.MultiSignatureData{
		BitArray: outerBits, Signatures: []signing.SignatureData{
			&signing.SingleSignatureData{},
			&signing.MultiSignatureData{BitArray: innerBits, Signatures: []signing.SignatureData{&signing.SingleSignatureData{}}},
		},
	}}
	for _, cost := range []uint64{0, 1, MinimumNativeMLDSAVerificationGas, 12345} {
		params := authtypes.DefaultParams()
		params.SigVerifyCostMlDsa65 = cost
		meter := storetypes.NewInfiniteGasMeter()
		require.NoError(t, PQCSafeSigVerificationGasConsumer(meter, sig, params))
		require.Equal(t, params.SigVerifyCostSecp256k1+max(cost, MinimumNativeMLDSAVerificationGas), meter.GasConsumed())
	}
}
