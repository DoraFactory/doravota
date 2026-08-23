package ante

import (
	"testing"

	sdkmldsa65 "github.com/cosmos/cosmos-sdk/crypto/keys/mldsa65"
	"github.com/cosmos/cosmos-sdk/crypto/keys/secp256k1"
	storetypes "github.com/cosmos/cosmos-sdk/store/v2/types"
	txsigning "github.com/cosmos/cosmos-sdk/types/tx/signing"
	authtypes "github.com/cosmos/cosmos-sdk/x/auth/types"
	"github.com/stretchr/testify/require"
)

func TestPQCSafeSigVerificationGasConsumerEnforcesNativeFloor(t *testing.T) {
	privateKey, err := sdkmldsa65.GenPrivKey()
	require.NoError(t, err)
	params := authtypes.DefaultParams()
	params.SigVerifyCostMlDsa65 = 1
	meter := storetypes.NewInfiniteGasMeter()
	require.NoError(t, PQCSafeSigVerificationGasConsumer(
		meter,
		txsigning.SignatureV2{PubKey: privateKey.PubKey()},
		params,
	))
	require.Equal(t, MinimumNativeMLDSAVerificationGas, meter.GasConsumed())
}

func TestPQCSafeSigVerificationGasConsumerPreservesHigherNativeCost(t *testing.T) {
	privateKey, err := sdkmldsa65.GenPrivKey()
	require.NoError(t, err)
	params := authtypes.DefaultParams()
	params.SigVerifyCostMlDsa65 = 12_345
	meter := storetypes.NewInfiniteGasMeter()
	require.NoError(t, PQCSafeSigVerificationGasConsumer(
		meter,
		txsigning.SignatureV2{PubKey: privateKey.PubKey()},
		params,
	))
	require.Equal(t, uint64(12_345), meter.GasConsumed())
}

func TestPQCSafeSigVerificationGasConsumerLeavesClassicCostUnchanged(t *testing.T) {
	params := authtypes.DefaultParams()
	params.SigVerifyCostMlDsa65 = 1
	meter := storetypes.NewInfiniteGasMeter()
	require.NoError(t, PQCSafeSigVerificationGasConsumer(
		meter,
		txsigning.SignatureV2{PubKey: secp256k1.GenPrivKey().PubKey()},
		params,
	))
	require.Equal(t, params.SigVerifyCostSecp256k1, meter.GasConsumed())
}
