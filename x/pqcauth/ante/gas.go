package ante

import (
	"github.com/cosmos/cosmos-sdk/crypto/keys/mldsa65"
	storetypes "github.com/cosmos/cosmos-sdk/store/v2/types"
	txsigning "github.com/cosmos/cosmos-sdk/types/tx/signing"
	authante "github.com/cosmos/cosmos-sdk/x/auth/ante"
	authtypes "github.com/cosmos/cosmos-sdk/x/auth/types"
)

// MinimumNativeMLDSAVerificationGas preserves the SDK v0.55 benchmark-backed
// floor even if an x/auth parameter proposal attempts to make native ML-DSA
// verification effectively free. The large public key and signature continue
// to be charged separately by ConsumeGasForTxSize.
const MinimumNativeMLDSAVerificationGas = authtypes.DefaultSigVerifyCostMlDsa65

// PQCSafeSigVerificationGasConsumer delegates to the SDK consumer after
// enforcing the native ML-DSA gas floor. Other key algorithms and configured
// ML-DSA costs above the floor are unchanged.
func PQCSafeSigVerificationGasConsumer(
	meter storetypes.GasMeter,
	signature txsigning.SignatureV2,
	params authtypes.Params,
) error {
	if _, isMLDSA := signature.PubKey.(*mldsa65.PubKey); isMLDSA &&
		params.SigVerifyCostMlDsa65 < MinimumNativeMLDSAVerificationGas {
		params.SigVerifyCostMlDsa65 = MinimumNativeMLDSAVerificationGas
	}
	return authante.DefaultSigVerificationGasConsumer(meter, signature, params)
}
