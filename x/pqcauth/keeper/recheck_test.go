package keeper

import (
	"testing"

	"github.com/DoraFactory/doravota/x/pqcauth/types"
	storetypes "github.com/cosmos/cosmos-sdk/store/v2/types"
	"github.com/stretchr/testify/require"
)

func TestRecheckKeyProofRetainsGas(t *testing.T) {
	k, ctx := setupKeeper(t, 10)
	p := types.DefaultParams()
	pub, secret := keyPair(3)
	proof := keyProof(t, ctx, p, k.Authority(), 1, types.Algorithm_ALGORITHM_ML_DSA_65, pub, secret, types.KeyRole_KEY_ROLE_SIGNING, types.PurposeRegisterSigning, 0, []byte(types.RegisterProofContext))
	for _, recheck := range []bool{false, true} {
		meter := storetypes.NewInfiniteGasMeter()
		err := VerifyKeyProof(ctx.WithIsReCheckTx(recheck).WithGasMeter(meter), p, k.Authority(), 1, types.Algorithm_ALGORITHM_ML_DSA_65, pub, types.KeyRole_KEY_ROLE_SIGNING, types.PurposeRegisterSigning, 0, proof, []byte(types.RegisterProofContext))
		require.NoError(t, err)
		require.EqualValues(t, 750, meter.GasConsumed())
	}
}
