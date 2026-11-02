package types

import (
	"math"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestPQCVerificationPriceCapacity(t *testing.T) {
	p := DefaultParams()
	p.VerificationGas = AbsoluteMaxVerificationGas
	require.NoError(t, p.Validate())
	require.Error(t, p.ValidateVerificationGasCapacity(30_000_000))
	require.NoError(t, p.ValidateVerificationGasCapacity(30_000_001))
	require.NoError(t, p.ValidateVerificationGasCapacity(-1))
	require.Error(t, p.ValidateVerificationGasCapacity(0))
	p.VerificationGas = math.MaxUint64
	require.Error(t, p.ValidateVerificationGasCapacity(math.MaxInt64))
}
