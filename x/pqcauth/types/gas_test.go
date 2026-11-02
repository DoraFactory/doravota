package types

import (
	"math"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestEstimateVerificationGas(t *testing.T) {
	estimate, err := EstimateVerificationGas(DefaultParams(), 2, 3)
	require.NoError(t, err)
	require.Equal(t, uint64(2), estimate.SignatureVerifications)
	require.Equal(t, uint64(3), estimate.ProofVerifications)
	require.Equal(t, uint64(1_500), estimate.SignatureGas)
	require.Equal(t, uint64(2_250), estimate.ProofGas)
	require.Equal(t, uint64(3_750), estimate.Total)
}

func TestEstimateVerificationGasUsesSafeEffectiveDefaults(t *testing.T) {
	params := DefaultParams()
	params.VerificationGas = math.MaxUint64
	estimate, err := EstimateVerificationGas(params, 1, 1)
	require.NoError(t, err)
	require.Equal(t, DefaultVerificationGas, estimate.SignatureGas)
	require.Equal(t, DefaultVerificationGas, estimate.ProofGas)
}

func TestEstimateVerificationGasRejectsOverflow(t *testing.T) {
	_, err := EstimateVerificationGas(DefaultParams(), math.MaxUint64, 0)
	require.ErrorIs(t, err, ErrInvalidParams)

	params := DefaultParams()
	params.VerificationGas = AbsoluteMaxVerificationGas
	count := math.MaxUint64 / AbsoluteMaxVerificationGas
	_, err = EstimateVerificationGas(params, count, count)
	require.ErrorIs(t, err, ErrInvalidParams)
}
