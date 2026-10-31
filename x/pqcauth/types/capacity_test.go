package types

import (
	"math"
	"strings"
	"testing"

	pqccrypto "github.com/DoraFactory/doravota/x/pqcauth/crypto"
	"github.com/stretchr/testify/require"
)

func TestPQCParameterCapacityBounds(t *testing.T) {
	for _, mutate := range []struct {
		name string
		fn   func(*Params)
	}{
		{"auth bytes one", func(p *Params) { p.MaxPqcAuthBytes = 1 }},
		{"auth bytes short", func(p *Params) { p.MaxPqcAuthBytes = MinimumPQCAuthBytes(p.MaxPqcSigners) - 1 }},
		{"one signer", func(p *Params) { p.MaxPqcSigners = 1 }},
		{"budget one", func(p *Params) { p.MaxPqcVerificationsPerTx = 1 }},
		{"budget two", func(p *Params) { p.MaxPqcVerificationsPerTx = 2 }},
		{"budget below signers", func(p *Params) { p.MaxPqcVerificationsPerTx = 3 }},
		{"block below transaction", func(p *Params) { p.MaxPqcVerificationsPerBlock = 1 }},
	} {
		t.Run(mutate.name, func(t *testing.T) {
			p := DefaultParams()
			mutate.fn(&p)
			require.Error(t, p.Validate())
			require.Error(t, p.ValidateGovernanceUpdate())
			g := DefaultGenesisState()
			g.Params = p
			require.Error(t, ValidateGenesis(*g))
			current := DefaultParams()
			pending := p.AsScheduled()
			current.Pending, current.PendingActivationHeight = &pending, 10
			require.Error(t, current.Validate(), "invalid pending policy must also be rejected")
		})
	}
	p := DefaultParams()
	p.MaxPqcSigners = MinimumMaxPQCSigners
	p.MaxPqcAuthBytes = MinimumPQCAuthBytes(p.MaxPqcSigners)
	p.MaxPqcVerificationsPerTx = MinimumMaxPQCVerificationsPerTx
	p.MaxPqcVerificationsPerBlock = p.MaxPqcVerificationsPerTx
	require.NoError(t, p.ValidateGovernanceUpdate())
	// Zero retains the existing backward-compatible default-budget semantics.
	p.MaxPqcVerificationsPerTx, p.MaxPqcVerificationsPerBlock = 0, 0
	require.NoError(t, p.Validate())
}

func TestPQCAuthByteFloorCoversMaximumEncoding(t *testing.T) {
	_, sigSize, err := pqccrypto.Sizes(pqccrypto.AlgorithmMLDSA65)
	require.NoError(t, err)
	for _, count := range []uint32{1, MinimumMaxPQCSigners, DefaultMaxPQCSigners, AbsoluteMaxPQCSigners} {
		ext := ExtensionPQCAuth{FormatVersion: FormatVersionV1}
		for i := uint32(0); i < count; i++ {
			ext.Signatures = append(ext.Signatures, SignerPQCSignature{
				Signer: strings.Repeat("x", MaxPQCSignerAddressBytes), SignerIndex: math.MaxUint32 - count + 1 + i,
				KeyId: math.MaxUint64, PolicyVersion: math.MaxUint64,
				Algorithm: Algorithm_ALGORITHM_ML_DSA_65, Signature: make([]byte, sigSize),
			})
		}
		encoded, err := ext.Marshal()
		require.NoError(t, err)
		require.EqualValues(t, len(encoded), MinimumPQCAuthBytes(count))
		require.LessOrEqual(t, MinimumPQCAuthBytes(count), AbsoluteMaxPQCAuthBytes)
	}
	require.Zero(t, MinimumPQCAuthBytes(math.MaxUint32))
}

func TestPQCBlockGasCapacity(t *testing.T) {
	p := DefaultParams()
	p.SignatureVerificationGas, p.ProofVerificationGas = AbsoluteMaxVerificationGas, AbsoluteMaxVerificationGas
	p.MaxPqcVerificationsPerTx = AbsoluteMaxPQCVerificationsPerTx
	require.NoError(t, p.Validate())
	require.Error(t, p.ValidateBlockGasCapacity(600_000_000))
	require.Error(t, p.ValidateBlockGasCapacity(640_000_000))
	require.NoError(t, p.ValidateBlockGasCapacity(640_000_001))
	require.NoError(t, p.ValidateBlockGasCapacity(-1))
	require.Error(t, p.ValidateBlockGasCapacity(0))
	p.SignatureVerificationGas = math.MaxUint64
	require.Error(t, p.ValidateBlockGasCapacity(math.MaxInt64), "must not wrap")
}
