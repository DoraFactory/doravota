package types

import (
	"fmt"
	"math/bits"
)

// VerificationGasEstimate is the deterministic cryptographic portion of a
// pqcauth gas estimate. Transaction bytes, SDK message execution, and store
// reads/writes remain accounted for by the normal SDK simulation path.
type VerificationGasEstimate struct {
	SignatureVerifications uint64 `json:"signature_verifications"`
	ProofVerifications     uint64 `json:"proof_verifications"`
	SignatureGas           uint64 `json:"signature_gas"`
	ProofGas               uint64 `json:"proof_gas"`
	Total                  uint64 `json:"total"`
}

// EstimateVerificationGas calculates the exact fixed gas charged by pqcauth
// for a known number of transaction signatures and lifecycle proofs. It
// rejects arithmetic overflow instead of allowing a client estimate to wrap.
func EstimateVerificationGas(
	params Params,
	signatureVerifications uint64,
	proofVerifications uint64,
) (VerificationGasEstimate, error) {
	signatureHigh, signatureGas := bits.Mul64(
		signatureVerifications,
		params.EffectiveSignatureVerificationGas(),
	)
	if signatureHigh != 0 {
		return VerificationGasEstimate{}, fmt.Errorf(
			"%w: signature verification gas estimate overflows uint64",
			ErrInvalidParams,
		)
	}

	proofHigh, proofGas := bits.Mul64(
		proofVerifications,
		params.EffectiveProofVerificationGas(),
	)
	if proofHigh != 0 {
		return VerificationGasEstimate{}, fmt.Errorf(
			"%w: proof verification gas estimate overflows uint64",
			ErrInvalidParams,
		)
	}
	total, carry := bits.Add64(signatureGas, proofGas, 0)
	if carry != 0 {
		return VerificationGasEstimate{}, fmt.Errorf(
			"%w: total verification gas estimate overflows uint64",
			ErrInvalidParams,
		)
	}

	return VerificationGasEstimate{
		SignatureVerifications: signatureVerifications,
		ProofVerifications:     proofVerifications,
		SignatureGas:           signatureGas,
		ProofGas:               proofGas,
		Total:                  total,
	}, nil
}
