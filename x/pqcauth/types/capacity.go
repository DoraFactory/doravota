package types

import "fmt"

// ValidateVerificationGasCapacity is a governance-only price sanity check,
// not a transaction or block verification quota. Two proofs plus a protected
// payer's authorization must leave room for the rest of a lifecycle tx.
// It never runs in BeginBlock or on unchanged emergency/cancellation requests.
func (p Params) ValidateVerificationGasCapacity(maxBlockGas int64) error {
	if err := p.ValidateGovernanceUpdate(); err != nil {
		return err
	}
	if maxBlockGas < 0 {
		return nil
	}
	const lifecycleVerifications uint64 = 3
	if maxBlockGas == 0 || p.EffectiveVerificationGas() > (uint64(maxBlockGas)-1)/lifecycleVerifications {
		return fmt.Errorf("%w: verification price leaves no room for lifecycle work in current block max_gas", ErrInvalidParams)
	}
	return nil
}
