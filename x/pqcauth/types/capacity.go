package types

import (
	"fmt"
	"math"
	"strings"

	pqccrypto "github.com/DoraFactory/doravota/x/pqcauth/crypto"
)

// MaxPQCSignerAddressBytes is the SDK bech32 decoder's maximum input length.
// This deliberately also covers non-standard address lengths/HRPs; using only
// today's 20-byte account address would undercount future valid encodings.
const MaxPQCSignerAddressBytes = 1023

var maximumPQCEntryEnvelopeBytes = func() uint32 {
	_, size, err := pqccrypto.Sizes(pqccrypto.AlgorithmMLDSA65)
	if err != nil {
		panic(err) // compile-time supported algorithm, never transaction input
	}
	ext := ExtensionPQCAuth{FormatVersion: FormatVersionV1, Signatures: []SignerPQCSignature{{
		Signer: strings.Repeat("x", MaxPQCSignerAddressBytes), SignerIndex: math.MaxUint32,
		KeyId: math.MaxUint64, Algorithm: Algorithm_ALGORITHM_ML_DSA_65,
		PolicyVersion: math.MaxUint64, Signature: make([]byte, size),
	}}}
	return uint32(ext.Size() - (&ExtensionPQCAuth{FormatVersion: FormatVersionV1}).Size())
}()

// MinimumPQCAuthBytes includes the envelope and every entry's length prefix,
// maximum-width identifiers and full ML-DSA signature. Only bounded counts are
// accepted, so arithmetic and memory costs cannot grow with untrusted input.
func MinimumPQCAuthBytes(signers uint32) uint32 {
	if signers == 0 || signers > AbsoluteMaxPQCSigners {
		return 0
	}
	return uint32((&ExtensionPQCAuth{FormatVersion: FormatVersionV1}).Size()) + signers*maximumPQCEntryEnvelopeBytes
}

// ValidateBlockGasCapacity is a governance preflight against the CURRENT
// consensus block limit, not an execution-time invariant. Consensus/auth gas
// parameters can change independently later; rejecting BeginBlock in that case
// would turn a configuration mistake into a chain halt. This only checks the
// PQCAuth cryptographic envelope, not native signatures, bytes or message gas.
func (p Params) ValidateBlockGasCapacity(maxBlockGas int64) error {
	if err := p.ValidateGovernanceUpdate(); err != nil {
		return err
	}
	if maxBlockGas < 0 { // CometBFT's unlimited block gas sentinel
		return nil
	}
	cost := max(p.EffectiveSignatureVerificationGas(), p.EffectiveProofVerificationGas())
	count := uint64(p.EffectiveMaxPQCVerificationsPerTx())
	// Division avoids overflow even when callers inspect invalid parameters.
	// Require room beyond crypto for the remaining transaction work.
	if maxBlockGas == 0 || cost > (uint64(maxBlockGas)-1)/count {
		return fmt.Errorf("%w: PQC verification gas envelope leaves no room in current block max_gas; lower verification gas/budget or review consensus gas limits", ErrInvalidParams)
	}
	return nil
}
