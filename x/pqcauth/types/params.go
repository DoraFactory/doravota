package types

import (
	"bytes"
	"crypto/sha256"
	"fmt"

	pqccrypto "github.com/DoraFactory/doravota/x/pqcauth/crypto"
)

const (
	DefaultSignatureVerificationGas     uint64 = 250_000
	DefaultProofVerificationGas         uint64 = 250_000
	DefaultMaxPQCSigners                uint32 = 8
	DefaultMaxPQCAuthBytes              uint32 = 64 * 1024
	DefaultMaxRetainedKeyRecordsPerRole uint32 = 16
	DefaultGovernanceSafetyDelayBlocks  uint64 = 17_280
	DefaultMaxEmergencyDurationBlocks   uint64 = 17_280

	AbsoluteMaxPQCSigners                  uint32 = 32
	AbsoluteMaxPQCAuthBytes                uint32 = 256 * 1024
	AbsoluteMaxRetainedKeyRecordsPerRole   uint32 = 64
	AbsoluteMaxVerificationGas             uint64 = 10_000_000
	AbsoluteMaxGovernanceSafetyDelayBlocks uint64 = 2_000_000
	AbsoluteMaxEmergencyDurationBlocks     uint64 = 172_800
	MinimumGovernanceSafetyDelayBlocks     uint64 = 2
	MinimumEmergencyDurationBlocks         uint64 = 2

	// Consensus gas floors prevent governance from making ML-DSA verification
	// effectively free. They must only be lowered through a coordinated binary
	// upgrade backed by target-hardware benchmarks.
	MinimumSignatureVerificationGas uint64 = 250_000
	MinimumProofVerificationGas     uint64 = 250_000
)

var defaultNetworkID = sha256.Sum256([]byte("doravota/pqcauth/network/v1"))

// NetworkIDForChain deterministically separates fresh development and custom
// chains. Production upgrades should replace this value with a launch-specific
// constant so a same-chain-ID fork can deliberately choose a new identity.
func NetworkIDForChain(chainID string) []byte {
	sum := sha256.Sum256([]byte("doravota/pqcauth/network/v1/chain/" + chainID))
	return append([]byte(nil), sum[:]...)
}

func UsesLegacyDefaultNetworkID(networkID []byte) bool {
	return bytes.Equal(networkID, defaultNetworkID[:])
}

func DefaultParams() Params {
	return Params{
		EnforcementMode:              EnforcementMode_ENFORCEMENT_MODE_OPTIONAL,
		NetworkId:                    append([]byte(nil), defaultNetworkID[:]...),
		AllowedAlgorithms:            []Algorithm{Algorithm_ALGORITHM_ML_DSA_65},
		SignatureVerificationGas:     DefaultSignatureVerificationGas,
		ProofVerificationGas:         DefaultProofVerificationGas,
		MaxPqcSigners:                DefaultMaxPQCSigners,
		MaxPqcAuthBytes:              DefaultMaxPQCAuthBytes,
		MaxRetainedKeyRecordsPerRole: DefaultMaxRetainedKeyRecordsPerRole,
		RegistrationMode:             RegistrationMode_REGISTRATION_MODE_OPEN,
		EmergencyMode:                EmergencyMode_EMERGENCY_MODE_NORMAL,
		GovernanceSafetyDelayBlocks:  DefaultGovernanceSafetyDelayBlocks,
		MaxEmergencyDurationBlocks:   DefaultMaxEmergencyDurationBlocks,
	}
}

func (p Params) Validate() error {
	if len(p.NetworkId) < 16 || len(p.NetworkId) > 64 {
		return fmt.Errorf("%w: network_id length must be between 16 and 64 bytes", ErrInvalidParams)
	}
	if p.GovernanceSafetyDelayBlocks < MinimumGovernanceSafetyDelayBlocks ||
		p.GovernanceSafetyDelayBlocks > AbsoluteMaxGovernanceSafetyDelayBlocks {
		return fmt.Errorf(
			"%w: governance safety delay must be in [%d,%d] blocks",
			ErrInvalidParams,
			MinimumGovernanceSafetyDelayBlocks,
			AbsoluteMaxGovernanceSafetyDelayBlocks,
		)
	}
	if p.MaxEmergencyDurationBlocks < MinimumEmergencyDurationBlocks ||
		p.MaxEmergencyDurationBlocks > AbsoluteMaxEmergencyDurationBlocks {
		return fmt.Errorf(
			"%w: maximum emergency duration must be in [%d,%d] blocks",
			ErrInvalidParams,
			MinimumEmergencyDurationBlocks,
			AbsoluteMaxEmergencyDurationBlocks,
		)
	}
	if err := validateScheduledParams(p.AsScheduled()); err != nil {
		return err
	}
	if p.PendingActivationHeight == 0 {
		if p.Pending != nil {
			return fmt.Errorf("%w: pending params require an activation height", ErrInvalidParams)
		}
	} else {
		if p.Pending == nil {
			return fmt.Errorf("%w: pending activation height requires params", ErrInvalidParams)
		}
		if err := validateScheduledParams(*p.Pending); err != nil {
			return fmt.Errorf("invalid pending params: %w", err)
		}
		if p.Pending.EmergencyMode != EmergencyMode_EMERGENCY_MODE_NORMAL &&
			p.Pending.EmergencyExpiresHeight <= p.PendingActivationHeight {
			return fmt.Errorf(
				"%w: pending emergency must expire after its activation height",
				ErrInvalidParams,
			)
		}
	}
	return nil
}

// ValidateGovernanceUpdate validates the user-controlled part of a parameter
// proposal. Emergency expiration is deliberately absent from that authority:
// the message server computes it from the immutable maximum duration.
func (p Params) ValidateGovernanceUpdate() error {
	if p.Pending != nil || p.PendingActivationHeight != 0 {
		return fmt.Errorf("%w: governance message cannot supply a nested pending schedule", ErrInvalidParams)
	}
	if p.EmergencyExpiresHeight != 0 {
		return fmt.Errorf("%w: governance message cannot set emergency expiration", ErrInvalidParams)
	}
	if p.EmergencyMode != EmergencyMode_EMERGENCY_MODE_NORMAL {
		p.EmergencyExpiresHeight = 1
	}
	return p.Validate()
}

func validateScheduledParams(p ScheduledParams) error {
	if !validEnforcementMode(p.EnforcementMode) {
		return fmt.Errorf("%w: invalid enforcement mode %d", ErrInvalidParams, p.EnforcementMode)
	}
	if len(p.AllowedAlgorithms) == 0 {
		return fmt.Errorf("%w: at least one algorithm must be allowed", ErrInvalidParams)
	}
	seen := make(map[Algorithm]struct{}, len(p.AllowedAlgorithms))
	for _, algorithm := range p.AllowedAlgorithms {
		if !SupportedAlgorithm(algorithm) {
			return fmt.Errorf("%w: algorithm %d", ErrUnsupportedAlgorithm, algorithm)
		}
		if _, exists := seen[algorithm]; exists {
			return fmt.Errorf("%w: duplicate algorithm %d", ErrInvalidParams, algorithm)
		}
		seen[algorithm] = struct{}{}
	}
	if p.SignatureVerificationGas < MinimumSignatureVerificationGas ||
		p.SignatureVerificationGas > AbsoluteMaxVerificationGas {
		return fmt.Errorf(
			"%w: signature verification gas must be in [%d,%d]",
			ErrInvalidParams,
			MinimumSignatureVerificationGas,
			AbsoluteMaxVerificationGas,
		)
	}
	if p.ProofVerificationGas < MinimumProofVerificationGas ||
		p.ProofVerificationGas > AbsoluteMaxVerificationGas {
		return fmt.Errorf(
			"%w: proof verification gas must be in [%d,%d]",
			ErrInvalidParams,
			MinimumProofVerificationGas,
			AbsoluteMaxVerificationGas,
		)
	}
	if p.MaxPqcSigners == 0 || p.MaxPqcSigners > AbsoluteMaxPQCSigners {
		return fmt.Errorf("%w: max PQC signers must be in [1,%d]", ErrInvalidParams, AbsoluteMaxPQCSigners)
	}
	if p.MaxPqcAuthBytes == 0 || p.MaxPqcAuthBytes > AbsoluteMaxPQCAuthBytes {
		return fmt.Errorf("%w: max PQC auth bytes must be in [1,%d]", ErrInvalidParams, AbsoluteMaxPQCAuthBytes)
	}
	if p.MaxRetainedKeyRecordsPerRole == 0 ||
		p.MaxRetainedKeyRecordsPerRole > AbsoluteMaxRetainedKeyRecordsPerRole {
		return fmt.Errorf(
			"%w: max retained key records per role must be in [1,%d]",
			ErrInvalidParams,
			AbsoluteMaxRetainedKeyRecordsPerRole,
		)
	}
	if !validRegistrationMode(normalizeRegistrationMode(p.RegistrationMode)) {
		return fmt.Errorf("%w: invalid registration mode %d", ErrInvalidParams, p.RegistrationMode)
	}
	if p.EmergencyMode != EmergencyMode_EMERGENCY_MODE_NORMAL &&
		p.EmergencyMode != EmergencyMode_EMERGENCY_MODE_PAUSE_NEW_KEYS &&
		p.EmergencyMode != EmergencyMode_EMERGENCY_MODE_PAUSE_PQC_TRANSACTIONS {
		return fmt.Errorf("%w: invalid emergency mode %d", ErrInvalidParams, p.EmergencyMode)
	}
	if p.EmergencyMode == EmergencyMode_EMERGENCY_MODE_NORMAL && p.EmergencyExpiresHeight != 0 {
		return fmt.Errorf("%w: normal emergency mode must not have an expiration height", ErrInvalidParams)
	}
	if p.EmergencyMode != EmergencyMode_EMERGENCY_MODE_NORMAL && p.EmergencyExpiresHeight == 0 {
		return fmt.Errorf("%w: emergency pause requires an expiration height", ErrInvalidParams)
	}
	return nil
}

func SupportedAlgorithm(algorithm Algorithm) bool {
	return algorithm == Algorithm_ALGORITHM_ML_DSA_65
}

func (p Params) IsAlgorithmAllowed(algorithm Algorithm) bool {
	for _, allowed := range p.AllowedAlgorithms {
		if allowed == algorithm {
			return true
		}
	}
	return false
}

func (p Params) EffectiveEnforcementMode(height int64) EnforcementMode {
	return p.Effective(height).EnforcementMode
}

func (p Params) EffectiveEmergencyMode(height int64) EmergencyMode {
	return p.Effective(height).EmergencyMode
}

// EffectiveRegistrationMode returns the active registration gate. A legacy
// registration cutoff remains authoritative and maps to CLOSED once reached.
func (p Params) EffectiveRegistrationMode(height int64) RegistrationMode {
	effective := p.Effective(height)
	if height >= 0 &&
		effective.RegistrationCutoffHeight != 0 &&
		uint64(height) >= effective.RegistrationCutoffHeight {
		return RegistrationMode_REGISTRATION_MODE_CLOSED
	}
	return normalizeRegistrationMode(effective.RegistrationMode)
}

// Effective atomically applies the complete pending parameter bundle at its
// activation height. The returned copy never contains an activated schedule.
func (p Params) Effective(height int64) Params {
	if height < 0 {
		return p
	}
	if p.Pending != nil &&
		p.PendingActivationHeight != 0 &&
		uint64(height) >= p.PendingActivationHeight {
		p.ApplyScheduled(*p.Pending)
		p.Pending = nil
		p.PendingActivationHeight = 0
	}
	if p.EmergencyMode != EmergencyMode_EMERGENCY_MODE_NORMAL &&
		p.EmergencyExpiresHeight != 0 &&
		uint64(height) >= p.EmergencyExpiresHeight {
		p.EmergencyMode = EmergencyMode_EMERGENCY_MODE_NORMAL
		p.EmergencyExpiresHeight = 0
	}
	p.RegistrationMode = normalizeRegistrationMode(p.RegistrationMode)
	return p
}

func (p Params) AsScheduled() ScheduledParams {
	return ScheduledParams{
		EnforcementMode:              p.EnforcementMode,
		AllowedAlgorithms:            append([]Algorithm(nil), p.AllowedAlgorithms...),
		SignatureVerificationGas:     p.SignatureVerificationGas,
		ProofVerificationGas:         p.ProofVerificationGas,
		MaxPqcSigners:                p.MaxPqcSigners,
		MaxPqcAuthBytes:              p.MaxPqcAuthBytes,
		MaxRetainedKeyRecordsPerRole: p.MaxRetainedKeyRecordsPerRole,
		RegistrationCutoffHeight:     p.RegistrationCutoffHeight,
		RegistrationMode:             normalizeRegistrationMode(p.RegistrationMode),
		EmergencyMode:                p.EmergencyMode,
		EmergencyExpiresHeight:       p.EmergencyExpiresHeight,
	}
}

func (p *Params) ApplyScheduled(scheduled ScheduledParams) {
	p.EnforcementMode = scheduled.EnforcementMode
	p.AllowedAlgorithms = append([]Algorithm(nil), scheduled.AllowedAlgorithms...)
	p.SignatureVerificationGas = scheduled.SignatureVerificationGas
	p.ProofVerificationGas = scheduled.ProofVerificationGas
	p.MaxPqcSigners = scheduled.MaxPqcSigners
	p.MaxPqcAuthBytes = scheduled.MaxPqcAuthBytes
	p.MaxRetainedKeyRecordsPerRole = scheduled.MaxRetainedKeyRecordsPerRole
	p.RegistrationCutoffHeight = scheduled.RegistrationCutoffHeight
	p.RegistrationMode = normalizeRegistrationMode(scheduled.RegistrationMode)
	p.EmergencyMode = scheduled.EmergencyMode
	p.EmergencyExpiresHeight = scheduled.EmergencyExpiresHeight
}

func (p Params) EffectiveMaxPQCSigners() uint32 {
	if p.MaxPqcSigners == 0 || p.MaxPqcSigners > AbsoluteMaxPQCSigners {
		return DefaultMaxPQCSigners
	}
	return p.MaxPqcSigners
}

func (p Params) EffectiveMaxPQCAuthBytes() uint32 {
	if p.MaxPqcAuthBytes == 0 || p.MaxPqcAuthBytes > AbsoluteMaxPQCAuthBytes {
		return DefaultMaxPQCAuthBytes
	}
	return p.MaxPqcAuthBytes
}

func (p Params) EffectiveMaxRetainedKeyRecordsPerRole() uint32 {
	if p.MaxRetainedKeyRecordsPerRole == 0 ||
		p.MaxRetainedKeyRecordsPerRole > AbsoluteMaxRetainedKeyRecordsPerRole {
		return DefaultMaxRetainedKeyRecordsPerRole
	}
	return p.MaxRetainedKeyRecordsPerRole
}

func (p Params) EffectiveSignatureVerificationGas() uint64 {
	if p.SignatureVerificationGas < MinimumSignatureVerificationGas ||
		p.SignatureVerificationGas > AbsoluteMaxVerificationGas {
		return DefaultSignatureVerificationGas
	}
	return p.SignatureVerificationGas
}

func (p Params) EffectiveProofVerificationGas() uint64 {
	if p.ProofVerificationGas < MinimumProofVerificationGas ||
		p.ProofVerificationGas > AbsoluteMaxVerificationGas {
		return DefaultProofVerificationGas
	}
	return p.ProofVerificationGas
}

func validEnforcementMode(mode EnforcementMode) bool {
	return mode >= EnforcementMode_ENFORCEMENT_MODE_DISABLED &&
		mode <= EnforcementMode_ENFORCEMENT_MODE_REQUIRED
}

func normalizeRegistrationMode(mode RegistrationMode) RegistrationMode {
	// Zero was the wire value written before registration modes existed. Treat
	// it as OPEN so upgrades preserve the historical registration behavior.
	if mode == RegistrationMode_REGISTRATION_MODE_UNSPECIFIED {
		return RegistrationMode_REGISTRATION_MODE_OPEN
	}
	return mode
}

func validRegistrationMode(mode RegistrationMode) bool {
	return mode >= RegistrationMode_REGISTRATION_MODE_OPEN &&
		mode <= RegistrationMode_REGISTRATION_MODE_CLOSED
}

func CryptoAlgorithm(algorithm Algorithm) (pqccrypto.Algorithm, error) {
	switch algorithm {
	case Algorithm_ALGORITHM_ML_DSA_65:
		return pqccrypto.AlgorithmMLDSA65, nil
	default:
		return pqccrypto.AlgorithmUnspecified, fmt.Errorf("%w: %d", ErrUnsupportedAlgorithm, algorithm)
	}
}

func EqualNetworkID(a, b []byte) bool {
	return bytes.Equal(a, b)
}
