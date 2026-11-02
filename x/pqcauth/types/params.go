package types

import (
	"bytes"
	"crypto/sha256"
	"fmt"

	pqccrypto "github.com/DoraFactory/doravota/x/pqcauth/crypto"
	authtypes "github.com/cosmos/cosmos-sdk/x/auth/types"
)

const (
	DefaultVerificationGas     uint64 = authtypes.DefaultSigVerifyCostMlDsa65
	MinimumVerificationGas     uint64 = authtypes.DefaultSigVerifyCostMlDsa65
	AbsoluteMaxVerificationGas uint64 = 10_000_000
	// Fixed operational caps; the raw-wire preflight retains independent ceilings.
	MaxPQCSigners                          uint32 = 8
	MaxPQCAuthBytes                        uint32 = 64 * 1024
	MaxRetainedKeyRecordsPerRole           uint32 = 16
	AbsoluteMaxPQCSigners                  uint32 = 32
	AbsoluteMaxPQCAuthBytes                uint32 = 256 * 1024
	DefaultGovernanceSafetyDelayBlocks     uint64 = 17_280
	DefaultMaxEmergencyDurationBlocks      uint64 = 46_080
	DefaultRecoveryDelayBlocks             uint64 = 107_520
	AbsoluteMaxGovernanceSafetyDelayBlocks uint64 = 2_000_000
	AbsoluteMaxEmergencyDurationBlocks     uint64 = 172_800
	AbsoluteMaxRecoveryDelayBlocks         uint64 = 2_000_000
	MinimumGovernanceSafetyDelayBlocks     uint64 = 2
	MinimumEmergencyDurationBlocks         uint64 = 2
	MinimumRecoveryDelayBlocks             uint64 = 2
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
		EnforcementMode:             EnforcementMode_ENFORCEMENT_MODE_OPTIONAL,
		VerificationGas:             DefaultVerificationGas,
		NetworkId:                   append([]byte(nil), defaultNetworkID[:]...),
		EmergencyMode:               EmergencyMode_EMERGENCY_MODE_NORMAL,
		GovernanceSafetyDelayBlocks: DefaultGovernanceSafetyDelayBlocks,
		MaxEmergencyDurationBlocks:  DefaultMaxEmergencyDurationBlocks,
		RecoveryDelayBlocks:         DefaultRecoveryDelayBlocks,
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
	recoveryDelay := p.EffectiveRecoveryDelayBlocks()
	if recoveryDelay < MinimumRecoveryDelayBlocks ||
		recoveryDelay > AbsoluteMaxRecoveryDelayBlocks {
		return fmt.Errorf(
			"%w: recovery delay must be in [%d,%d] blocks",
			ErrInvalidParams,
			MinimumRecoveryDelayBlocks,
			AbsoluteMaxRecoveryDelayBlocks,
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
	if e := p.PendingEmergency; e != nil {
		if p.Pending == nil || e.ActivationHeight == 0 || e.ActivationHeight > p.PendingActivationHeight {
			return fmt.Errorf("%w: independent emergency requires a pending bundle at or after its activation", ErrInvalidParams)
		}
		if e.Mode != EmergencyMode_EMERGENCY_MODE_NORMAL && e.Mode != EmergencyMode_EMERGENCY_MODE_PAUSE_NEW_KEYS && e.Mode != EmergencyMode_EMERGENCY_MODE_PAUSE_PQC_TRANSACTIONS {
			return fmt.Errorf("%w: invalid independent emergency mode", ErrInvalidParams)
		}
		if e.Mode == EmergencyMode_EMERGENCY_MODE_NORMAL {
			if e.ExpiresHeight != 0 {
				return fmt.Errorf("%w: normal independent emergency cannot expire", ErrInvalidParams)
			}
		} else if e.ExpiresHeight <= e.ActivationHeight || e.ExpiresHeight-e.ActivationHeight > p.MaxEmergencyDurationBlocks {
			return fmt.Errorf("%w: invalid independent emergency duration", ErrInvalidParams)
		}
		mode, expiry := e.Mode, e.ExpiresHeight
		if expiry != 0 && expiry <= p.PendingActivationHeight {
			mode, expiry = EmergencyMode_EMERGENCY_MODE_NORMAL, 0
		}
		if p.Pending.EmergencyMode != mode || p.Pending.EmergencyExpiresHeight != expiry {
			return fmt.Errorf("%w: pending bundle must preserve independent emergency expiry", ErrInvalidParams)
		}
	}
	return nil
}

// ValidateGovernanceUpdate validates the user-controlled part of a parameter
// proposal. Emergency expiration is deliberately absent from that authority:
// the message server computes it from the immutable maximum duration.
func (p Params) ValidateGovernanceUpdate() error {
	if p.Pending != nil || p.PendingActivationHeight != 0 || p.PendingEmergency != nil {
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
	if p.VerificationGas < MinimumVerificationGas || p.VerificationGas > AbsoluteMaxVerificationGas {
		return fmt.Errorf("%w: verification gas must be in [%d,%d]", ErrInvalidParams, MinimumVerificationGas, AbsoluteMaxVerificationGas)
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
	return SupportedAlgorithm(algorithm)
}

func (p Params) EffectiveEnforcementMode(height int64) EnforcementMode {
	return p.Effective(height).EnforcementMode
}

func (p Params) EffectiveEmergencyMode(height int64) EmergencyMode {
	return p.Effective(height).EmergencyMode
}

// Effective applies the pending parameter bundle and its independent emergency
// override at their own heights. The returned copy contains no activated schedule.
func (p Params) Effective(height int64) Params {
	p.RecoveryDelayBlocks = p.EffectiveRecoveryDelayBlocks()
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
	if e := p.PendingEmergency; e != nil && uint64(height) >= e.ActivationHeight {
		p.EmergencyMode, p.EmergencyExpiresHeight = e.Mode, e.ExpiresHeight
		p.PendingEmergency = nil
	}
	if p.EmergencyMode != EmergencyMode_EMERGENCY_MODE_NORMAL &&
		p.EmergencyExpiresHeight != 0 &&
		uint64(height) >= p.EmergencyExpiresHeight {
		p.EmergencyMode = EmergencyMode_EMERGENCY_MODE_NORMAL
		p.EmergencyExpiresHeight = 0
	}
	return p
}

func (p Params) AsScheduled() ScheduledParams {
	return ScheduledParams{
		EnforcementMode:        p.EnforcementMode,
		VerificationGas:        p.VerificationGas,
		EmergencyMode:          p.EmergencyMode,
		EmergencyExpiresHeight: p.EmergencyExpiresHeight,
	}
}

func (p *Params) ApplyScheduled(scheduled ScheduledParams) {
	p.EnforcementMode = scheduled.EnforcementMode
	p.VerificationGas = scheduled.VerificationGas
	p.EmergencyMode = scheduled.EmergencyMode
	p.EmergencyExpiresHeight = scheduled.EmergencyExpiresHeight
}

func (p Params) EffectiveVerificationGas() uint64 {
	if p.VerificationGas < MinimumVerificationGas || p.VerificationGas > AbsoluteMaxVerificationGas {
		return DefaultVerificationGas
	}
	return p.VerificationGas
}

// EffectiveRecoveryDelayBlocks maps the zero value written by pre-v2 state to
// the v2 default. The delay is immutable after genesis and deliberately lives
// outside ScheduledParams so governance cannot shorten an active challenge
// period.
func (p Params) EffectiveRecoveryDelayBlocks() uint64 {
	if p.RecoveryDelayBlocks == 0 {
		return DefaultRecoveryDelayBlocks
	}
	return p.RecoveryDelayBlocks
}

func validEnforcementMode(mode EnforcementMode) bool {
	// Phase one is opt-in: global REQUIRED is reserved until composite
	// accounts, wallets and relayers have a reviewed migration path. Keep the
	// wire enum and fail-closed runtime handling; never map it to OPTIONAL.
	return mode == EnforcementMode_ENFORCEMENT_MODE_OPTIONAL || mode == EnforcementMode_ENFORCEMENT_MODE_REQUIRED_FOR_REGISTERED
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
