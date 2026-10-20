package types

import (
	"fmt"
	"math"

	sdk "github.com/cosmos/cosmos-sdk/types"

	pqccrypto "github.com/DoraFactory/doravota/x/pqcauth/crypto"
)

func DefaultGenesisState() *GenesisState {
	return &GenesisState{Params: DefaultParams()}
}

func ValidateGenesis(genesis GenesisState) error {
	if err := genesis.Params.Validate(); err != nil {
		return err
	}

	keys := make(map[string]PQCKeyRecord, len(genesis.Keys))
	maxKnownKeyID := make(map[string]uint64)
	for _, key := range genesis.Keys {
		owner, err := canonicalAddress(key.Owner)
		if err != nil {
			return fmt.Errorf("invalid key owner: %w", err)
		}
		if key.KeyId == 0 || key.KeyId == math.MaxUint64 ||
			!genesis.Params.IsAlgorithmAllowed(key.Algorithm) {
			return fmt.Errorf("%w: invalid genesis key id or algorithm", ErrInvalidKey)
		}
		algorithm, err := CryptoAlgorithm(key.Algorithm)
		if err != nil {
			return err
		}
		publicKeySize, _, err := pqccrypto.Sizes(algorithm)
		if err != nil || len(key.PublicKey) != publicKeySize {
			return fmt.Errorf("%w: invalid public key size for %s/%d", ErrInvalidKey, key.Owner, key.KeyId)
		}
		if key.Role != KeyRole_KEY_ROLE_SIGNING && key.Role != KeyRole_KEY_ROLE_RECOVERY {
			return fmt.Errorf("%w: invalid role for %s/%d", ErrInvalidKey, key.Owner, key.KeyId)
		}
		if key.Status != KeyStatus_KEY_STATUS_LIVE && key.Status != KeyStatus_KEY_STATUS_REVOKED {
			return fmt.Errorf("%w: invalid status for %s/%d", ErrInvalidKey, key.Owner, key.KeyId)
		}
		if key.InactiveFromHeight != 0 && key.InactiveFromHeight <= key.EffectiveHeight {
			return fmt.Errorf("%w: invalid height window for %s/%d", ErrInvalidKey, key.Owner, key.KeyId)
		}
		mapKey := owner.String() + fmt.Sprintf("/%d", key.KeyId)
		if _, duplicate := keys[mapKey]; duplicate {
			return fmt.Errorf("%w: duplicate key %s", ErrInvalidKey, mapKey)
		}
		keys[mapKey] = key
		if key.KeyId > maxKnownKeyID[owner.String()] {
			maxKnownKeyID[owner.String()] = key.KeyId
		}
	}

	histories := make(map[string]AccountKeyHistory, len(genesis.KeyHistories))
	for _, history := range genesis.KeyHistories {
		owner, err := canonicalAddress(history.Owner)
		if err != nil {
			return fmt.Errorf("invalid key history owner: %w", err)
		}
		if history.Role != KeyRole_KEY_ROLE_SIGNING && history.Role != KeyRole_KEY_ROLE_RECOVERY {
			return fmt.Errorf("%w: invalid key history role for %s", ErrInvalidKey, history.Owner)
		}
		if history.CompactedCount == 0 ||
			history.CompactedCount > history.LastCompactedKeyId ||
			history.LastCompactedKeyId == 0 ||
			history.LastCompactedKeyId == math.MaxUint64 ||
			len(history.Accumulator) != KeyHistoryAccumulatorSize {
			return fmt.Errorf("%w: invalid key history for %s/%s", ErrInvalidKey, history.Owner, history.Role)
		}
		mapKey := fmt.Sprintf("%s/%d", owner.String(), history.Role)
		if _, duplicate := histories[mapKey]; duplicate {
			return fmt.Errorf("%w: duplicate key history %s", ErrInvalidKey, mapKey)
		}
		histories[mapKey] = history
		if history.LastCompactedKeyId > maxKnownKeyID[owner.String()] {
			maxKnownKeyID[owner.String()] = history.LastCompactedKeyId
		}
	}
	for _, key := range genesis.Keys {
		mapKey := fmt.Sprintf("%s/%d", key.Owner, key.Role)
		history, found := histories[mapKey]
		if found && key.KeyId <= history.LastCompactedKeyId {
			return fmt.Errorf(
				"%w: full key %s/%d is not newer than compacted %s history %d",
				ErrInconsistentState,
				key.Owner,
				key.KeyId,
				key.Role,
				history.LastCompactedKeyId,
			)
		}
	}

	policies := make(map[string]struct{}, len(genesis.Policies))
	for _, policy := range genesis.Policies {
		owner, err := canonicalAddress(policy.Owner)
		if err != nil {
			return fmt.Errorf("invalid policy owner: %w", err)
		}
		if _, duplicate := policies[owner.String()]; duplicate {
			return fmt.Errorf("%w: duplicate policy for %s", ErrInvalidKey, policy.Owner)
		}
		policies[owner.String()] = struct{}{}
		if policy.CurrentSigningKeyId == 0 && policy.PendingSigningKeyId == 0 {
			return fmt.Errorf("%w: policy has no signing key", ErrInvalidKey)
		}
		if policy.RecoveryKeyId == 0 && policy.PendingRecoveryKeyId == 0 {
			return fmt.Errorf("%w: policy has no recovery key", ErrInvalidKey)
		}
		if policy.CurrentSigningKeyId != 0 {
			key, exists := keys[owner.String()+fmt.Sprintf("/%d", policy.CurrentSigningKeyId)]
			if !exists || key.Role != KeyRole_KEY_ROLE_SIGNING ||
				key.Status != KeyStatus_KEY_STATUS_LIVE {
				return fmt.Errorf("%w: current signing key missing for %s", ErrInvalidKey, policy.Owner)
			}
			if policy.PolicyVersion == 0 {
				return fmt.Errorf("%w: current policy version is zero", ErrInvalidPolicyVersion)
			}
		}
		hasPending := policy.PendingSigningKeyId != 0 ||
			policy.PendingEffectiveHeight != 0 ||
			policy.PendingPolicyVersion != 0 ||
			policy.PendingRecoveryKeyId != 0 ||
			policy.PendingChangeKind != PolicyChangeKind_POLICY_CHANGE_KIND_UNSPECIFIED ||
			policy.PendingCreatedHeight != 0
		if hasPending {
			key, exists := keys[owner.String()+fmt.Sprintf("/%d", policy.PendingSigningKeyId)]
			if !exists || key.Role != KeyRole_KEY_ROLE_SIGNING ||
				key.Status != KeyStatus_KEY_STATUS_LIVE ||
				policy.PendingEffectiveHeight == 0 ||
				policy.PendingPolicyVersion == 0 ||
				policy.PendingPolicyVersion != policy.PolicyVersion+1 ||
				policy.PolicyVersion == math.MaxUint64 {
				return fmt.Errorf("%w: incomplete pending policy for %s", ErrInvalidKey, policy.Owner)
			}
			if policy.PendingSigningKeyId != policy.CurrentSigningKeyId {
				if key.EffectiveHeight != policy.PendingEffectiveHeight {
					return fmt.Errorf(
						"%w: pending signing key activation does not match policy for %s",
						ErrInvalidKey,
						policy.Owner,
					)
				}
			}
			if policy.CurrentSigningKeyId != 0 &&
				policy.PendingSigningKeyId != policy.CurrentSigningKeyId {
				current := keys[owner.String()+fmt.Sprintf("/%d", policy.CurrentSigningKeyId)]
				if current.InactiveFromHeight != policy.PendingEffectiveHeight {
					return fmt.Errorf(
						"%w: current signing key retirement does not match pending policy for %s",
						ErrInvalidKey,
						policy.Owner,
					)
				}
			}
			if err := validatePendingPolicyChangeKind(policy, genesis.Params); err != nil {
				return fmt.Errorf("%w for %s", err, policy.Owner)
			}
		} else if policy.PendingChangeKind != PolicyChangeKind_POLICY_CHANGE_KIND_UNSPECIFIED ||
			policy.PendingCreatedHeight != 0 {
			return fmt.Errorf("%w: pending metadata without a pending policy for %s", ErrInvalidKey, policy.Owner)
		}
		if policy.PendingRecoveryKeyId != 0 {
			key, exists := keys[owner.String()+fmt.Sprintf("/%d", policy.PendingRecoveryKeyId)]
			if !exists || key.Role != KeyRole_KEY_ROLE_RECOVERY ||
				key.Status != KeyStatus_KEY_STATUS_LIVE ||
				key.EffectiveHeight != policy.PendingEffectiveHeight {
				return fmt.Errorf("%w: pending recovery key missing for %s", ErrInvalidKey, policy.Owner)
			}
			if policy.RecoveryKeyId != 0 &&
				policy.PendingRecoveryKeyId != policy.RecoveryKeyId {
				current := keys[owner.String()+fmt.Sprintf("/%d", policy.RecoveryKeyId)]
				if current.InactiveFromHeight != policy.PendingEffectiveHeight {
					return fmt.Errorf(
						"%w: current recovery key retirement does not match pending policy for %s",
						ErrInvalidKey,
						policy.Owner,
					)
				}
			}
		}
		if policy.RecoveryKeyId != 0 {
			key, exists := keys[owner.String()+fmt.Sprintf("/%d", policy.RecoveryKeyId)]
			if !exists || key.Role != KeyRole_KEY_ROLE_RECOVERY ||
				key.Status != KeyStatus_KEY_STATUS_LIVE {
				return fmt.Errorf("%w: recovery key missing for %s", ErrInvalidKey, policy.Owner)
			}
		}
		if err := validateDistinctPolicyRoleKeys(owner.String(), policy, keys); err != nil {
			return err
		}
	}

	sequences := make(map[string]struct{}, len(genesis.KeySequences))
	for _, sequence := range genesis.KeySequences {
		owner, err := canonicalAddress(sequence.Owner)
		if err != nil {
			return fmt.Errorf("invalid key sequence owner: %w", err)
		}
		if _, duplicate := sequences[owner.String()]; duplicate {
			return fmt.Errorf("%w: duplicate key sequence for %s", ErrInvalidKey, sequence.Owner)
		}
		sequences[owner.String()] = struct{}{}
		if sequence.NextKeyId == 0 ||
			sequence.NextKeyId <= maxKnownKeyID[owner.String()] {
			return fmt.Errorf("%w: invalid next key id for %s", ErrInvalidKey, sequence.Owner)
		}
	}
	return nil
}

func validatePendingPolicyChangeKind(policy AccountPolicy, params Params) error {
	// Pending schedules written before Recovery v2 did not identify their
	// operation. Preserve import compatibility while requiring every v2
	// schedule to carry a creation height and a precise kind.
	if policy.PendingChangeKind == PolicyChangeKind_POLICY_CHANGE_KIND_UNSPECIFIED {
		if policy.PendingCreatedHeight != 0 {
			return fmt.Errorf("%w: legacy pending change has a creation height", ErrInvalidKey)
		}
		return nil
	}
	if policy.PendingCreatedHeight == 0 ||
		policy.PendingCreatedHeight >= policy.PendingEffectiveHeight {
		return fmt.Errorf("%w: invalid pending change height window", ErrInvalidKey)
	}

	switch policy.PendingChangeKind {
	case PolicyChangeKind_POLICY_CHANGE_KIND_REGISTRATION:
		if policy.CurrentSigningKeyId != 0 || policy.RecoveryKeyId != 0 ||
			policy.PendingSigningKeyId == 0 || policy.PendingRecoveryKeyId == 0 {
			return fmt.Errorf("%w: invalid pending registration", ErrInvalidKey)
		}
	case PolicyChangeKind_POLICY_CHANGE_KIND_ROTATE_SIGNING:
		if policy.CurrentSigningKeyId == 0 ||
			policy.PendingSigningKeyId == policy.CurrentSigningKeyId ||
			policy.PendingRecoveryKeyId != 0 {
			return fmt.Errorf("%w: invalid pending signing-key rotation", ErrInvalidKey)
		}
	case PolicyChangeKind_POLICY_CHANGE_KIND_ROTATE_RECOVERY:
		if policy.CurrentSigningKeyId == 0 ||
			policy.PendingSigningKeyId != policy.CurrentSigningKeyId ||
			policy.RecoveryKeyId == 0 ||
			policy.PendingRecoveryKeyId == 0 ||
			policy.PendingRecoveryKeyId == policy.RecoveryKeyId {
			return fmt.Errorf("%w: invalid pending recovery-key rotation", ErrInvalidKey)
		}
	case PolicyChangeKind_POLICY_CHANGE_KIND_SET_PROTECTION:
		if policy.CurrentSigningKeyId == 0 ||
			policy.PendingSigningKeyId != policy.CurrentSigningKeyId ||
			policy.PendingRecoveryKeyId != 0 {
			return fmt.Errorf("%w: invalid pending protection change", ErrInvalidKey)
		}
	case PolicyChangeKind_POLICY_CHANGE_KIND_RECOVER_SIGNING:
		delay := params.EffectiveRecoveryDelayBlocks()
		if policy.CurrentSigningKeyId == 0 ||
			policy.PendingSigningKeyId == policy.CurrentSigningKeyId ||
			policy.PendingRecoveryKeyId != 0 ||
			policy.PendingCreatedHeight > math.MaxUint64-delay ||
			policy.PendingCreatedHeight+delay != policy.PendingEffectiveHeight {
			return fmt.Errorf("%w: invalid pending signing-key recovery", ErrInvalidKey)
		}
	default:
		return fmt.Errorf("%w: unknown pending change kind %d", ErrInvalidKey, policy.PendingChangeKind)
	}
	return nil
}

func validateDistinctPolicyRoleKeys(
	owner string,
	policy AccountPolicy,
	keys map[string]PQCKeyRecord,
) error {
	signingIDs := []uint64{policy.CurrentSigningKeyId, policy.PendingSigningKeyId}
	recoveryIDs := []uint64{policy.RecoveryKeyId, policy.PendingRecoveryKeyId}
	for _, signingID := range signingIDs {
		if signingID == 0 {
			continue
		}
		signing, found := keys[owner+fmt.Sprintf("/%d", signingID)]
		if !found {
			continue
		}
		for _, recoveryID := range recoveryIDs {
			if recoveryID == 0 {
				continue
			}
			recovery, found := keys[owner+fmt.Sprintf("/%d", recoveryID)]
			if !found {
				continue
			}
			if err := ValidateDistinctRoleKeys(
				signing.Algorithm,
				signing.PublicKey,
				recovery.Algorithm,
				recovery.PublicKey,
			); err != nil {
				return fmt.Errorf("%w for %s", err, owner)
			}
		}
	}
	return nil
}

func canonicalAddress(value string) (sdk.AccAddress, error) {
	address, err := sdk.AccAddressFromBech32(value)
	if err != nil || address.String() != value {
		return nil, fmt.Errorf("address must be canonical bech32")
	}
	return address, nil
}
