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
	maxKeyID := make(map[string]uint64)
	keyCount := make(map[string]uint32)
	for _, key := range genesis.Keys {
		owner, err := canonicalAddress(key.Owner)
		if err != nil {
			return fmt.Errorf("invalid key owner: %w", err)
		}
		if key.KeyId == 0 || key.KeyId == math.MaxUint64 ||
			key.KeyId > uint64(genesis.Params.EffectiveMaxKeysPerAccount()) ||
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
		keyCount[owner.String()]++
		if keyCount[owner.String()] > genesis.Params.EffectiveMaxKeysPerAccount() {
			return fmt.Errorf(
				"%w: lifetime key-record quota exceeded for %s",
				ErrKeyLimit,
				key.Owner,
			)
		}
		if key.KeyId > maxKeyID[owner.String()] {
			maxKeyID[owner.String()] = key.KeyId
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
			policy.PendingRecoveryKeyId != 0
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
			sequence.NextKeyId <= maxKeyID[owner.String()] ||
			sequence.NextKeyId-1 > uint64(genesis.Params.EffectiveMaxKeysPerAccount()) {
			return fmt.Errorf("%w: invalid next key id for %s", ErrInvalidKey, sequence.Owner)
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
