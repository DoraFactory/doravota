package client

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"github.com/DoraFactory/doravota/x/pqcauth/types"
	sdkclient "github.com/cosmos/cosmos-sdk/client"
	sdk "github.com/cosmos/cosmos-sdk/types"
)

// BundleKeyChange is derived from decoded transaction bytes, never from
// user-supplied bundle metadata. It describes the target, not the authorizer.
type BundleKeyChange struct {
	Operation       string          `json:"operation"`
	Role            string          `json:"role"`
	NewKeyID        uint64          `json:"new_key_id"`
	Algorithm       types.Algorithm `json:"algorithm"`
	PublicKeySHA256 string          `json:"public_key_sha256"`
}

func bundleKeyChange(tx sdk.Tx) (*BundleKeyChange, error) {
	var change *BundleKeyChange
	for _, msg := range tx.GetMsgs() {
		switch m := msg.(type) {
		case *types.MsgRotateKey:
			if m == nil {
				return nil, fmt.Errorf("nil signing-key rotation")
			}
			if err := m.ValidateBasic(); err != nil {
				return nil, err
			}
			change = &BundleKeyChange{"rotate-key", "signing", m.ExpectedNewKeyId, m.NewAlgorithm, PublicKeySHA256(m.NewPublicKey)}
		case *types.MsgRotateRecoveryKey:
			if m == nil {
				return nil, fmt.Errorf("nil recovery-key rotation")
			}
			if err := m.ValidateBasic(); err != nil {
				return nil, err
			}
			change = &BundleKeyChange{"rotate-recovery-key", "recovery", m.ExpectedNewKeyId, m.NewAlgorithm, PublicKeySHA256(m.NewPublicKey)}
		}
		if change != nil && len(tx.GetMsgs()) != 1 {
			return nil, fmt.Errorf("key rotation must be the only top-level message")
		}
	}
	return change, nil
}

func validateExpectedPublicKey(algorithm types.Algorithm, actualSHA256, expectedSHA256 string) error {
	expected, err := hex.DecodeString(expectedSHA256)
	if err != nil || len(expected) != sha256.Size {
		return fmt.Errorf("expected new key fingerprint must be a full 64-character SHA-256 hex value")
	}
	if algorithm != types.Algorithm_ALGORITHM_ML_DSA_65 {
		return fmt.Errorf("expected new key must use ML-DSA-65")
	}
	actual, err := hex.DecodeString(actualSHA256)
	if err != nil || len(actual) != sha256.Size || !constantTimeBytesEqual(actual, expected) {
		return fmt.Errorf("new key fingerprint does not match trusted expected key")
	}
	return nil
}

// ValidatePQCSigningTarget requires an independently trusted target for a
// rotation. Do not silently ignore an expected target on a different action.
func ValidatePQCSigningTarget(summary PQCSignBundleSummary, expectedSHA256 string) error {
	if summary.KeyChange == nil {
		if expectedSHA256 != "" {
			return fmt.Errorf("expected new key supplied but transaction is not a key rotation")
		}
		return nil
	}
	return validateExpectedPublicKey(summary.KeyChange.Algorithm, summary.KeyChange.PublicKeySHA256, expectedSHA256)
}

// SignPQCSignBundleForTarget is the offline/untrusted-bundle entry point. An
// empty expected fingerprint is accepted only for non-rotation transactions.
func SignPQCSignBundleForTarget(ctx context.Context, txConfig sdkclient.TxConfig, bundle *PQCSignBundleV1, signer PQCSigner, expectedSHA256 string) (*PQCSignBundleV1, PQCSignBundleSummary, error) {
	summary, err := ValidatePQCSignBundle(txConfig, bundle, false)
	if err != nil {
		return nil, PQCSignBundleSummary{}, err
	}
	if err := ValidatePQCSigningTarget(summary, expectedSHA256); err != nil {
		return nil, PQCSignBundleSummary{}, err
	}
	return SignPQCSignBundle(ctx, txConfig, bundle, signer)
}
