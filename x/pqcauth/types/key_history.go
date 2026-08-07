package types

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
)

const KeyHistoryAccumulatorSize = sha256.Size

var (
	keyFingerprintDomain = []byte("doravota/pqcauth/key-fingerprint/v1")
	keyHistoryDomain     = []byte("doravota/pqcauth/key-history/v1")
)

// KeyFingerprint provides an algorithm-separated identifier for public key
// material. It is used for role-separation checks and compacted history.
func KeyFingerprint(algorithm Algorithm, publicKey []byte) [sha256.Size]byte {
	hasher := sha256.New()
	_, _ = hasher.Write(keyFingerprintDomain)
	var encoded [4]byte
	binary.BigEndian.PutUint32(encoded[:], uint32(algorithm))
	_, _ = hasher.Write(encoded[:])
	_, _ = hasher.Write(publicKey)
	var result [sha256.Size]byte
	copy(result[:], hasher.Sum(nil))
	return result
}

func SameKeyMaterial(
	leftAlgorithm Algorithm,
	leftPublicKey []byte,
	rightAlgorithm Algorithm,
	rightPublicKey []byte,
) bool {
	if leftAlgorithm != rightAlgorithm {
		return false
	}
	left := KeyFingerprint(leftAlgorithm, leftPublicKey)
	right := KeyFingerprint(rightAlgorithm, rightPublicKey)
	return bytes.Equal(left[:], right[:])
}

func ValidateDistinctRoleKeys(
	signingAlgorithm Algorithm,
	signingPublicKey []byte,
	recoveryAlgorithm Algorithm,
	recoveryPublicKey []byte,
) error {
	if SameKeyMaterial(
		signingAlgorithm,
		signingPublicKey,
		recoveryAlgorithm,
		recoveryPublicKey,
	) {
		return fmt.Errorf("%w: signing and recovery keys must be distinct", ErrInvalidKey)
	}
	return nil
}

// AccumulateKeyHistory commits one complete terminal record into a deterministic
// per-role hash chain. Callers must compact records in increasing key-id order.
func AccumulateKeyHistory(previous []byte, key PQCKeyRecord) ([]byte, error) {
	if len(previous) != 0 && len(previous) != KeyHistoryAccumulatorSize {
		return nil, fmt.Errorf("%w: invalid key history accumulator length", ErrInvalidKey)
	}
	hasher := sha256.New()
	_, _ = hasher.Write(keyHistoryDomain)
	if len(previous) == 0 {
		_, _ = hasher.Write(make([]byte, KeyHistoryAccumulatorSize))
	} else {
		_, _ = hasher.Write(previous)
	}
	writeHistoryBytes(hasher, []byte(key.Owner))
	writeHistoryUint64(hasher, key.KeyId)
	writeHistoryUint64(hasher, uint64(key.Algorithm))
	writeHistoryUint64(hasher, uint64(key.Role))
	writeHistoryUint64(hasher, uint64(key.Status))
	writeHistoryUint64(hasher, key.CreatedHeight)
	writeHistoryUint64(hasher, key.EffectiveHeight)
	writeHistoryUint64(hasher, key.InactiveFromHeight)
	fingerprint := KeyFingerprint(key.Algorithm, key.PublicKey)
	_, _ = hasher.Write(fingerprint[:])
	return hasher.Sum(nil), nil
}

type historyHashWriter interface {
	Write([]byte) (int, error)
}

func writeHistoryUint64(writer historyHashWriter, value uint64) {
	var encoded [8]byte
	binary.BigEndian.PutUint64(encoded[:], value)
	_, _ = writer.Write(encoded[:])
}

func writeHistoryBytes(writer historyHashWriter, value []byte) {
	writeHistoryUint64(writer, uint64(len(value)))
	_, _ = writer.Write(value)
}
