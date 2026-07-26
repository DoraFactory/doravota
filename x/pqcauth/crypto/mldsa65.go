package pqccrypto

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

// Algorithm is the wire-level identifier of a post-quantum signature algorithm.
// Values are append-only once they are enabled on a network.
type Algorithm uint32

const (
	AlgorithmUnspecified Algorithm = 0
	AlgorithmMLDSA65     Algorithm = 1
)

const MaxContextSize = 255

var (
	ErrUnsupportedAlgorithm = errors.New("unsupported PQC signature algorithm")
	ErrInvalidPublicKey     = errors.New("invalid PQC public key")
	ErrInvalidPrivateKey    = errors.New("invalid PQC private key")
	ErrInvalidSignature     = errors.New("invalid PQC signature")
	ErrContextTooLarge      = errors.New("PQC signature context exceeds 255 bytes")
)

// Sizes returns the canonical public-key and signature sizes for algorithm.
func Sizes(algorithm Algorithm) (publicKeySize int, signatureSize int, err error) {
	switch algorithm {
	case AlgorithmMLDSA65:
		return mldsa65.PublicKeySize, mldsa65.SignatureSize, nil
	default:
		return 0, 0, fmt.Errorf("%w: %d", ErrUnsupportedAlgorithm, algorithm)
	}
}

// PrivateKeySize returns the canonical encoded private-key size for algorithm.
func PrivateKeySize(algorithm Algorithm) (int, error) {
	switch algorithm {
	case AlgorithmMLDSA65:
		return mldsa65.PrivateKeySize, nil
	default:
		return 0, fmt.Errorf("%w: %d", ErrUnsupportedAlgorithm, algorithm)
	}
}

// Verify validates a detached post-quantum signature. It performs strict
// length checks before entering the cryptographic library so malformed
// transaction data cannot trigger unchecked slice access.
func Verify(algorithm Algorithm, publicKey, message, context, signature []byte) error {
	if len(context) > MaxContextSize {
		return ErrContextTooLarge
	}

	switch algorithm {
	case AlgorithmMLDSA65:
		return verifyMLDSA65(publicKey, message, context, signature)
	default:
		return fmt.Errorf("%w: %d", ErrUnsupportedAlgorithm, algorithm)
	}
}

func verifyMLDSA65(publicKey, message, context, signature []byte) error {
	if len(publicKey) != mldsa65.PublicKeySize {
		return fmt.Errorf("%w: ML-DSA-65 public key length %d, want %d",
			ErrInvalidPublicKey, len(publicKey), mldsa65.PublicKeySize)
	}
	if len(signature) != mldsa65.SignatureSize {
		return fmt.Errorf("%w: ML-DSA-65 signature length %d, want %d",
			ErrInvalidSignature, len(signature), mldsa65.SignatureSize)
	}

	var key mldsa65.PublicKey
	if err := key.UnmarshalBinary(publicKey); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidPublicKey, err)
	}
	if !mldsa65.Verify(&key, message, context, signature) {
		return ErrInvalidSignature
	}
	return nil
}

// GenerateMLDSA65Key generates an encoded ML-DSA-65 key pair. A nil entropy
// source selects crypto/rand.Reader.
func GenerateMLDSA65Key(entropy io.Reader) (publicKey, privateKey []byte, err error) {
	if entropy == nil {
		entropy = rand.Reader
	}

	pk, sk, err := mldsa65.GenerateKey(entropy)
	if err != nil {
		return nil, nil, fmt.Errorf("generate ML-DSA-65 key: %w", err)
	}
	return append([]byte(nil), pk.Bytes()...), append([]byte(nil), sk.Bytes()...), nil
}

// SignMLDSA65 signs message with the FIPS 204 context string. randomized
// should normally be true for wallets; deterministic signing is retained for
// reproducible test vectors and hardware implementations that require it.
func SignMLDSA65(privateKey, message, context []byte, randomized bool) ([]byte, error) {
	if len(context) > MaxContextSize {
		return nil, ErrContextTooLarge
	}
	if len(privateKey) != mldsa65.PrivateKeySize {
		return nil, fmt.Errorf("%w: ML-DSA-65 private key length %d, want %d",
			ErrInvalidPrivateKey, len(privateKey), mldsa65.PrivateKeySize)
	}

	var key mldsa65.PrivateKey
	if err := key.UnmarshalBinary(privateKey); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidPrivateKey, err)
	}

	signature := make([]byte, mldsa65.SignatureSize)
	if err := mldsa65.SignTo(&key, message, context, randomized, signature); err != nil {
		return nil, fmt.Errorf("sign with ML-DSA-65: %w", err)
	}
	return signature, nil
}

// MLDSA65PublicKeyFromPrivate derives the encoded public key from an encoded
// private key without exposing CIRCL key types to callers.
func MLDSA65PublicKeyFromPrivate(privateKey []byte) ([]byte, error) {
	if len(privateKey) != mldsa65.PrivateKeySize {
		return nil, fmt.Errorf("%w: ML-DSA-65 private key length %d, want %d",
			ErrInvalidPrivateKey, len(privateKey), mldsa65.PrivateKeySize)
	}
	var key mldsa65.PrivateKey
	if err := key.UnmarshalBinary(privateKey); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidPrivateKey, err)
	}
	publicKey, ok := key.Public().(*mldsa65.PublicKey)
	if !ok {
		return nil, ErrInvalidPrivateKey
	}
	return append([]byte(nil), publicKey.Bytes()...), nil
}
