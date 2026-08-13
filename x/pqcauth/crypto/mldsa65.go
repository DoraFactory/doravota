package pqccrypto

import (
	"errors"
	"fmt"
	"io"

	cmtmldsa65 "github.com/cometbft/cometbft/crypto/mldsa65"
	sdkmldsa65 "github.com/cosmos/cosmos-sdk/crypto/keys/mldsa65"
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
		return cmtmldsa65.PubKeySize, cmtmldsa65.SignatureSize, nil
	default:
		return 0, 0, fmt.Errorf("%w: %d", ErrUnsupportedAlgorithm, algorithm)
	}
}

// PrivateKeySize returns the canonical encoded private-key size for algorithm.
func PrivateKeySize(algorithm Algorithm) (int, error) {
	switch algorithm {
	case AlgorithmMLDSA65:
		return cmtmldsa65.PrivKeySize, nil
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
	if len(publicKey) != cmtmldsa65.PubKeySize {
		return fmt.Errorf("%w: ML-DSA-65 public key length %d, want %d",
			ErrInvalidPublicKey, len(publicKey), cmtmldsa65.PubKeySize)
	}
	if len(signature) != cmtmldsa65.SignatureSize {
		return fmt.Errorf("%w: ML-DSA-65 signature length %d, want %d",
			ErrInvalidSignature, len(signature), cmtmldsa65.SignatureSize)
	}

	key := sdkmldsa65.PubKey{Key: append([]byte(nil), publicKey...)}
	if _, err := cmtmldsa65.NewPubKeyFromBytes(key.Key); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidPublicKey, err)
	}
	if !key.VerifySignature(domainSeparatedMessage(message, context), signature) {
		return ErrInvalidSignature
	}
	return nil
}

// GenerateMLDSA65Key creates a new ML-DSA-65 key pair. A nil entropy source
// uses the SDK's OS-random key generator. A non-nil source is read into the
// fixed-size seed accepted by the SDK to support reproducible test vectors.
func GenerateMLDSA65Key(entropy io.Reader) (publicKey, privateKey []byte, err error) {
	if entropy == nil {
		key, err := sdkmldsa65.GenPrivKey()
		if err != nil {
			return nil, nil, fmt.Errorf("generate ML-DSA-65 key: %w", err)
		}
		return encodedKeyPair(key)
	}

	seed := make([]byte, cmtmldsa65.SeedSize)
	if _, err := io.ReadFull(entropy, seed); err != nil {
		return nil, nil, fmt.Errorf("generate ML-DSA-65 seed: %w", err)
	}
	key, err := sdkmldsa65.GenPrivKeyFromSeed(seed)
	if err != nil {
		return nil, nil, fmt.Errorf("generate ML-DSA-65 key: %w", err)
	}
	return encodedKeyPair(key)
}

// SignMLDSA65 signs a domain-separated message with the SDK's deterministic
// ML-DSA-65 implementation. randomized is retained for source compatibility
// but ignored because the native SDK API intentionally exposes pure mode.
func SignMLDSA65(privateKey, message, context []byte, randomized bool) ([]byte, error) {
	if len(context) > MaxContextSize {
		return nil, ErrContextTooLarge
	}
	if len(privateKey) != cmtmldsa65.PrivKeySize {
		return nil, fmt.Errorf("%w: ML-DSA-65 private key length %d, want %d",
			ErrInvalidPrivateKey, len(privateKey), cmtmldsa65.PrivKeySize)
	}

	key, err := sdkmldsa65.NewPrivateKeyFromBytes(privateKey)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidPrivateKey, err)
	}

	// The SDK wrapper intentionally exposes deterministic pure-mode signing.
	// PQCAuth preserves explicit domain separation by signing a canonical
	// envelope containing the former FIPS 204 context and the message. The
	// randomized flag remains in the public API for backward compatibility;
	// signatures produced through the native SDK path are deterministic.
	_ = randomized
	signature, err := key.Sign(domainSeparatedMessage(message, context))
	if err != nil {
		return nil, fmt.Errorf("sign with ML-DSA-65: %w", err)
	}
	return signature, nil
}

// MLDSA65PublicKeyFromPrivate derives the encoded public key from an encoded
// private key without exposing implementation-specific key types to callers.
func MLDSA65PublicKeyFromPrivate(privateKey []byte) ([]byte, error) {
	if len(privateKey) != cmtmldsa65.PrivKeySize {
		return nil, fmt.Errorf("%w: ML-DSA-65 private key length %d, want %d",
			ErrInvalidPrivateKey, len(privateKey), cmtmldsa65.PrivKeySize)
	}
	key, err := sdkmldsa65.NewPrivateKeyFromBytes(privateKey)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidPrivateKey, err)
	}
	publicKey, ok := key.PubKey().(*sdkmldsa65.PubKey)
	if !ok {
		return nil, ErrInvalidPrivateKey
	}
	return append([]byte(nil), publicKey.Bytes()...), nil
}

func encodedKeyPair(privateKey sdkmldsa65.PrivKey) ([]byte, []byte, error) {
	publicKey, ok := privateKey.PubKey().(*sdkmldsa65.PubKey)
	if !ok || publicKey == nil {
		return nil, nil, ErrInvalidPrivateKey
	}
	return append([]byte(nil), publicKey.Bytes()...),
		append([]byte(nil), privateKey.Bytes()...), nil
}

// domainSeparatedMessage returns PQCAuth's canonical SDK-native envelope:
// version || len(ctx) || ctx || M. CometBFT and the SDK wrapper expose the
// FIPS 204 pure mode (empty context), so the module binds its protocol domain
// into the message passed to that API. This is a coordinated consensus change
// and is not byte-for-byte compatible with pre-v0.55 contextual signatures.
func domainSeparatedMessage(message, context []byte) []byte {
	encoded := make([]byte, 0, 2+len(context)+len(message))
	encoded = append(encoded, 0, byte(len(context)))
	encoded = append(encoded, context...)
	encoded = append(encoded, message...)
	return encoded
}
