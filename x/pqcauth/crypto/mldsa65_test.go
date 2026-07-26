package pqccrypto_test

import (
	"bytes"
	"errors"
	"io"
	"testing"

	pqccrypto "github.com/DoraFactory/doravota/x/pqcauth/crypto"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

func deterministicKeyPair() ([]byte, []byte) {
	var seed [mldsa65.SeedSize]byte
	for i := range seed {
		seed[i] = byte(i + 1)
	}
	pk, sk := mldsa65.NewKeyFromSeed(&seed)
	return pk.Bytes(), sk.Bytes()
}

func TestMLDSA65RoundTrip(t *testing.T) {
	publicKey, privateKey := deterministicKeyPair()
	message := []byte("canonical PQC sign doc")
	context := []byte("doravota/pqcauth/tx/v1")

	signature, err := pqccrypto.SignMLDSA65(privateKey, message, context, false)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if err := pqccrypto.Verify(
		pqccrypto.AlgorithmMLDSA65,
		publicKey,
		message,
		context,
		signature,
	); err != nil {
		t.Fatalf("verify: %v", err)
	}
	derived, err := pqccrypto.MLDSA65PublicKeyFromPrivate(privateKey)
	if err != nil {
		t.Fatalf("derive public key: %v", err)
	}
	if !bytes.Equal(publicKey, derived) {
		t.Fatal("derived public key does not match")
	}
}

func TestMLDSA65RejectsAlteredInputs(t *testing.T) {
	publicKey, privateKey := deterministicKeyPair()
	message := []byte("canonical PQC sign doc")
	context := []byte("doravota/pqcauth/tx/v1")
	signature, err := pqccrypto.SignMLDSA65(privateKey, message, context, false)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	tests := []struct {
		name      string
		publicKey []byte
		message   []byte
		context   []byte
		signature []byte
	}{
		{
			name:      "message",
			publicKey: publicKey,
			message:   []byte("different sign doc"),
			context:   context,
			signature: signature,
		},
		{
			name:      "context",
			publicKey: publicKey,
			message:   message,
			context:   []byte("doravota/pqcauth/register/v1"),
			signature: signature,
		},
		{
			name:      "signature",
			publicKey: publicKey,
			message:   message,
			context:   context,
			signature: append([]byte(nil), signature...),
		},
		{
			name:      "public key",
			publicKey: append([]byte(nil), publicKey...),
			message:   message,
			context:   context,
			signature: signature,
		},
	}
	tests[2].signature[0] ^= 0x80
	tests[3].publicKey[0] ^= 0x80

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := pqccrypto.Verify(
				pqccrypto.AlgorithmMLDSA65,
				test.publicKey,
				test.message,
				test.context,
				test.signature,
			)
			if !errors.Is(err, pqccrypto.ErrInvalidSignature) {
				t.Fatalf("got %v, want invalid signature", err)
			}
		})
	}
}

func TestMLDSA65RejectsInvalidLengthsAndAlgorithm(t *testing.T) {
	publicKey, privateKey := deterministicKeyPair()
	message := []byte("message")
	context := []byte("doravota/pqcauth/tx/v1")
	signature, err := pqccrypto.SignMLDSA65(privateKey, message, context, false)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	if err := pqccrypto.Verify(
		pqccrypto.AlgorithmMLDSA65,
		publicKey[:len(publicKey)-1],
		message,
		context,
		signature,
	); !errors.Is(err, pqccrypto.ErrInvalidPublicKey) {
		t.Fatalf("short public key: got %v", err)
	}
	if err := pqccrypto.Verify(
		pqccrypto.AlgorithmMLDSA65,
		publicKey,
		message,
		context,
		signature[:len(signature)-1],
	); !errors.Is(err, pqccrypto.ErrInvalidSignature) {
		t.Fatalf("short signature: got %v", err)
	}
	if err := pqccrypto.Verify(99, publicKey, message, context, signature); !errors.Is(
		err,
		pqccrypto.ErrUnsupportedAlgorithm,
	) {
		t.Fatalf("unsupported algorithm: got %v", err)
	}
	if _, err := pqccrypto.SignMLDSA65(
		privateKey,
		message,
		bytes.Repeat([]byte{1}, pqccrypto.MaxContextSize+1),
		false,
	); !errors.Is(err, pqccrypto.ErrContextTooLarge) {
		t.Fatalf("oversized context: got %v", err)
	}
	if err := pqccrypto.Verify(
		pqccrypto.AlgorithmMLDSA65,
		publicKey,
		message,
		bytes.Repeat([]byte{1}, pqccrypto.MaxContextSize+1),
		signature,
	); !errors.Is(err, pqccrypto.ErrContextTooLarge) {
		t.Fatalf("verify oversized context: got %v", err)
	}
	if _, err := pqccrypto.SignMLDSA65(
		privateKey[:1],
		message,
		context,
		false,
	); !errors.Is(err, pqccrypto.ErrInvalidPrivateKey) {
		t.Fatalf("short private key: got %v", err)
	}
	if _, err := pqccrypto.MLDSA65PublicKeyFromPrivate(
		privateKey[:1],
	); !errors.Is(err, pqccrypto.ErrInvalidPrivateKey) {
		t.Fatalf("derive from short private key: got %v", err)
	}
}

type failingEntropyReader struct{}

func (failingEntropyReader) Read([]byte) (int, error) {
	return 0, io.ErrUnexpectedEOF
}

func TestAlgorithmSizesAndKeyGenerationBoundaries(t *testing.T) {
	publicKeySize, signatureSize, err := pqccrypto.Sizes(pqccrypto.AlgorithmMLDSA65)
	if err != nil {
		t.Fatalf("sizes: %v", err)
	}
	if publicKeySize != mldsa65.PublicKeySize || signatureSize != mldsa65.SignatureSize {
		t.Fatalf("unexpected sizes: public=%d signature=%d", publicKeySize, signatureSize)
	}
	if _, _, err := pqccrypto.Sizes(99); !errors.Is(
		err,
		pqccrypto.ErrUnsupportedAlgorithm,
	) {
		t.Fatalf("unsupported sizes: %v", err)
	}
	privateKeySize, err := pqccrypto.PrivateKeySize(pqccrypto.AlgorithmMLDSA65)
	if err != nil || privateKeySize != mldsa65.PrivateKeySize {
		t.Fatalf("private key size: %d, %v", privateKeySize, err)
	}
	if _, err := pqccrypto.PrivateKeySize(99); !errors.Is(
		err,
		pqccrypto.ErrUnsupportedAlgorithm,
	) {
		t.Fatalf("unsupported private size: %v", err)
	}

	publicKey, privateKey, err := pqccrypto.GenerateMLDSA65Key(
		bytes.NewReader(make([]byte, mldsa65.SeedSize)),
	)
	if err != nil {
		t.Fatalf("deterministic generation: %v", err)
	}
	if len(publicKey) != publicKeySize || len(privateKey) != privateKeySize {
		t.Fatalf("generated key sizes: public=%d private=%d", len(publicKey), len(privateKey))
	}
	if _, _, err := pqccrypto.GenerateMLDSA65Key(failingEntropyReader{}); err == nil {
		t.Fatal("expected entropy failure")
	}
}

func FuzzMLDSA65VerifyDoesNotPanic(f *testing.F) {
	publicKey, privateKey := deterministicKeyPair()
	message := []byte("message")
	context := []byte("doravota/pqcauth/tx/v1")
	signature, err := pqccrypto.SignMLDSA65(privateKey, message, context, false)
	if err != nil {
		f.Fatalf("sign: %v", err)
	}
	f.Add(publicKey, message, context, signature)
	f.Add([]byte{1}, []byte{}, []byte{}, []byte{2})

	f.Fuzz(func(t *testing.T, pk, msg, ctx, sig []byte) {
		_ = pqccrypto.Verify(pqccrypto.AlgorithmMLDSA65, pk, msg, ctx, sig)
	})
}

func BenchmarkMLDSA65Verify(b *testing.B) {
	publicKey, privateKey := deterministicKeyPair()
	message := []byte("canonical PQC sign doc")
	context := []byte("doravota/pqcauth/tx/v1")
	signature, err := pqccrypto.SignMLDSA65(privateKey, message, context, false)
	if err != nil {
		b.Fatalf("sign: %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := pqccrypto.Verify(
			pqccrypto.AlgorithmMLDSA65,
			publicKey,
			message,
			context,
			signature,
		); err != nil {
			b.Fatal(err)
		}
	}
}
