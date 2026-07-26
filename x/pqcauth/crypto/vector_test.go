package pqccrypto_test

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

func TestMLDSA65DeterministicVector(t *testing.T) {
	var seed [mldsa65.SeedSize]byte
	for i := range seed {
		seed[i] = byte(i*7 + 3)
	}
	publicKey, privateKey := mldsa65.NewKeyFromSeed(&seed)
	message := []byte("doravota pqcauth deterministic cross-architecture vector v1")
	context := []byte("doravota/pqcauth/tx/v1")
	signature := make([]byte, mldsa65.SignatureSize)
	if err := mldsa65.SignTo(privateKey, message, context, false, signature); err != nil {
		t.Fatal(err)
	}
	publicKeyDigest := sha256.Sum256(publicKey.Bytes())
	signatureDigest := sha256.Sum256(signature)
	if got, want := hex.EncodeToString(publicKeyDigest[:]), "f03a276f0d38544fe656170c0098c2507ac0a4936f1f0bbf6a3e73cba5dcc42d"; got != want {
		t.Fatalf("public key digest changed: got %s, want %s", got, want)
	}
	if got, want := hex.EncodeToString(signatureDigest[:]), "84ef4fed3e30e3cb8f61b7622fc2f6ac89e87aba619ce53d33e90499ee8cbb9f"; got != want {
		t.Fatalf("signature digest changed: got %s, want %s", got, want)
	}
}
