package pqccrypto_test

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"

	pqccrypto "github.com/DoraFactory/doravota/x/pqcauth/crypto"
	cmtmldsa65 "github.com/cometbft/cometbft/crypto/mldsa65"
	sdkmldsa65 "github.com/cosmos/cosmos-sdk/crypto/keys/mldsa65"
)

func TestMLDSA65DeterministicVector(t *testing.T) {
	seed := make([]byte, cmtmldsa65.SeedSize)
	for i := range seed {
		seed[i] = byte(i*7 + 3)
	}
	privateKey, err := sdkmldsa65.GenPrivKeyFromSeed(seed)
	if err != nil {
		t.Fatal(err)
	}
	publicKey := privateKey.PubKey()
	message := []byte("doravota pqcauth deterministic cross-architecture vector v1")
	context := []byte("doravota/pqcauth/tx/v1")
	signature, err := pqccrypto.SignMLDSA65(privateKey.Bytes(), message, context, false)
	if err != nil {
		t.Fatal(err)
	}
	publicKeyDigest := sha256.Sum256(publicKey.Bytes())
	signatureDigest := sha256.Sum256(signature)
	if got, want := hex.EncodeToString(publicKeyDigest[:]), "f03a276f0d38544fe656170c0098c2507ac0a4936f1f0bbf6a3e73cba5dcc42d"; got != want {
		t.Fatalf("public key digest changed: got %s, want %s", got, want)
	}
	if got, want := hex.EncodeToString(signatureDigest[:]), "be0b385e2c26739b954e52fd9dbb3ff1b47212a5abc4eda23e2e384352e83d47"; got != want {
		t.Fatalf("signature digest changed: got %s, want %s", got, want)
	}
}
