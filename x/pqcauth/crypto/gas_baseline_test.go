package pqccrypto_test

import (
	"bytes"
	"fmt"
	"testing"

	pqccrypto "github.com/DoraFactory/doravota/x/pqcauth/crypto"
	sdkmldsa65 "github.com/cosmos/cosmos-sdk/crypto/keys/mldsa65"
)

// Compare exactly the same key, signed bytes and signature. The SDK case
// receives the already-built envelope; the wrapper case includes envelope
// construction and its extra validation. Neither measures a full Ante path,
// transaction canonicalization, state access or network throughput.
func BenchmarkMLDSA65GasBaseline(b *testing.B) {
	publicKey, privateKey := deterministicKeyPair()
	key := sdkmldsa65.PubKey{Key: publicKey}
	domain := []byte("doravota/pqcauth/tx/v1")
	for _, size := range []int{256, 4096, 65536} {
		message := bytes.Repeat([]byte{42}, size)
		envelope, err := pqccrypto.SigningEnvelope(message, domain)
		if err != nil {
			b.Fatal(err)
		}
		sig, err := pqccrypto.SignMLDSA65(privateKey, message, domain, false)
		if err != nil {
			b.Fatal(err)
		}
		if !key.VerifySignature(envelope, sig) {
			b.Fatal("the exact PQCAuth envelope must verify through the SDK")
		}
		b.Run(fmt.Sprintf("bytes%d/SDK", size), func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				if !key.VerifySignature(envelope, sig) {
					b.Fatal("SDK verification failed")
				}
			}
		})
		b.Run(fmt.Sprintf("bytes%d/PQCAuth", size), func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				if err := pqccrypto.Verify(pqccrypto.AlgorithmMLDSA65, publicKey, message, domain, sig); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
