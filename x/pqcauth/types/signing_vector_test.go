package types

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

func TestPQCSignDocV1DeterministicVector(t *testing.T) {
	signBytes, err := MarshalPQCSignDocV1(PQCSignDocV1{
		FormatVersion:           FormatVersionV1,
		NetworkId:               []byte("0123456789abcdef0123456789abcdef"),
		ChainId:                 "doravota-vector-1",
		AccountNumber:           17,
		Sequence:                23,
		SignerIndex:             1,
		Signer:                  "dora1vectorowner",
		KeyId:                   9,
		Algorithm:               Algorithm_ALGORITHM_ML_DSA_65,
		PolicyVersion:           5,
		BodyBytesWithoutPqcAuth: []byte{0x0a, 0x01, 0x01},
		AuthInfoBytes:           []byte{0x12, 0x01, 0x02},
	})
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(signBytes)
	if got, want := hex.EncodeToString(signBytes), "0801122030313233343536373839616263646566303132333435363738396162636465661a11646f7261766f74612d766563746f722d312011281730013a10646f726131766563746f726f776e65724009480150055a030a01016203120102"; got != want {
		t.Fatalf("sign doc encoding changed: got %s, want %s", got, want)
	}
	if got, want := hex.EncodeToString(digest[:]), "01ab370dadd89187efbc2fba80ffc0d9782721f572b941c5b191e4d51d234c75"; got != want {
		t.Fatalf("sign doc digest changed: got %s, want %s", got, want)
	}
}
