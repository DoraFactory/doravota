package client

import (
	"bytes"
	"context"
	"fmt"

	pqccrypto "github.com/DoraFactory/doravota/x/pqcauth/crypto"
	"github.com/DoraFactory/doravota/x/pqcauth/types"
	"github.com/cosmos/cosmos-sdk/crypto/keyring"
	"github.com/cosmos/cosmos-sdk/crypto/keys/mldsa65"
	"github.com/cosmos/cosmos-sdk/crypto/keys/secp256k1"
	cryptotypes "github.com/cosmos/cosmos-sdk/crypto/types"
	"github.com/cosmos/cosmos-sdk/types/tx/signing"
)

type keyringSigner struct {
	keys keyring.Keyring
	name string
}

// NewKeyringSigner uses the SDK's key management, without exporting private keys.
func NewKeyringSigner(keys keyring.Keyring, name string) (PQCSigner, error) {
	if keys == nil || name == "" {
		return nil, fmt.Errorf("ML-DSA keyring and key name are required")
	}
	s := keyringSigner{keys, name}
	if _, err := s.PublicKey(context.Background()); err != nil {
		return nil, err
	}
	return s, nil
}
func (keyringSigner) Algorithm() types.Algorithm { return types.Algorithm_ALGORITHM_ML_DSA_65 }
func (s keyringSigner) PublicKey(ctx context.Context) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	r, err := s.keys.Key(s.name)
	if err != nil {
		return nil, err
	}
	pub, err := r.GetPubKey()
	if err != nil {
		return nil, err
	}
	if _, ok := pub.(*mldsa65.PubKey); !ok {
		return nil, fmt.Errorf("PQC factor must be an ml_dsa_65 key")
	}
	return pub.Bytes(), nil
}
func (s keyringSigner) Sign(ctx context.Context, msg, domain []byte) ([]byte, error) {
	expected, err := s.PublicKey(ctx)
	if err != nil {
		return nil, err
	}
	envelope, err := pqccrypto.SigningEnvelope(msg, domain)
	if err != nil {
		return nil, err
	}
	sig, pub, err := s.keys.Sign(s.name, envelope, signing.SignMode_SIGN_MODE_DIRECT)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(pub.Bytes(), expected) {
		return nil, fmt.Errorf("keyring public key changed while signing")
	}
	if err := pqccrypto.Verify(pqccrypto.AlgorithmMLDSA65, expected, msg, domain, sig); err != nil {
		return nil, err
	}
	return sig, nil
}

// CheckFactorIndependence catches the known same-derived-key coupling only.
// A false checked result means no local secp256k1 private key was available;
// it must never be presented as proof of mnemonic independence.
func CheckFactorIndependence(keys keyring.Keyring, owner string, factors ...[]byte) (checked bool, err error) {
	if keys == nil || owner == "" {
		return false, nil
	}
	record, err := keys.Key(owner)
	if err != nil {
		return false, err
	}
	pub, err := record.GetPubKey()
	if err != nil {
		return false, err
	}
	if _, ok := pub.(*secp256k1.PubKey); !ok {
		return false, nil
	}
	local := record.GetLocal()
	if local == nil || local.PrivKey == nil {
		return false, nil
	}
	priv, ok := local.PrivKey.GetCachedValue().(cryptotypes.PrivKey)
	if !ok {
		return false, fmt.Errorf("cannot inspect local owner key")
	}
	// Copy: never clear the live keyring key's backing storage.
	seed := append([]byte(nil), priv.Bytes()...)
	defer clear(seed)
	derived, err := mldsa65.GenPrivKeyFromSeed(seed)
	if err != nil {
		return false, err
	}
	defer clear(derived.Key)
	coupled := derived.PubKey().Bytes()
	for _, factor := range factors {
		if bytes.Equal(factor, coupled) {
			return true, fmt.Errorf("unsafe PQC factor: derived from the owner's classical private key; use a fresh dedicated mnemonic")
		}
	}
	return true, nil
}

// NewLegacyFileSigner is exclusively for keys created by the old raw-file CLI.
func NewLegacyFileSigner(path string) (PQCSigner, func(), error) {
	raw, err := LoadPrivateKeyFile(path)
	if err != nil {
		return nil, func() {}, err
	}
	return localMLDSA65Signer{privateKey: raw}, func() { clear(raw) }, nil
}
