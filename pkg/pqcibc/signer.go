package pqcibc

import (
	"fmt"

	"github.com/cometbft/cometbft/crypto/mldsa65"
	"github.com/cosmos/cosmos-sdk/crypto/hd"
	"github.com/cosmos/cosmos-sdk/crypto/keyring"
	cryptotypes "github.com/cosmos/cosmos-sdk/crypto/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
	signing "github.com/cosmos/cosmos-sdk/types/tx/signing"
)

const SigningAlgorithmMLDSA65 = "ml_dsa_65"

// KeyringOption is the drop-in replacement for relayers that currently
// overwrite the SDK keyring algorithm lists. It preserves caller-specific
// software and Ledger algorithms while always enabling native Cosmos
// secp256k1 and ML-DSA-65 software keys. ML-DSA-65 is intentionally not added
// to Ledger algorithms until a hardware implementation exists.
func KeyringOption(softwareExtras, ledgerExtras keyring.SigningAlgoList) keyring.Option {
	return func(options *keyring.Options) {
		options.SupportedAlgos = appendUniqueAlgorithms(
			options.SupportedAlgos,
			append(keyring.SigningAlgoList{hd.Secp256k1, hd.MlDsa65}, softwareExtras...)...,
		)
		options.SupportedAlgosLedger = appendUniqueAlgorithms(
			options.SupportedAlgosLedger,
			append(keyring.SigningAlgoList{hd.Secp256k1}, ledgerExtras...)...,
		)
	}
}

// ResolveSigningAlgorithm maps relayer configuration to the SDK v0.55 native
// key algorithms. An empty value retains the conventional secp256k1 default.
func ResolveSigningAlgorithm(name string) (keyring.SignatureAlgo, error) {
	switch name {
	case "", string(hd.Secp256k1Type):
		return hd.Secp256k1, nil
	case SigningAlgorithmMLDSA65:
		return hd.MlDsa65, nil
	default:
		return nil, fmt.Errorf("unsupported relayer signing algorithm %q", name)
	}
}

// NewNativeMLDSA65Key creates a mnemonic-backed, recoverable relayer key using
// the SDK's native ML-DSA-65 account implementation.
func NewNativeMLDSA65Key(kb keyring.Keyring, name string) (*keyring.Record, string, error) {
	if kb == nil {
		return nil, "", fmt.Errorf("keyring is nil")
	}
	record, mnemonic, err := kb.NewMnemonic(
		name,
		keyring.English,
		sdk.FullFundraiserPath,
		keyring.DefaultBIP39Passphrase,
		hd.MlDsa65,
	)
	if err != nil {
		return nil, "", fmt.Errorf("create ML-DSA-65 relayer key: %w", err)
	}
	return record, mnemonic, nil
}

// KeyringSigner is the signing boundary used by a relayer transaction
// broadcaster. Construction fails unless the selected key is native
// ML-DSA-65, preventing an operator from believing the relayer itself is PQC
// while it is silently broadcasting with a classic key.
type KeyringSigner struct {
	keyring keyring.Keyring
	name    string
	address sdk.AccAddress
	pubKey  cryptotypes.PubKey
}

// NewKeyringSigner binds a native ML-DSA-65 key from an SDK keyring.
func NewKeyringSigner(kb keyring.Keyring, name string) (*KeyringSigner, error) {
	if kb == nil {
		return nil, fmt.Errorf("keyring is nil")
	}
	record, err := kb.Key(name)
	if err != nil {
		return nil, fmt.Errorf("load relayer key %q: %w", name, err)
	}
	pubKey, err := record.GetPubKey()
	if err != nil {
		return nil, fmt.Errorf("load relayer public key: %w", err)
	}
	if pubKey.Type() != mldsa65.KeyType {
		return nil, fmt.Errorf("relayer key %q uses %q, expected %q", name, pubKey.Type(), mldsa65.KeyType)
	}
	address, err := record.GetAddress()
	if err != nil {
		return nil, fmt.Errorf("derive relayer address: %w", err)
	}
	return &KeyringSigner{keyring: kb, name: name, address: address, pubKey: pubKey}, nil
}

// Address returns the account that must fund and authorize relayer messages.
func (s *KeyringSigner) Address() sdk.AccAddress {
	return append(sdk.AccAddress(nil), s.address...)
}

// PublicKey returns the native ML-DSA-65 account public key.
func (s *KeyringSigner) PublicKey() cryptotypes.PubKey {
	return s.pubKey
}

// SignDirect signs SDK SIGN_MODE_DIRECT bytes and verifies the signature before
// returning it to the broadcaster.
func (s *KeyringSigner) SignDirect(signBytes []byte) ([]byte, error) {
	if s == nil || s.keyring == nil {
		return nil, fmt.Errorf("relayer signer is not initialized")
	}
	signature, pubKey, err := s.keyring.Sign(s.name, signBytes, signing.SignMode_SIGN_MODE_DIRECT)
	if err != nil {
		return nil, fmt.Errorf("sign relayer transaction: %w", err)
	}
	if pubKey.Type() != mldsa65.KeyType || !pubKey.Equals(s.pubKey) {
		return nil, fmt.Errorf("keyring returned an unexpected public key")
	}
	if !pubKey.VerifySignature(signBytes, signature) {
		return nil, fmt.Errorf("keyring returned an invalid ML-DSA-65 signature")
	}
	return signature, nil
}

func appendUniqueAlgorithms(base keyring.SigningAlgoList, algorithms ...keyring.SignatureAlgo) keyring.SigningAlgoList {
	result := append(keyring.SigningAlgoList(nil), base...)
	for _, algorithm := range algorithms {
		if algorithm == nil {
			continue
		}
		found := false
		for _, existing := range result {
			if existing.Name() == algorithm.Name() {
				found = true
				break
			}
		}
		if !found {
			result = append(result, algorithm)
		}
	}
	return result
}
