package types

import (
	"github.com/cosmos/cosmos-sdk/crypto/keys/ed25519"
	"github.com/cosmos/cosmos-sdk/crypto/keys/mldsa65"
	"github.com/cosmos/cosmos-sdk/crypto/keys/secp256k1"
	"github.com/cosmos/cosmos-sdk/crypto/keys/secp256r1"
	cryptotypes "github.com/cosmos/cosmos-sdk/crypto/types"
)

// AccountAuthentication identifies the SDK-level authentication family of an
// account. pqcauth is intentionally a compatibility layer for classic direct
// account keys; native post-quantum accounts must use SDK authentication only.
type AccountAuthentication uint8

const (
	AccountAuthenticationUnsupported AccountAuthentication = iota
	AccountAuthenticationClassic
	AccountAuthenticationNativePQC
)

// ClassifyAccountAuthentication uses concrete, codec-registered public-key
// types rather than caller-controlled type strings. Unknown and composite key
// types remain unsupported until they receive an explicit security review.
func ClassifyAccountAuthentication(publicKey cryptotypes.PubKey) AccountAuthentication {
	switch publicKey.(type) {
	case *mldsa65.PubKey:
		return AccountAuthenticationNativePQC
	case *secp256k1.PubKey, *ed25519.PubKey, *secp256r1.PubKey:
		return AccountAuthenticationClassic
	default:
		return AccountAuthenticationUnsupported
	}
}
