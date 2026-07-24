package types

import (
	"fmt"

	sdk "github.com/cosmos/cosmos-sdk/types"
)

// CanonicalAddressString parses an account address and returns the canonical
// Bech32 representation used by the SDK.
func CanonicalAddressString(addr string) (string, error) {
	parsed, err := sdk.AccAddressFromBech32(addr)
	if err != nil {
		return "", err
	}
	return parsed.String(), nil
}

// ValidateCanonicalAddress rejects alternate textual encodings of the same
// address. State keys, lifecycle generations, and ticket digests must all use
// one representation.
func ValidateCanonicalAddress(addr string) error {
	_, err := AccAddressFromCanonicalBech32(addr)
	return err
}

// AccAddressFromCanonicalBech32 parses an address only when its textual form is
// already canonical.
func AccAddressFromCanonicalBech32(addr string) (sdk.AccAddress, error) {
	parsed, err := sdk.AccAddressFromBech32(addr)
	if err != nil {
		return nil, err
	}
	if addr != parsed.String() {
		return nil, fmt.Errorf("address must use canonical Bech32 encoding")
	}
	return parsed, nil
}

// CanonicalAddressOrOriginal is a defensive helper for low-level key builders
// and legacy state. Public message and genesis validation still reject
// non-canonical inputs; valid alternate encodings map to the canonical key.
func CanonicalAddressOrOriginal(addr string) string {
	canonical, err := CanonicalAddressString(addr)
	if err != nil {
		return addr
	}
	return canonical
}
