package types

import (
	"encoding/binary"
)

const (
	// ModuleName defines the module name
	ModuleName = "sponsor"

	// StoreKey defines the primary module store key
	StoreKey = ModuleName

	// RouterKey defines the module's message routing key
	RouterKey = ModuleName
)

var (
	// SponsorKeyPrefix defines the prefix for sponsor records
	SponsorKeyPrefix = []byte{0x01}

	// ParamsKey defines the key for module parameters
	ParamsKey = []byte{0x02}

	// UserGrantUsageKeyPrefix defines the prefix for user grant usage records
	UserGrantUsageKeyPrefix = []byte{0x03}

	// PolicyTicketKeyPrefix defines the prefix for stored policy tickets
	PolicyTicketKeyPrefix = []byte{0x10}

	// ExpiryIndexKeyPrefix defines the prefix for expiry-time ordered ticket index
	ExpiryIndexKeyPrefix = []byte{0x11}

	// SponsorGenerationKeyPrefix stores the current lifecycle generation for a
	// contract. It intentionally survives Sponsor deletion.
	SponsorGenerationKeyPrefix = []byte{0x12}
)

// GetSponsorKey returns the store key for a sponsor record
func GetSponsorKey(contractAddr string) []byte {
	return append(SponsorKeyPrefix, []byte(CanonicalAddressOrOriginal(contractAddr))...)
}

// GetSponsorGenerationKey returns the persistent generation key for a contract.
func GetSponsorGenerationKey(contractAddr string) []byte {
	return append(SponsorGenerationKeyPrefix, []byte(CanonicalAddressOrOriginal(contractAddr))...)
}

// GetUserGrantUsageKey returns the store key for a user grant usage record
func GetUserGrantUsageKey(userAddr, contractAddr string) []byte {
	// Format: UserGrantUsageKeyPrefix + userAddr + "/" + contractAddr
	key := append(UserGrantUsageKeyPrefix, []byte(CanonicalAddressOrOriginal(userAddr))...)
	key = append(key, []byte("/")...)
	key = append(key, []byte(CanonicalAddressOrOriginal(contractAddr))...)
	return key
}

// GetPolicyTicketKey returns the store key for a policy ticket
// Format: PolicyTicketKeyPrefix + contractAddr + "/" + userAddr + "/" + digest
func GetPolicyTicketKey(contractAddr, userAddr, digest string) []byte {
	key := append(PolicyTicketKeyPrefix, []byte(CanonicalAddressOrOriginal(contractAddr))...)
	key = append(key, []byte("/")...)
	key = append(key, []byte(CanonicalAddressOrOriginal(userAddr))...)
	key = append(key, []byte("/")...)
	key = append(key, []byte(digest)...)
	return key
}

// EncodeUint64BigEndian encodes a uint64 as 8-byte big-endian
func EncodeUint64BigEndian(x uint64) []byte {
	bz := make([]byte, 8)
	binary.BigEndian.PutUint64(bz, x)
	return bz
}

// GetExpiryIndexPrefixForHeight returns the prefix for a specific expiry height bucket
func GetExpiryIndexPrefixForHeight(expiryHeight uint64) []byte {
	p := append([]byte{}, ExpiryIndexKeyPrefix...)
	p = append(p, EncodeUint64BigEndian(expiryHeight)...)
	p = append(p, '/')
	return p
}

// GetExpiryIndexKey returns the index key for (expiry, contract, user, digest)
// Format: ExpiryIndexKeyPrefix | BE8(expiry_height) | '/' | contract | '/' | user | '/' | digest
func GetExpiryIndexKey(expiryHeight uint64, contractAddr, userAddr, digest string) []byte {
	key := append([]byte{}, ExpiryIndexKeyPrefix...)
	key = append(key, EncodeUint64BigEndian(expiryHeight)...)
	key = append(key, '/')
	key = append(key, []byte(CanonicalAddressOrOriginal(contractAddr))...)
	key = append(key, '/')
	key = append(key, []byte(CanonicalAddressOrOriginal(userAddr))...)
	key = append(key, '/')
	key = append(key, []byte(digest)...)
	return key
}

// ParseExpiryIndexKey parses a key relative to ExpiryIndexKeyPrefix.
// It returns the expiry height and the corresponding policy-ticket key suffix.
func ParseExpiryIndexKey(key []byte) (uint64, []byte, bool) {
	const encodedHeightLength = 8
	if len(key) <= encodedHeightLength+1 || key[encodedHeightLength] != '/' {
		return 0, nil, false
	}

	expiryHeight := binary.BigEndian.Uint64(key[:encodedHeightLength])
	ticketKey := key[encodedHeightLength+1:]
	return expiryHeight, ticketKey, true
}

// ValidateContractAddress validates a contract address
func ValidateContractAddress(addr string) error {
	if addr == "" {
		return ErrInvalidContractAddress.Wrap("contract address cannot be empty")
	}

	// Validate bech32 format - this already ensures the address is valid
	if err := ValidateCanonicalAddress(addr); err != nil {
		// Do not echo raw input to avoid log/response amplification
		return ErrInvalidContractAddress.Wrap("contract address must use canonical bech32 encoding")
	}

	return nil
}
