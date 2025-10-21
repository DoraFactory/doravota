package types

import (
    sdk "github.com/cosmos/cosmos-sdk/types"
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

	// Parameter store keys
	KeySponsorshipEnabled   = []byte("SponsorshipEnabled")
	KeyMaxGasPerSponsorship = []byte("MaxGasPerSponsorship")
)

// GetSponsorKey returns the store key for a sponsor record
func GetSponsorKey(contractAddr string) []byte {
	return append(SponsorKeyPrefix, []byte(contractAddr)...)
}

// GetUserGrantUsageKey returns the store key for a user grant usage record
func GetUserGrantUsageKey(userAddr, contractAddr string) []byte {
	// Format: UserGrantUsageKeyPrefix + userAddr + "/" + contractAddr
	key := append(UserGrantUsageKeyPrefix, []byte(userAddr)...)
	key = append(key, []byte("/")...)
	key = append(key, []byte(contractAddr)...)
	return key
}


// ValidateContractAddress validates a contract address
func ValidateContractAddress(addr string) error {
	if addr == "" {
		return ErrInvalidContractAddress.Wrap("contract address cannot be empty")
	}

	// Validate bech32 format - this already ensures the address is valid
	_, err := sdk.AccAddressFromBech32(addr)
	if err != nil {
		// Do not echo raw input to avoid log/response amplification
		return ErrInvalidContractAddress.Wrap("invalid bech32 address format")
	}

	return nil
}
