package types

import (
	sdk "github.com/cosmos/cosmos-sdk/types"
)

const (
	// ModuleName defines the module name
	ModuleName = "contract-sponsor"

	// StoreKey defines the primary module store key
	StoreKey = ModuleName

	// MemStoreKey defines the in-memory store key
	MemStoreKey = "mem_sponsor"

	// RouterKey defines the module's message routing key
	RouterKey = ModuleName

	// QuerierRoute defines the module's query routing key
	QuerierRoute = ModuleName

	// Message types
	TypeMsgSetSponsor    = "set_sponsor"
	TypeMsgUpdateSponsor = "update_sponsor"
	TypeMsgDeleteSponsor = "delete_sponsor"
)

var (
	// SponsorKeyPrefix defines the prefix for sponsor records
	SponsorKeyPrefix = []byte{0x01}
	
	// ParamsKey defines the key for module parameters
	ParamsKey = []byte{0x02}
	
	// UserGrantUsageKeyPrefix defines the prefix for user grant usage records
	UserGrantUsageKeyPrefix = []byte{0x03}

	// Parameter store keys
	KeySponsorshipEnabled    = []byte("SponsorshipEnabled")
	KeyMaxGasPerSponsorship = []byte("MaxGasPerSponsorship")
)

// GetSponsorKey returns the store key for a sponsor record
func GetSponsorKey(contractAddr string) []byte {
	return append(SponsorKeyPrefix, []byte(contractAddr)...)
}

// GetSponsorKeyFromBytes returns the contract address from a sponsor key
func GetSponsorKeyFromBytes(key []byte) string {
	return string(key[len(SponsorKeyPrefix):])
}

// GetUserGrantUsageKey returns the store key for a user grant usage record
func GetUserGrantUsageKey(userAddr, contractAddr string) []byte {
	// Format: UserGrantUsageKeyPrefix + userAddr + "/" + contractAddr
	key := append(UserGrantUsageKeyPrefix, []byte(userAddr)...)
	key = append(key, []byte("/")...)
	key = append(key, []byte(contractAddr)...)
	return key
}

// GetUserGrantUsageKeyPrefix returns the prefix for all user grant usage records for a specific user
func GetUserGrantUsageKeyPrefix(userAddr string) []byte {
	return append(UserGrantUsageKeyPrefix, []byte(userAddr)...)
}

// ValidateContractAddress validates a contract address
func ValidateContractAddress(addr string) error {
	if addr == "" {
		return ErrInvalidContractAddress.Wrap("contract address cannot be empty")
	}
	
	// Validate bech32 format - this already ensures the address is valid
	_, err := sdk.AccAddressFromBech32(addr)
	if err != nil {
		return ErrInvalidContractAddress.Wrapf("invalid bech32 address format: %s", addr)
	}
	
	return nil
}
