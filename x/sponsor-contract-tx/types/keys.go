package types

import (
	sdk "github.com/cosmos/cosmos-sdk/types"
)

const (
	// ModuleName defines the module name
	ModuleName = "sponsor"

	// StoreKey defines the primary module store key
	StoreKey = ModuleName

	// MemStoreKey defines the in-memory store key
	MemStoreKey = "mem_sponsor"

	// RouterKey defines the module's message routing key
	RouterKey = ModuleName

	// QuerierRoute defines the module's query routing key
	QuerierRoute = ModuleName
)

var (
	// SponsorKeyPrefix defines the prefix for sponsor records
	SponsorKeyPrefix = []byte{0x01}
	
	// ParamsKey defines the key for module parameters
	ParamsKey = []byte{0x02}
)

// GetSponsorKey returns the store key for a sponsor record
func GetSponsorKey(contractAddr string) []byte {
	return append(SponsorKeyPrefix, []byte(contractAddr)...)
}

// GetSponsorKeyFromBytes returns the contract address from a sponsor key
func GetSponsorKeyFromBytes(key []byte) string {
	return string(key[len(SponsorKeyPrefix):])
}

// ValidateContractAddress validates a contract address
func ValidateContractAddress(addr string) error {
	if addr == "" {
		return ErrInvalidContractAddress.Wrap("contract address cannot be empty")
	}
	
	// Validate bech32 format
	accAddr, err := sdk.AccAddressFromBech32(addr)
	if err != nil {
		return ErrInvalidContractAddress.Wrapf("invalid bech32 address format: %s", addr)
	}
	
	// Check address length (should be 20 bytes for cosmos addresses)
	if len(accAddr) != 20 {
		return ErrInvalidContractAddress.Wrapf("invalid address length: expected 20 bytes, got %d", len(accAddr))
	}
	
	return nil
}
