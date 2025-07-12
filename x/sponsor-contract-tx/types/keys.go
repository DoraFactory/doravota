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
	if _, err := sdk.AccAddressFromBech32(addr); err != nil {
		return err
	}
	return nil
}
