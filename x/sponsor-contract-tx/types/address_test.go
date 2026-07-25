package types

import (
	"bytes"
	"strings"
	"testing"

	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/stretchr/testify/require"
)

func TestCanonicalAddressValidationRejectsAlternateEncoding(t *testing.T) {
	canonical := sdk.AccAddress(bytes.Repeat([]byte{0x01}, 20)).String()
	alternate := strings.ToUpper(canonical)

	// The SDK accepts an all-uppercase Bech32 encoding, so parsing alone is not
	// enough to guarantee a single textual identity for state keys.
	parsed, err := sdk.AccAddressFromBech32(alternate)
	require.NoError(t, err)
	require.Equal(t, canonical, parsed.String())

	normalized, err := CanonicalAddressString(alternate)
	require.NoError(t, err)
	require.Equal(t, canonical, normalized)

	require.NoError(t, ValidateCanonicalAddress(canonical))
	require.Error(t, ValidateCanonicalAddress(alternate))
}

func TestAddressKeyBuildersCanonicalizeEquivalentEncodings(t *testing.T) {
	contract := sdk.AccAddress(bytes.Repeat([]byte{0x02}, 20)).String()
	user := sdk.AccAddress(bytes.Repeat([]byte{0x03}, 20)).String()
	alternateContract := strings.ToUpper(contract)
	alternateUser := strings.ToUpper(user)

	require.Equal(t, GetSponsorKey(contract), GetSponsorKey(alternateContract))
	require.Equal(t, GetSponsorGenerationKey(contract), GetSponsorGenerationKey(alternateContract))
	require.Equal(
		t,
		GetUserGrantUsageKey(user, contract),
		GetUserGrantUsageKey(alternateUser, alternateContract),
	)
	require.Equal(
		t,
		GetPolicyTicketKey(contract, user, "digest"),
		GetPolicyTicketKey(alternateContract, alternateUser, "digest"),
	)
	require.Equal(
		t,
		GetExpiryIndexKey(42, contract, user, "digest"),
		GetExpiryIndexKey(42, alternateContract, alternateUser, "digest"),
	)
}

func TestValidateGenesisRejectsNonCanonicalStateAddresses(t *testing.T) {
	contract := sdk.AccAddress(bytes.Repeat([]byte{0x04}, 20)).String()
	user := sdk.AccAddress(bytes.Repeat([]byte{0x05}, 20)).String()
	params := DefaultParams()
	genesis := GenesisState{
		Params: &params,
		PolicyTickets: []*PolicyTicket{{
			ContractAddress: contract,
			UserAddress:     strings.ToUpper(user),
			Digest:          "digest",
			UsesRemaining:   1,
			Generation:      1,
		}},
	}

	require.Error(t, ValidateGenesis(genesis))

	genesis.PolicyTickets[0].UserAddress = user
	require.NoError(t, ValidateGenesis(genesis))
}
