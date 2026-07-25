package types

import (
	"testing"

	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/cosmos/cosmos-sdk/types/address"
	"github.com/stretchr/testify/require"
)

func validSponsorStateFixture() ContractSponsor {
	contract := sdk.AccAddress([]byte("state_contract______"))
	admin := sdk.AccAddress([]byte("state_admin_________"))
	return ContractSponsor{
		ContractAddress: contract.String(),
		CreatorAddress:  admin.String(),
		SponsorAddress: sdk.AccAddress(
			address.Derive(contract, []byte("sponsor")),
		).String(),
		IsSponsored: true,
		MaxGrantPerUser: []*sdk.Coin{
			{
				Denom:  SponsorshipDenom,
				Amount: sdk.NewInt(100),
			},
		},
		Generation: 1,
	}
}

func TestValidateContractSponsorState(t *testing.T) {
	sponsor := validSponsorStateFixture()
	require.NoError(t, ValidateContractSponsorState(sponsor, true))

	invalid := sponsor
	invalid.SponsorAddress = invalid.CreatorAddress
	require.Error(t, ValidateContractSponsorState(invalid, true))

	invalid = sponsor
	invalid.Generation = 0
	require.Error(t, ValidateContractSponsorState(invalid, true))
	require.NoError(t, ValidateContractSponsorState(invalid, false))
}

func TestValidatePolicyTicketState(t *testing.T) {
	sponsor := validSponsorStateFixture()
	user := sdk.AccAddress([]byte("state_ticket_user___")).String()
	method := "execute"
	ticket := PolicyTicket{
		ContractAddress: sponsor.ContractAddress,
		UserAddress:     user,
		Digest:          ComputeMethodDigestSingle(sponsor.ContractAddress, method),
		ExpiryHeight:    20,
		UsesRemaining:   1,
		IssuedHeight:    10,
		Method:          method,
		Generation:      1,
	}
	require.NoError(t, ValidatePolicyTicketState(ticket, 64, true))

	invalid := ticket
	invalid.Digest = "mismatch"
	require.Error(t, ValidatePolicyTicketState(invalid, 64, true))

	invalid = ticket
	invalid.Consumed = true
	require.Error(t, ValidatePolicyTicketState(invalid, 64, true))

	invalid = ticket
	invalid.UsesRemaining = 0
	invalid.Consumed = true
	require.NoError(t, ValidatePolicyTicketState(invalid, 64, true))

	invalid = ticket
	invalid.IssuedHeight = invalid.ExpiryHeight + 1
	require.Error(t, ValidatePolicyTicketState(invalid, 64, true))
}

func TestValidateUserGrantUsageState(t *testing.T) {
	sponsor := validSponsorStateFixture()
	user := sdk.AccAddress([]byte("state_usage_user____")).String()
	usage := UserGrantUsage{
		ContractAddress: sponsor.ContractAddress,
		UserAddress:     user,
		TotalGrantUsed: []*sdk.Coin{
			{
				Denom:  SponsorshipDenom,
				Amount: sdk.NewInt(100),
			},
		},
		Generation: 1,
	}
	require.NoError(t, ValidateUserGrantUsageState(usage, true))

	duplicate := sdk.NewInt64Coin(SponsorshipDenom, 1)
	invalid := usage
	invalid.TotalGrantUsed = append(invalid.TotalGrantUsed, &duplicate)
	require.Error(t, ValidateUserGrantUsageState(invalid, true))

	invalid = usage
	invalid.Generation = 0
	require.Error(t, ValidateUserGrantUsageState(invalid, true))
}
