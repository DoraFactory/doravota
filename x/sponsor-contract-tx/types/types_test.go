package types

import (
	"testing"

	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/stretchr/testify/require"
)

func TestContractSponsor(t *testing.T) {
	tests := []struct {
		name     string
		sponsor  ContractSponsor
		expected string
	}{
		{
			name: "active sponsor",
			sponsor: ContractSponsor{
				ContractAddress: "dora1contract123",
				IsSponsored:     true,
			},
			expected: "dora1contract123",
		},
		{
			name: "inactive sponsor",
			sponsor: ContractSponsor{
				ContractAddress: "dora1contract456",
				IsSponsored:     false,
			},
			expected: "dora1contract456",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.expected, tt.sponsor.ContractAddress)
		})
	}
}

func TestMsgSetSponsor(t *testing.T) {
	// Test MsgSetSponsor creation with max grant per user
	maxGrant := sdk.NewCoins(sdk.NewCoin("dora", sdk.NewInt(1000000)))
	msg := NewMsgSetSponsor("cosmos1signer", "cosmos1contract", true, maxGrant)

	require.Equal(t, "cosmos1signer", msg.Creator)
	require.Equal(t, "cosmos1contract", msg.ContractAddress)
	require.True(t, msg.IsSponsored)
	require.Len(t, msg.MaxGrantPerUser, 1)
	require.Equal(t, "dora", msg.MaxGrantPerUser[0].Denom)
	require.Equal(t, sdk.NewInt(1000000), msg.MaxGrantPerUser[0].Amount)
	require.Equal(t, "set_sponsor", msg.Type())
	require.Equal(t, RouterKey, msg.Route())
}

func TestMsgUpdateSponsor(t *testing.T) {
	// Test MsgUpdateSponsor creation with max grant per user
	maxGrant := sdk.NewCoins(sdk.NewCoin("dora", sdk.NewInt(500000)))
	msg := NewMsgUpdateSponsor("cosmos1signer", "cosmos1contract", false, maxGrant)

	require.Equal(t, "cosmos1signer", msg.Creator)
	require.Equal(t, "cosmos1contract", msg.ContractAddress)
	require.False(t, msg.IsSponsored)
	require.Len(t, msg.MaxGrantPerUser, 1)
	require.Equal(t, "dora", msg.MaxGrantPerUser[0].Denom)
	require.Equal(t, sdk.NewInt(500000), msg.MaxGrantPerUser[0].Amount)
	require.Equal(t, "update_sponsor", msg.Type())
	require.Equal(t, RouterKey, msg.Route())
}

func TestMsgDeleteSponsor(t *testing.T) {
	// Test MsgDeleteSponsor creation
	msg := NewMsgDeleteSponsor("cosmos1signer", "cosmos1contract")

	require.Equal(t, "cosmos1signer", msg.Creator)
	require.Equal(t, "cosmos1contract", msg.ContractAddress)
	require.Equal(t, "delete_sponsor", msg.Type())
	require.Equal(t, RouterKey, msg.Route())
}

func TestGenesisState(t *testing.T) {
	// Test default genesis state
	genState := DefaultGenesisState()
	require.NotNil(t, genState)
	require.Empty(t, genState.Sponsors)
	require.Empty(t, genState.UserGrantUsages)

	// Test genesis validation
	err := ValidateGenesis(*genState)
	require.NoError(t, err)

	// Test with sponsors
	sponsors := []*ContractSponsor{
		{
			ContractAddress: "cosmos1test1",
			IsSponsored:     true,
		},
		{
			ContractAddress: "cosmos1test2",
			IsSponsored:     false,
		},
	}

	genState = NewGenesisState(sponsors, []*UserGrantUsage{})
	require.Equal(t, 2, len(genState.Sponsors))

	err = ValidateGenesis(*genState)
	require.NoError(t, err)
}

func TestGenesisValidation(t *testing.T) {
	// Test duplicate contract addresses
	sponsors := []*ContractSponsor{
		{
			ContractAddress: "cosmos1test1",
			IsSponsored:     true,
		},
		{
			ContractAddress: "cosmos1test1", // duplicate
			IsSponsored:     false,
		},
	}

	genState := NewGenesisState(sponsors, []*UserGrantUsage{})
	err := ValidateGenesis(*genState)
	require.Error(t, err)
	require.Contains(t, err.Error(), "duplicate sponsor contract address")

	// Test empty contract address
	sponsors = []*ContractSponsor{
		{
			ContractAddress: "",
			IsSponsored:     true,
		},
	}

	genState = NewGenesisState(sponsors, []*UserGrantUsage{})
	err = ValidateGenesis(*genState)
	require.Error(t, err)
	require.Contains(t, err.Error(), "contract address cannot be empty")

	// Test duplicate user grant usage entries
	usages := []*UserGrantUsage{
		{
			UserAddress:     "cosmos1user",
			ContractAddress: "cosmos1test1",
		},
		{
			UserAddress:     "cosmos1user",
			ContractAddress: "cosmos1test1",
		},
	}

	genState = NewGenesisState([]*ContractSponsor{}, usages)
	err = ValidateGenesis(*genState)
	require.Error(t, err)
	require.Contains(t, err.Error(), "duplicate user grant usage")

	// Test empty user address in usage
	usages = []*UserGrantUsage{
		{
			UserAddress:     "",
			ContractAddress: "cosmos1test1",
		},
	}

	genState = NewGenesisState([]*ContractSponsor{}, usages)
	err = ValidateGenesis(*genState)
	require.Error(t, err)
	require.Contains(t, err.Error(), "user grant usage user address cannot be empty")

	// Test empty contract address in usage
	usages = []*UserGrantUsage{
		{
			UserAddress:     "cosmos1user",
			ContractAddress: "",
		},
	}

	genState = NewGenesisState([]*ContractSponsor{}, usages)
	err = ValidateGenesis(*genState)
	require.Error(t, err)
	require.Contains(t, err.Error(), "user grant usage contract address cannot be empty")
}
