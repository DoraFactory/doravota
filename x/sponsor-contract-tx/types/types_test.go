package types

import (
    "testing"

    sdk "github.com/cosmos/cosmos-sdk/types"
    "github.com/cosmos/cosmos-sdk/types/address"
    "github.com/stretchr/testify/require"
)

// mkAddr returns a deterministic bech32 address for tests
func mkAddr(seed byte) string {
    b := make([]byte, 20)
    for i := range b { b[i] = seed }
    return sdk.AccAddress(b).String()
}

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
    maxGrant := sdk.NewCoins(sdk.NewCoin("peaka", sdk.NewInt(1000000)))
    msg := NewMsgSetSponsor("cosmos1signer", "cosmos1contract", true, maxGrant)

	require.Equal(t, "cosmos1signer", msg.Creator)
	require.Equal(t, "cosmos1contract", msg.ContractAddress)
	require.True(t, msg.IsSponsored)
    require.Len(t, msg.MaxGrantPerUser, 1)
    require.Equal(t, "peaka", msg.MaxGrantPerUser[0].Denom)
	require.Equal(t, sdk.NewInt(1000000), msg.MaxGrantPerUser[0].Amount)
	require.Equal(t, "set_sponsor", msg.Type())
	require.Equal(t, RouterKey, msg.Route())
}

func TestMsgUpdateSponsor(t *testing.T) {
    // Test MsgUpdateSponsor creation with max grant per user
    maxGrant := sdk.NewCoins(sdk.NewCoin("peaka", sdk.NewInt(500000)))
    msg := NewMsgUpdateSponsor("cosmos1signer", "cosmos1contract", false, maxGrant)

	require.Equal(t, "cosmos1signer", msg.Creator)
	require.Equal(t, "cosmos1contract", msg.ContractAddress)
	require.False(t, msg.IsSponsored)
    require.Len(t, msg.MaxGrantPerUser, 1)
    require.Equal(t, "peaka", msg.MaxGrantPerUser[0].Denom)
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

    // Test with sponsors (use valid bech32 + derived sponsor address)
    contract1 := mkAddr(1)
    creator1 := mkAddr(3)
    ca1, _ := sdk.AccAddressFromBech32(contract1)
    sponsor1 := sdk.AccAddress(address.Derive(ca1, []byte("sponsor"))).String()

    contract2 := mkAddr(2)
    creator2 := mkAddr(4)
    ca2, _ := sdk.AccAddressFromBech32(contract2)
    sponsor2 := sdk.AccAddress(address.Derive(ca2, []byte("sponsor"))).String()

    sponsors := []*ContractSponsor{
        {
            ContractAddress: contract1,
            CreatorAddress:  creator1,
            SponsorAddress:  sponsor1,
            IsSponsored:     true,
            MaxGrantPerUser: []*sdk.Coin{{Denom: "peaka", Amount: sdk.NewInt(1)}},
        },
        {
            ContractAddress: contract2,
            CreatorAddress:  creator2,
            SponsorAddress:  sponsor2,
            IsSponsored:     false,
        },
    }

	genState = NewGenesisState(sponsors, []*UserGrantUsage{})
	require.Equal(t, 2, len(genState.Sponsors))

	err = ValidateGenesis(*genState)
	require.NoError(t, err)
}

func TestGenesisValidation(t *testing.T) {
    // Test duplicate contract addresses (provide required fields)
    dupContract := mkAddr(11)
    dupCreator := mkAddr(12)
    dupCA, _ := sdk.AccAddressFromBech32(dupContract)
    dupSponsor := sdk.AccAddress(address.Derive(dupCA, []byte("sponsor"))).String()
    sponsors := []*ContractSponsor{
        {
            ContractAddress: dupContract,
            CreatorAddress:  dupCreator,
            SponsorAddress:  dupSponsor,
            IsSponsored:     true,
            MaxGrantPerUser: []*sdk.Coin{{Denom: "peaka", Amount: sdk.NewInt(1)}},
        },
        {
            ContractAddress: dupContract, // duplicate
            CreatorAddress:  dupCreator,
            SponsorAddress:  dupSponsor,
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

    // Test duplicate user grant usage entries (valid bech32)
    user := mkAddr(21)
    contract := mkAddr(22)
    usages := []*UserGrantUsage{
        {
            UserAddress:     user,
            ContractAddress: contract,
        },
        {
            UserAddress:     user,
            ContractAddress: contract,
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
            ContractAddress: mkAddr(23),
        },
    }

	genState = NewGenesisState([]*ContractSponsor{}, usages)
	err = ValidateGenesis(*genState)
	require.Error(t, err)
	require.Contains(t, err.Error(), "user grant usage user address cannot be empty")

	// Test empty contract address in usage
    usages = []*UserGrantUsage{
        {
            UserAddress:     mkAddr(24),
            ContractAddress: "",
        },
    }

	genState = NewGenesisState([]*ContractSponsor{}, usages)
	err = ValidateGenesis(*genState)
	require.Error(t, err)
    require.Contains(t, err.Error(), "contract address cannot be empty")
}

// --- Genesis audit focused tests ---

func TestValidateGenesis_SponsorAddressFields(t *testing.T) {
    // empty contract address
    gen := NewGenesisState([]*ContractSponsor{{
        ContractAddress: "",
        CreatorAddress:  mkAddr(1),
        SponsorAddress:  mkAddr(2),
        IsSponsored:     false,
    }}, nil)
    err := ValidateGenesis(*gen)
    require.Error(t, err)
    require.Contains(t, err.Error(), "contract address cannot be empty")

    // invalid creator address
    ca := mkAddr(3)
    caAcc, _ := sdk.AccAddressFromBech32(ca)
    sp := sdk.AccAddress(address.Derive(caAcc, []byte("sponsor"))).String()
    gen = NewGenesisState([]*ContractSponsor{{
        ContractAddress: ca,
        CreatorAddress:  "invalid",
        SponsorAddress:  sp,
        IsSponsored:     false,
    }}, nil)
    err = ValidateGenesis(*gen)
    require.Error(t, err)
    require.Contains(t, err.Error(), "invalid sponsor creator address")

    // invalid sponsor address format
    gen = NewGenesisState([]*ContractSponsor{{
        ContractAddress: ca,
        CreatorAddress:  mkAddr(4),
        SponsorAddress:  "invalid",
        IsSponsored:     false,
    }}, nil)
    err = ValidateGenesis(*gen)
    require.Error(t, err)
    require.Contains(t, err.Error(), "invalid sponsor address")
}

func TestValidateGenesis_SponsorAddressMismatch(t *testing.T) {
    contract := mkAddr(5)
    caAcc, _ := sdk.AccAddressFromBech32(contract)
    // derive expected
    _ = sdk.AccAddress(address.Derive(caAcc, []byte("sponsor"))).String()
    // use a different valid address as sponsor to trigger mismatch
    wrongSponsor := mkAddr(6)
    gen := NewGenesisState([]*ContractSponsor{{
        ContractAddress: contract,
        CreatorAddress:  mkAddr(7),
        SponsorAddress:  wrongSponsor,
        IsSponsored:     false,
    }}, nil)
    err := ValidateGenesis(*gen)
    require.Error(t, err)
    require.Contains(t, err.Error(), "sponsor address must be derived from contract address")
}

func TestValidateGenesis_SponsoredRequiresMaxGrant(t *testing.T) {
    contract := mkAddr(8)
    caAcc, _ := sdk.AccAddressFromBech32(contract)
    sp := sdk.AccAddress(address.Derive(caAcc, []byte("sponsor"))).String()
    gen := NewGenesisState([]*ContractSponsor{{
        ContractAddress: contract,
        CreatorAddress:  mkAddr(9),
        SponsorAddress:  sp,
        IsSponsored:     true,
        MaxGrantPerUser: nil,
    }}, nil)
    err := ValidateGenesis(*gen)
    require.Error(t, err)
    require.Contains(t, err.Error(), "max_grant_per_user is required")
}

func TestValidateGenesis_MaxGrant_InvalidDenomOrAmount(t *testing.T) {
    contract := mkAddr(10)
    caAcc, _ := sdk.AccAddressFromBech32(contract)
    sp := sdk.AccAddress(address.Derive(caAcc, []byte("sponsor"))).String()
    // invalid denom
    gen := NewGenesisState([]*ContractSponsor{{
        ContractAddress: contract,
        CreatorAddress:  mkAddr(11),
        SponsorAddress:  sp,
        IsSponsored:     true,
        MaxGrantPerUser: []*sdk.Coin{{Denom: "dora", Amount: sdk.NewInt(1)}},
    }}, nil)
    err := ValidateGenesis(*gen)
    require.Error(t, err)
    require.Contains(t, err.Error(), "invalid denomination")

    // non-positive amount
    gen = NewGenesisState([]*ContractSponsor{{
        ContractAddress: contract,
        CreatorAddress:  mkAddr(11),
        SponsorAddress:  sp,
        IsSponsored:     true,
        MaxGrantPerUser: []*sdk.Coin{{Denom: "peaka", Amount: sdk.NewInt(0)}},
    }}, nil)
    err = ValidateGenesis(*gen)
    require.Error(t, err)
    require.Contains(t, err.Error(), "coin amount must be positive")
}

func TestValidateGenesis_SponsorTimeConsistency(t *testing.T) {
    contract := mkAddr(12)
    caAcc, _ := sdk.AccAddressFromBech32(contract)
    sp := sdk.AccAddress(address.Derive(caAcc, []byte("sponsor"))).String()
    gen := NewGenesisState([]*ContractSponsor{{
        ContractAddress: contract,
        CreatorAddress:  mkAddr(13),
        SponsorAddress:  sp,
        CreatedAt:       10,
        UpdatedAt:       5,
        IsSponsored:     false,
    }}, nil)
    err := ValidateGenesis(*gen)
    require.Error(t, err)
    require.Contains(t, err.Error(), "created_at must be <= updated_at")
}

func TestValidateGenesis_UserGrant_UnknownSponsor(t *testing.T) {
    user := mkAddr(21)
    contract := mkAddr(22)
    gen := NewGenesisState(nil, []*UserGrantUsage{{
        UserAddress:     user,
        ContractAddress: contract,
    }})
    err := ValidateGenesis(*gen)
    require.Error(t, err)
    require.Contains(t, err.Error(), "references unknown sponsor contract")
}

func TestValidateGenesis_UserGrant_InvalidCoins(t *testing.T) {
    user := mkAddr(23)
    contract := mkAddr(24)
    // invalid denom
    gen := NewGenesisState(nil, []*UserGrantUsage{{
        UserAddress:     user,
        ContractAddress: contract,
        TotalGrantUsed:  []*sdk.Coin{{Denom: "dora", Amount: sdk.NewInt(1)}},
    }})
    err := ValidateGenesis(*gen)
    require.Error(t, err)
    require.Contains(t, err.Error(), "invalid denomination")

    // negative amount
    gen = NewGenesisState(nil, []*UserGrantUsage{{
        UserAddress:     user,
        ContractAddress: contract,
        TotalGrantUsed:  []*sdk.Coin{{Denom: "peaka", Amount: sdk.NewInt(-1)}},
    }})
    err = ValidateGenesis(*gen)
    require.Error(t, err)
    require.Contains(t, err.Error(), "cannot be negative")
}

func TestValidateGenesis_UserGrant_ExceedsLimit(t *testing.T) {
    // sponsor with limit 100
    contract := mkAddr(25)
    creator := mkAddr(26)
    caAcc, _ := sdk.AccAddressFromBech32(contract)
    sp := sdk.AccAddress(address.Derive(caAcc, []byte("sponsor"))).String()
    sponsors := []*ContractSponsor{{
        ContractAddress: contract,
        CreatorAddress:  creator,
        SponsorAddress:  sp,
        IsSponsored:     true,
        MaxGrantPerUser: []*sdk.Coin{{Denom: "peaka", Amount: sdk.NewInt(100)}},
    }}
    usages := []*UserGrantUsage{{
        UserAddress:     mkAddr(27),
        ContractAddress: contract,
        TotalGrantUsed:  []*sdk.Coin{{Denom: "peaka", Amount: sdk.NewInt(101)}},
    }}
    gen := NewGenesisState(sponsors, usages)
    err := ValidateGenesis(*gen)
    require.Error(t, err)
    require.Contains(t, err.Error(), "exceeds max_grant_per_user")
}

func TestParams_MaxMethodTicketUsesPerIssue_Validate(t *testing.T) {
    // default should be 50
    p := DefaultParams()
    require.Equal(t, uint32(50), p.MaxMethodTicketUsesPerIssue)
    require.NoError(t, p.Validate())

    // 0 -> invalid
    p0 := p
    p0.MaxMethodTicketUsesPerIssue = 0
    require.Error(t, p0.Validate())

    // 1 -> ok
    p1 := p
    p1.MaxMethodTicketUsesPerIssue = 1
    require.NoError(t, p1.Validate())

    // 100 -> ok
    p100 := p
    p100.MaxMethodTicketUsesPerIssue = 100
    require.NoError(t, p100.Validate())

    // 101 -> invalid
    p101 := p
    p101.MaxMethodTicketUsesPerIssue = 101
    require.Error(t, p101.Validate())
}

func TestParams_MaxPolicyExecMsgBytes_UpperBound(t *testing.T) {
    p := DefaultParams()
    // at bound ok
    p.MaxPolicyExecMsgBytes = 1024 * 1024
    require.NoError(t, p.Validate())
    // above bound invalid
    p.MaxPolicyExecMsgBytes = 1024*1024 + 1
    require.Error(t, p.Validate())
}

func TestMsgIssuePolicyTicket_ValidateBasic_MethodOnly(t *testing.T) {
    validCreator := mkAddr(31)
    validContract := mkAddr(32)
    validUser := mkAddr(33)

    // valid baseline
    msg := MsgIssuePolicyTicket{
        Creator:         validCreator,
        ContractAddress: validContract,
        UserAddress:     validUser,
        Method:          "ping",
        Uses:            0,
    }
    require.NoError(t, msg.ValidateBasic())

    // empty methods -> error
    msgEmpty := msg
    msgEmpty.Method = ""
    err := msgEmpty.ValidateBasic()
    require.Error(t, err)
    require.Contains(t, err.Error(), "method is required")

    // invalid creator address
    msgBadCreator := msg
    msgBadCreator.Creator = "invalid"
    err = msgBadCreator.ValidateBasic()
    require.Error(t, err)

    // invalid contract address
    msgBadContract := msg
    msgBadContract.ContractAddress = "invalid"
    err = msgBadContract.ValidateBasic()
    require.Error(t, err)

    // invalid user address
    msgBadUser := msg
    msgBadUser.UserAddress = "invalid"
    err = msgBadUser.ValidateBasic()
    require.Error(t, err)
}
