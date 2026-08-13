package sponsor_test

import (
	sdkmath "cosmossdk.io/math"
	"math"
	"testing"

	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/cosmos/cosmos-sdk/types/address"
	"github.com/stretchr/testify/require"

	sponsor "github.com/DoraFactory/doravota/x/sponsor-contract-tx"
	"github.com/DoraFactory/doravota/x/sponsor-contract-tx/types"
)

func TestInitGenesisValidatesBeforeWritingState(t *testing.T) {
	k, ctx := setupKeeper(t)
	params := types.DefaultParams()
	params.PolicyTicketTtlBlocks = 77
	genesis := types.GenesisState{
		Params:   &params,
		Sponsors: []*types.ContractSponsor{nil},
	}

	require.Panics(t, func() {
		sponsor.InitGenesis(ctx, k, genesis)
	})
	require.Equal(
		t,
		types.DefaultParams().PolicyTicketTtlBlocks,
		k.GetParams(ctx).PolicyTicketTtlBlocks,
	)
}

func TestInitGenesisDoesNotMutateInputGenerations(t *testing.T) {
	k, ctx := setupKeeper(t)
	contract := sdk.AccAddress([]byte("immutable_contract__")).String()
	creator := sdk.AccAddress([]byte("immutable_creator___")).String()
	user := sdk.AccAddress([]byte("immutable_user______")).String()
	contractAddr, err := sdk.AccAddressFromBech32(contract)
	require.NoError(t, err)
	sponsorAddr := sdk.AccAddress(address.Derive(contractAddr, []byte("sponsor"))).String()
	digest := types.ComputeMethodDigestSingle(contract, "execute")
	params := types.DefaultParams()

	sponsorState := &types.ContractSponsor{
		ContractAddress: contract,
		CreatorAddress:  creator,
		SponsorAddress:  sponsorAddr,
		IsSponsored:     true,
		MaxGrantPerUser: []*sdk.Coin{{
			Denom:  types.SponsorshipDenom,
			Amount: sdkmath.NewInt(100),
		}},
	}
	usageState := &types.UserGrantUsage{
		UserAddress:     user,
		ContractAddress: contract,
	}
	ticketState := &types.PolicyTicket{
		ContractAddress: contract,
		UserAddress:     user,
		Digest:          digest,
		ExpiryHeight:    10,
		UsesRemaining:   1,
		Method:          "execute",
	}
	genesis := types.GenesisState{
		Params:          &params,
		Sponsors:        []*types.ContractSponsor{sponsorState},
		UserGrantUsages: []*types.UserGrantUsage{usageState},
		PolicyTickets:   []*types.PolicyTicket{ticketState},
	}

	sponsor.InitGenesis(ctx, k, genesis)

	require.Zero(t, sponsorState.Generation)
	require.Zero(t, usageState.Generation)
	require.Zero(t, ticketState.Generation)

	storedSponsor, found := k.GetSponsor(ctx, contract)
	require.True(t, found)
	require.Equal(t, uint64(1), storedSponsor.Generation)
	storedUsage := k.GetUserGrantUsage(ctx, user, contract)
	require.Equal(t, uint64(1), storedUsage.Generation)
	storedTicket, found := k.GetPolicyTicket(ctx, contract, user, digest)
	require.True(t, found)
	require.Equal(t, uint64(1), storedTicket.Generation)
}

func TestValidateGenesisRejectsAmbiguousOrOverflowingOrphanTickets(t *testing.T) {
	contract := sdk.AccAddress([]byte("orphan_gen_contract_")).String()
	user := sdk.AccAddress([]byte("orphan_gen_user_____")).String()
	params := types.DefaultParams()
	genesis := types.GenesisState{
		Params: &params,
		PolicyTickets: []*types.PolicyTicket{{
			ContractAddress: contract,
			UserAddress:     user,
			Digest:          "digest",
			UsesRemaining:   1,
			ExpiryHeight:    10,
		}},
	}

	require.Error(t, types.ValidateGenesis(genesis))

	genesis.PolicyTickets[0].Generation = math.MaxUint64
	require.Error(t, types.ValidateGenesis(genesis))

	genesis.ContractGenerations = []*types.ContractGeneration{{
		ContractAddress: contract,
		Generation:      math.MaxUint64,
	}}
	genesis.PolicyTickets[0].Generation = math.MaxUint64 - 1
	require.NoError(t, types.ValidateGenesis(genesis))

	genesis.PolicyTickets[0].Generation = math.MaxUint64
	require.Error(t, types.ValidateGenesis(genesis))
}
