package keeper

import (
	"testing"

	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/cosmos/cosmos-sdk/types/address"
	"github.com/stretchr/testify/require"

	"github.com/DoraFactory/doravota/x/sponsor-contract-tx/types"
)

func activeSponsorFixture(contract, admin string) types.ContractSponsor {
	contractAddress, err := sdk.AccAddressFromBech32(contract)
	if err != nil {
		panic(err)
	}
	return types.ContractSponsor{
		ContractAddress: contract,
		CreatorAddress:  admin,
		SponsorAddress: sdk.AccAddress(
			address.Derive(contractAddress, []byte("sponsor")),
		).String(),
		IsSponsored: true,
		MaxGrantPerUser: []*sdk.Coin{
			{
				Denom:  types.SponsorshipDenom,
				Amount: sdk.NewInt(1_000_000),
			},
		},
	}
}

func TestSetActiveSponsorValidatesStateAndWasmDependency(t *testing.T) {
	k, ctx, wasmKeeper := setupKeeper(t)
	contract := sdk.AccAddress([]byte("validated_contract__")).String()
	admin := sdk.AccAddress([]byte("validated_admin_____")).String()
	sponsor := activeSponsorFixture(contract, admin)

	require.Error(t, k.SetActiveSponsor(ctx, sponsor))
	require.False(t, k.HasSponsor(ctx, contract))

	wasmKeeper.SetContractInfo(contract, admin)
	invalid := sponsor
	invalid.SponsorAddress = admin
	require.Error(t, k.SetActiveSponsor(ctx, invalid))
	require.False(t, k.HasSponsor(ctx, contract))

	invalid = sponsor
	invalid.Generation = 2
	require.Error(t, k.SetActiveSponsor(ctx, invalid))
	require.Equal(t, uint64(0), k.GetSponsorGeneration(ctx, contract))

	require.NoError(t, k.SetActiveSponsor(ctx, sponsor))
	stored, found := k.GetSponsor(ctx, contract)
	require.True(t, found)
	require.Equal(t, uint64(1), stored.Generation)
	require.Equal(t, stored.Generation, k.GetSponsorGeneration(ctx, contract))
}

func TestActiveAndGenesisTicketLifecycleValidation(t *testing.T) {
	k, ctx, wasmKeeper := setupKeeper(t)
	contract := sdk.AccAddress([]byte("ticket_contract_____")).String()
	admin := sdk.AccAddress([]byte("ticket_admin________")).String()
	user := sdk.AccAddress([]byte("ticket_user_________")).String()
	wasmKeeper.SetContractInfo(contract, admin)
	require.NoError(t, k.SetActiveSponsor(ctx, activeSponsorFixture(contract, admin)))

	method := "execute"
	digest := k.ComputeMethodDigestSingle(contract, method)
	ticket := types.PolicyTicket{
		ContractAddress: contract,
		UserAddress:     user,
		Digest:          digest,
		ExpiryHeight:    10,
		UsesRemaining:   1,
		Method:          method,
	}
	require.NoError(t, k.SetActivePolicyTicket(ctx, ticket))
	stored, found := k.GetPolicyTicket(ctx, contract, user, digest)
	require.True(t, found)
	require.Equal(t, uint64(1), stored.Generation)

	badDigest := ticket
	badDigest.Digest = "wrong"
	require.Error(t, k.SetActivePolicyTicket(ctx, badDigest))

	badGeneration := ticket
	badGeneration.Generation = 2
	require.Error(t, k.SetActivePolicyTicket(ctx, badGeneration))

	badUses := ticket
	badUses.Consumed = true
	require.Error(t, k.SetActivePolicyTicket(ctx, badUses))

	require.NoError(t, k.DeleteSponsor(ctx, contract))
	require.Equal(t, uint64(2), k.GetSponsorGeneration(ctx, contract))
	require.Error(t, k.SetActivePolicyTicket(ctx, ticket))

	historical := ticket
	historical.Generation = 1
	require.NoError(t, k.SetPolicyTicketForGenesis(ctx, historical))
	historical.Generation = 2
	require.Error(t, k.SetPolicyTicketForGenesis(ctx, historical))
}

func TestActiveAndGenesisUsageLifecycleValidation(t *testing.T) {
	k, ctx, wasmKeeper := setupKeeper(t)
	contract := sdk.AccAddress([]byte("usage_contract______")).String()
	admin := sdk.AccAddress([]byte("usage_admin_________")).String()
	user := sdk.AccAddress([]byte("usage_user__________")).String()
	wasmKeeper.SetContractInfo(contract, admin)
	require.NoError(t, k.SetActiveSponsor(ctx, activeSponsorFixture(contract, admin)))

	usage := types.UserGrantUsage{
		ContractAddress: contract,
		UserAddress:     user,
		TotalGrantUsed: []*sdk.Coin{
			{
				Denom:  types.SponsorshipDenom,
				Amount: sdk.NewInt(100),
			},
		},
	}
	require.NoError(t, k.SetActiveUserGrantUsage(ctx, usage))
	stored := k.GetUserGrantUsage(ctx, user, contract)
	require.Equal(t, uint64(1), stored.Generation)

	badGeneration := usage
	badGeneration.Generation = 2
	require.Error(t, k.SetActiveUserGrantUsage(ctx, badGeneration))

	require.NoError(t, k.DeleteSponsor(ctx, contract))
	require.Error(t, k.SetActiveUserGrantUsage(ctx, usage))

	historical := usage
	historical.Generation = 1
	require.NoError(t, k.SetUserGrantUsageForGenesis(ctx, historical))
	historical.Generation = 2
	require.Error(t, k.SetUserGrantUsageForGenesis(ctx, historical))
}

func TestSetParamsRejectsInvalidStateWithoutOverwriting(t *testing.T) {
	k, ctx := setupKeeperSimple(t)
	valid := types.DefaultParams()
	require.NoError(t, k.SetParams(ctx, valid))

	invalid := valid
	invalid.PolicyTicketTtlBlocks = 0
	require.Error(t, k.SetParams(ctx, invalid))
	require.Equal(t, valid, k.GetParams(ctx))
}
