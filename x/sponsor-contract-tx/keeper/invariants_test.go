package keeper

import (
	"testing"

	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/cosmos/cosmos-sdk/types/address"
	"github.com/stretchr/testify/require"

	"github.com/DoraFactory/doravota/x/sponsor-contract-tx/types"
)

type invariantRegistryRecorder struct {
	routes map[string]sdk.Invariant
}

func (r *invariantRegistryRecorder) RegisterRoute(moduleName, route string, invariant sdk.Invariant) {
	if r.routes == nil {
		r.routes = make(map[string]sdk.Invariant)
	}
	r.routes[moduleName+"/"+route] = invariant
}

func TestRegisterInvariants(t *testing.T) {
	k, _ := setupKeeperSimple(t)
	registry := &invariantRegistryRecorder{}

	RegisterInvariants(registry, k)

	require.Contains(t, registry.routes, types.ModuleName+"/"+LifecycleInvariantRoute)
	require.Contains(t, registry.routes, types.ModuleName+"/"+ParamsInvariantRoute)
}

func TestLifecycleInvariant(t *testing.T) {
	k, ctx, wasmKeeper := setupKeeper(t)
	contract := sdk.AccAddress([]byte("invariant_contract__")).String()
	admin := sdk.AccAddress([]byte("invariant_admin_____")).String()
	user := sdk.AccAddress([]byte("invariant_user______")).String()
	wasmKeeper.SetContractInfo(contract, admin)
	contractAddress, err := sdk.AccAddressFromBech32(contract)
	require.NoError(t, err)
	sponsor := types.ContractSponsor{
		ContractAddress: contract,
		CreatorAddress:  admin,
		SponsorAddress: sdk.AccAddress(
			address.Derive(contractAddress, []byte("sponsor")),
		).String(),
	}
	require.NoError(t, k.SetSponsor(ctx, sponsor))
	current, found := k.GetSponsor(ctx, sponsor.ContractAddress)
	require.True(t, found)

	require.NoError(t, k.SetPolicyTicket(ctx, types.PolicyTicket{
		ContractAddress: sponsor.ContractAddress,
		UserAddress:     user,
		Digest:          "digest",
		ExpiryHeight:    100,
		UsesRemaining:   1,
	}))
	require.NoError(t, k.SetUserGrantUsage(ctx, types.UserGrantUsage{
		ContractAddress: sponsor.ContractAddress,
		UserAddress:     user,
		Generation:      current.Generation,
	}))

	_, broken := LifecycleInvariant(k)(ctx)
	require.False(t, broken)

	wasmKeeper.SetContractInfo(contract, "")
	message, broken := LifecycleInvariant(k)(ctx)
	require.True(t, broken)
	require.Contains(t, message, "has no wasm contract admin")

	wasmKeeper.SetContractInfo(contract, admin)
	ctx.KVStore(k.storeKey).Set(
		types.GetSponsorGenerationKey(sponsor.ContractAddress),
		types.EncodeUint64BigEndian(current.Generation+1),
	)
	message, broken = LifecycleInvariant(k)(ctx)
	require.True(t, broken)
	require.Contains(t, message, "generation mismatch")
}

func TestParamsInvariant(t *testing.T) {
	k, ctx := setupKeeperSimple(t)
	require.NoError(t, k.SetParams(ctx, types.DefaultParams()))
	_, broken := ParamsInvariant(k)(ctx)
	require.False(t, broken)

	params := types.DefaultParams()
	params.MaxExecMsgsPerTxForSponsor = 0
	require.Error(t, k.SetParams(ctx, params))
	bz, err := k.cdc.Marshal(&params)
	require.NoError(t, err)
	ctx.KVStore(k.storeKey).Set(types.ParamsKey, bz)
	message, broken := ParamsInvariant(k)(ctx)
	require.True(t, broken)
	require.Contains(t, message, "max_exec_msgs_per_tx_for_sponsor")
}
