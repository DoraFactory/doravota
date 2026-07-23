package keeper

import (
	"testing"

	sdk "github.com/cosmos/cosmos-sdk/types"
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
	k, ctx := setupKeeperSimple(t)
	sponsor := types.ContractSponsor{ContractAddress: "contract"}
	require.NoError(t, k.SetSponsor(ctx, sponsor))
	current, found := k.GetSponsor(ctx, sponsor.ContractAddress)
	require.True(t, found)

	require.NoError(t, k.SetPolicyTicket(ctx, types.PolicyTicket{
		ContractAddress: sponsor.ContractAddress,
		UserAddress:     "user",
		Digest:          "digest",
		ExpiryHeight:    100,
		UsesRemaining:   1,
	}))
	require.NoError(t, k.SetUserGrantUsage(ctx, types.UserGrantUsage{
		ContractAddress: sponsor.ContractAddress,
		UserAddress:     "user",
		Generation:      current.Generation,
	}))

	_, broken := LifecycleInvariant(k)(ctx)
	require.False(t, broken)

	ctx.KVStore(k.storeKey).Set(
		types.GetSponsorGenerationKey(sponsor.ContractAddress),
		types.EncodeUint64BigEndian(current.Generation+1),
	)
	message, broken := LifecycleInvariant(k)(ctx)
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
	require.NoError(t, k.SetParams(ctx, params))
	message, broken := ParamsInvariant(k)(ctx)
	require.True(t, broken)
	require.Contains(t, message, "max_exec_msgs_per_tx_for_sponsor")
}
