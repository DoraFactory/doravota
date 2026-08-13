package keeper

import (
	sdkmath "cosmossdk.io/math"
	"math"
	"testing"

	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/stretchr/testify/require"

	"github.com/DoraFactory/doravota/x/sponsor-contract-tx/types"
)

func TestSponsorDeletionPermanentlyInvalidatesLifecycleState(t *testing.T) {
	k, ctx := setupKeeperSimple(t)
	const (
		contract = "contract"
		user     = "user"
		digest   = "digest"
	)

	require.NoError(t, k.SetSponsor(ctx, types.ContractSponsor{ContractAddress: contract}))
	firstSponsor, found := k.GetSponsor(ctx, contract)
	require.True(t, found)
	require.Equal(t, uint64(1), firstSponsor.Generation)

	oldTicket := types.PolicyTicket{
		ContractAddress: contract,
		UserAddress:     user,
		Digest:          digest,
		ExpiryHeight:    100,
		UsesRemaining:   1,
	}
	require.NoError(t, k.SetPolicyTicket(ctx, oldTicket))
	activeTicket, found := k.GetActivePolicyTicket(ctx, contract, user, digest)
	require.True(t, found)
	require.Equal(t, firstSponsor.Generation, activeTicket.Generation)

	oldUsage := types.UserGrantUsage{
		UserAddress:     user,
		ContractAddress: contract,
		TotalGrantUsed: []*sdk.Coin{
			{Denom: types.SponsorshipDenom, Amount: sdkmath.NewInt(25)},
		},
		Generation: firstSponsor.Generation,
	}
	require.NoError(t, k.SetUserGrantUsage(ctx, oldUsage))
	require.Equal(t, firstSponsor.Generation, k.GetUserGrantUsage(ctx, user, contract).Generation)

	require.NoError(t, k.DeleteSponsor(ctx, contract))
	require.Equal(t, uint64(2), k.GetSponsorGeneration(ctx, contract))

	// Deletion does not perform an unbounded scan. The historical ticket stays
	// in raw storage for GC, but is no longer active.
	storedTicket, found := k.GetPolicyTicket(ctx, contract, user, digest)
	require.True(t, found)
	require.Equal(t, firstSponsor.Generation, storedTicket.Generation)
	_, found = k.GetActivePolicyTicket(ctx, contract, user, digest)
	require.False(t, found)

	// Recreating the same contract uses the rotated generation. Neither ticket
	// authorization nor user quota consumption carries into the new lifecycle.
	require.NoError(t, k.SetSponsor(ctx, types.ContractSponsor{ContractAddress: contract}))
	secondSponsor, found := k.GetSponsor(ctx, contract)
	require.True(t, found)
	require.Equal(t, uint64(2), secondSponsor.Generation)

	_, found = k.GetActivePolicyTicket(ctx, contract, user, digest)
	require.False(t, found, "a ticket from a deleted lifecycle must never reactivate")
	require.Error(t, k.ConsumePolicyTicket(ctx, contract, user, digest))

	currentUsage := k.GetUserGrantUsage(ctx, user, contract)
	require.Equal(t, secondSponsor.Generation, currentUsage.Generation)
	require.Empty(t, currentUsage.TotalGrantUsed)
	require.Zero(t, currentUsage.LastUsedTime)
}

func TestDeleteSponsorDoesNotWrapGeneration(t *testing.T) {
	k, ctx := setupKeeperSimple(t)
	const contract = "contract"

	require.NoError(t, k.SetSponsorGenerationForGenesis(ctx, contract, math.MaxUint64))
	require.NoError(t, k.SetSponsor(ctx, types.ContractSponsor{
		ContractAddress: contract,
		Generation:      math.MaxUint64,
	}))

	require.Error(t, k.DeleteSponsor(ctx, contract))
	require.True(t, k.HasSponsor(ctx, contract))
	require.Equal(t, uint64(math.MaxUint64), k.GetSponsorGeneration(ctx, contract))
}

func TestIterateSponsorGenerationsRejectsMalformedState(t *testing.T) {
	for _, tc := range []struct {
		name  string
		value []byte
	}{
		{name: "wrong encoded length", value: []byte{1}},
		{name: "zero generation", value: make([]byte, 8)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			k, ctx := setupKeeperSimple(t)
			ctx.KVStore(k.storeKey).Set(
				types.GetSponsorGenerationKey("contract"),
				tc.value,
			)

			called := false
			err := k.IterateSponsorGenerations(ctx, func(string, uint64) bool {
				called = true
				return false
			})

			require.Error(t, err)
			require.Contains(t, err.Error(), "malformed sponsor generation")
			require.False(t, called)
		})
	}
}
