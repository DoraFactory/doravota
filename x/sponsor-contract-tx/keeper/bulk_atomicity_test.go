package keeper

import (
	"testing"

	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/stretchr/testify/require"

	"github.com/DoraFactory/doravota/x/sponsor-contract-tx/types"
)

func TestConsumePolicyTicketsBulk_ValidationOrderIsDeterministic(t *testing.T) {
	k, ctx := setupKeeperSimple(t)

	err := k.ConsumePolicyTicketsBulk(ctx, "contract", "user", map[string]uint32{
		"z-missing": 1,
		"a-missing": 1,
	})
	require.Error(t, err)
	require.ErrorContains(t, err, "a-missing")
}

func TestConsumePolicyTicketsBulk_ApplyFailureIsAtomic(t *testing.T) {
	k, ctx, wasmKeeper := setupKeeper(t)
	contract := sdk.AccAddress([]byte("bulk_contract_______")).String()
	admin := sdk.AccAddress([]byte("bulk_admin__________")).String()
	user := sdk.AccAddress([]byte("bulk_user___________")).String()
	wasmKeeper.SetContractInfo(contract, admin)
	require.NoError(t, k.SetActiveSponsor(ctx, activeSponsorFixture(contract, admin)))

	validDigest := "a-valid"
	invalidDigest := "z-invalid"
	require.NoError(t, k.SetPolicyTicket(ctx, types.PolicyTicket{
		ContractAddress: contract,
		UserAddress:     user,
		Digest:          validDigest,
		ExpiryHeight:    10,
		UsesRemaining:   2,
	}))
	// The low-level setter intentionally permits legacy/corrupt fixtures. The
	// method/digest mismatch is detected only by the strict apply-time setter.
	require.NoError(t, k.SetPolicyTicket(ctx, types.PolicyTicket{
		ContractAddress: contract,
		UserAddress:     user,
		Digest:          invalidDigest,
		ExpiryHeight:    10,
		UsesRemaining:   2,
		Method:          "execute",
	}))

	err := k.ConsumePolicyTicketsBulk(ctx, contract, user, map[string]uint32{
		validDigest:   1,
		invalidDigest: 1,
	})
	require.Error(t, err)

	validTicket, found := k.GetPolicyTicket(ctx, contract, user, validDigest)
	require.True(t, found)
	require.Equal(t, uint32(2), validTicket.UsesRemaining)
	require.False(t, validTicket.Consumed)

	invalidTicket, found := k.GetPolicyTicket(ctx, contract, user, invalidDigest)
	require.True(t, found)
	require.Equal(t, uint32(2), invalidTicket.UsesRemaining)
	require.False(t, invalidTicket.Consumed)
}
