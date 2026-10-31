package keeper

import (
	"bytes"
	"testing"

	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/stretchr/testify/require"

	"github.com/DoraFactory/doravota/x/pqcauth/types"
)

type invariantRegistryStub struct {
	moduleName string
	route      string
	invariant  sdk.Invariant
}

func (r *invariantRegistryStub) RegisterRoute(
	moduleName string,
	route string,
	invariant sdk.Invariant,
) {
	r.moduleName = moduleName
	r.route = route
	r.invariant = invariant
}

func TestRegisterInvariantsRegistersStateConsistencyRoute(t *testing.T) {
	moduleKeeper, ctx := setupKeeper(t, 10)
	require.NoError(t, moduleKeeper.SetParams(ctx, types.DefaultParams()))
	registry := &invariantRegistryStub{}

	RegisterInvariants(registry, moduleKeeper)

	require.Equal(t, types.ModuleName, registry.moduleName)
	require.Equal(t, stateInvariantRoute, registry.route)
	require.NotNil(t, registry.invariant)
	message, broken := registry.invariant(ctx)
	require.False(t, broken)
	require.Contains(t, message, "state is consistent")
}

func TestStateInvariantDetectsMissingPendingRecoveryKey(t *testing.T) {
	moduleKeeper, ctx := setupKeeper(t, 10)
	require.NoError(t, moduleKeeper.SetParams(ctx, types.DefaultParams()))
	owner := sdk.AccAddress(bytes.Repeat([]byte{0x57}, 20))
	publicKey, _ := keyPair(10)
	require.NoError(t, moduleKeeper.SetKey(ctx, owner, types.PQCKeyRecord{
		Owner:           owner.String(),
		KeyId:           1,
		Algorithm:       types.Algorithm_ALGORITHM_ML_DSA_65,
		PublicKey:       publicKey,
		Role:            types.KeyRole_KEY_ROLE_SIGNING,
		Status:          types.KeyStatus_KEY_STATUS_LIVE,
		EffectiveHeight: 1,
	}))
	require.NoError(t, moduleKeeper.SetAccountPolicy(ctx, owner, types.AccountPolicy{
		Owner:                  owner.String(),
		CurrentSigningKeyId:    1,
		PendingSigningKeyId:    1,
		PendingEffectiveHeight: 11,
		PolicyVersion:          1,
		PendingPolicyVersion:   2,
		PendingRecoveryKeyId:   2,
		PendingSelfEnforced:    true,
	}))
	require.NoError(t, moduleKeeper.SetKeySequence(ctx, owner, types.AccountKeySequence{
		Owner:     owner.String(),
		NextKeyId: 2,
	}))

	message, broken := StateInvariant(moduleKeeper)(ctx)
	require.True(t, broken)
	require.Contains(t, message, "pending recovery key missing")
}
