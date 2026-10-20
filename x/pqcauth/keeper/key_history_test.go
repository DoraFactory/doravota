package keeper

import (
	"bytes"
	"testing"

	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/stretchr/testify/require"

	"github.com/DoraFactory/doravota/x/pqcauth/types"
)

func TestCompactTerminalKeyHistoryRetainsRolesSeparatelyAndPinsPolicyKeys(t *testing.T) {
	moduleKeeper, ctx := setupKeeper(t, 100)
	owner := sdk.AccAddress(bytes.Repeat([]byte{0x71}, 20))
	policy := types.AccountPolicy{
		Owner:                  owner.String(),
		CurrentSigningKeyId:    1,
		RecoveryKeyId:          22,
		PendingSigningKeyId:    43,
		PendingRecoveryKeyId:   44,
		PendingEffectiveHeight: 101,
		PolicyVersion:          7,
		PendingPolicyVersion:   8,
	}

	putKey := func(key types.PQCKeyRecord) {
		require.NoError(t, moduleKeeper.SetKey(ctx, owner, key))
	}
	publicKey, _ := keyPair(70)
	putKey(types.PQCKeyRecord{
		Owner: owner.String(), KeyId: 1,
		Algorithm: types.Algorithm_ALGORITHM_ML_DSA_65, PublicKey: publicKey,
		Role: types.KeyRole_KEY_ROLE_SIGNING, Status: types.KeyStatus_KEY_STATUS_LIVE,
		EffectiveHeight: 1,
	})

	recoveryTerminal := make([]types.PQCKeyRecord, 0, 20)
	for keyID := uint64(2); keyID <= 21; keyID++ {
		keyBytes, _ := keyPair(byte(keyID))
		key := types.PQCKeyRecord{
			Owner: owner.String(), KeyId: keyID,
			Algorithm: types.Algorithm_ALGORITHM_ML_DSA_65, PublicKey: keyBytes,
			Role: types.KeyRole_KEY_ROLE_RECOVERY, Status: types.KeyStatus_KEY_STATUS_LIVE,
			EffectiveHeight: 1, InactiveFromHeight: 50,
		}
		recoveryTerminal = append(recoveryTerminal, key)
		putKey(key)
	}
	currentRecovery, _ := keyPair(22)
	putKey(types.PQCKeyRecord{
		Owner: owner.String(), KeyId: 22,
		Algorithm: types.Algorithm_ALGORITHM_ML_DSA_65, PublicKey: currentRecovery,
		Role: types.KeyRole_KEY_ROLE_RECOVERY, Status: types.KeyStatus_KEY_STATUS_LIVE,
		EffectiveHeight: 1,
	})

	signingTerminal := make([]types.PQCKeyRecord, 0, 20)
	for keyID := uint64(23); keyID <= 42; keyID++ {
		keyBytes, _ := keyPair(byte(keyID))
		key := types.PQCKeyRecord{
			Owner: owner.String(), KeyId: keyID,
			Algorithm: types.Algorithm_ALGORITHM_ML_DSA_65, PublicKey: keyBytes,
			Role: types.KeyRole_KEY_ROLE_SIGNING, Status: types.KeyStatus_KEY_STATUS_LIVE,
			EffectiveHeight: 1, InactiveFromHeight: 50,
		}
		signingTerminal = append(signingTerminal, key)
		putKey(key)
	}
	pendingSigning, _ := keyPair(43)
	putKey(types.PQCKeyRecord{
		Owner: owner.String(), KeyId: 43,
		Algorithm: types.Algorithm_ALGORITHM_ML_DSA_65, PublicKey: pendingSigning,
		Role: types.KeyRole_KEY_ROLE_SIGNING, Status: types.KeyStatus_KEY_STATUS_LIVE,
		EffectiveHeight: 101,
	})
	pendingRecovery, _ := keyPair(44)
	putKey(types.PQCKeyRecord{
		Owner: owner.String(), KeyId: 44,
		Algorithm: types.Algorithm_ALGORITHM_ML_DSA_65, PublicKey: pendingRecovery,
		Role: types.KeyRole_KEY_ROLE_RECOVERY, Status: types.KeyStatus_KEY_STATUS_LIVE,
		EffectiveHeight: 101,
	})

	require.NoError(t, moduleKeeper.CompactTerminalKeyHistory(ctx, owner, policy, 2))

	for _, keyID := range []uint64{1, 21, 22, 42, 43, 44} {
		_, found := moduleKeeper.GetKey(ctx, owner, keyID)
		require.Truef(t, found, "key %d must be retained", keyID)
	}
	for keyID := uint64(2); keyID <= 20; keyID++ {
		_, found := moduleKeeper.GetKey(ctx, owner, keyID)
		require.Falsef(t, found, "terminal recovery key %d should be compacted", keyID)
	}
	for keyID := uint64(23); keyID <= 41; keyID++ {
		_, found := moduleKeeper.GetKey(ctx, owner, keyID)
		require.Falsef(t, found, "terminal signing key %d should be compacted", keyID)
	}

	recoveryHistory, found := moduleKeeper.GetKeyHistory(
		ctx,
		owner,
		types.KeyRole_KEY_ROLE_RECOVERY,
	)
	require.True(t, found)
	require.Equal(t, uint64(19), recoveryHistory.CompactedCount)
	require.Equal(t, uint64(20), recoveryHistory.LastCompactedKeyId)
	require.Equal(t, accumulateHistory(t, recoveryTerminal[:19]), recoveryHistory.Accumulator)

	signingHistory, found := moduleKeeper.GetKeyHistory(
		ctx,
		owner,
		types.KeyRole_KEY_ROLE_SIGNING,
	)
	require.True(t, found)
	require.Equal(t, uint64(19), signingHistory.CompactedCount)
	require.Equal(t, uint64(41), signingHistory.LastCompactedKeyId)
	require.Equal(t, accumulateHistory(t, signingTerminal[:19]), signingHistory.Accumulator)

	// Re-running compaction is idempotent and cannot consume a pinned key.
	require.NoError(t, moduleKeeper.CompactTerminalKeyHistory(ctx, owner, policy, 2))
	require.Equal(t, recoveryHistory, mustHistory(t, moduleKeeper, ctx, owner, types.KeyRole_KEY_ROLE_RECOVERY))
	require.Equal(t, signingHistory, mustHistory(t, moduleKeeper, ctx, owner, types.KeyRole_KEY_ROLE_SIGNING))
}

func TestCompactTerminalKeyHistoryNeverDeletesCurrentSigningDuringRecoveryChurn(t *testing.T) {
	moduleKeeper, ctx := setupKeeper(t, 200)
	owner := sdk.AccAddress(bytes.Repeat([]byte{0x72}, 20))
	currentSigning, _ := keyPair(1)
	require.NoError(t, moduleKeeper.SetKey(ctx, owner, types.PQCKeyRecord{
		Owner: owner.String(), KeyId: 1,
		Algorithm: types.Algorithm_ALGORITHM_ML_DSA_65, PublicKey: currentSigning,
		Role: types.KeyRole_KEY_ROLE_SIGNING, Status: types.KeyStatus_KEY_STATUS_LIVE,
		EffectiveHeight: 1,
	}))
	for keyID := uint64(2); keyID <= 101; keyID++ {
		keyBytes, _ := keyPair(byte(keyID))
		inactive := uint64(100)
		if keyID == 101 {
			inactive = 0
		}
		require.NoError(t, moduleKeeper.SetKey(ctx, owner, types.PQCKeyRecord{
			Owner: owner.String(), KeyId: keyID,
			Algorithm: types.Algorithm_ALGORITHM_ML_DSA_65, PublicKey: keyBytes,
			Role: types.KeyRole_KEY_ROLE_RECOVERY, Status: types.KeyStatus_KEY_STATUS_LIVE,
			EffectiveHeight: 1, InactiveFromHeight: inactive,
		}))
	}
	policy := types.AccountPolicy{
		Owner: owner.String(), CurrentSigningKeyId: 1, RecoveryKeyId: 101, PolicyVersion: 100,
	}
	require.NoError(t, moduleKeeper.CompactTerminalKeyHistory(ctx, owner, policy, 16))
	_, signingFound := moduleKeeper.GetKey(ctx, owner, 1)
	_, recoveryFound := moduleKeeper.GetKey(ctx, owner, 101)
	require.True(t, signingFound)
	require.True(t, recoveryFound)
	history := mustHistory(t, moduleKeeper, ctx, owner, types.KeyRole_KEY_ROLE_RECOVERY)
	require.Equal(t, uint64(83), history.CompactedCount)
	for keyID := uint64(85); keyID <= 100; keyID++ {
		_, found := moduleKeeper.GetKey(ctx, owner, keyID)
		require.Truef(t, found, "most recent recovery history key %d must remain", keyID)
	}
}

func accumulateHistory(t testing.TB, records []types.PQCKeyRecord) []byte {
	t.Helper()
	var accumulator []byte
	for _, record := range records {
		var err error
		accumulator, err = types.AccumulateKeyHistory(accumulator, record)
		require.NoError(t, err)
	}
	return accumulator
}

func mustHistory(
	t testing.TB,
	moduleKeeper Keeper,
	ctx sdk.Context,
	owner sdk.AccAddress,
	role types.KeyRole,
) types.AccountKeyHistory {
	t.Helper()
	history, found := moduleKeeper.GetKeyHistory(ctx, owner, role)
	require.True(t, found)
	return history
}
