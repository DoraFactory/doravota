package keeper

import (
	"bytes"
	"testing"

	"github.com/DoraFactory/doravota/x/pqcauth/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/stretchr/testify/require"
)

func TestKeyHistoryRetentionBeyondDefaultPage(t *testing.T) {
	k, ctx := setupKeeper(t, 1000)
	owner := sdk.AccAddress(bytes.Repeat([]byte{0x73}, 20))
	params := types.DefaultParams()
	params.MaxRetainedKeyRecordsPerRole = 64
	require.NoError(t, k.SetParams(ctx, params))
	pub, _ := keyPair(99)
	for i := uint64(1); i <= 132; i++ {
		role := types.KeyRole_KEY_ROLE_SIGNING
		if i%2 == 0 {
			role = types.KeyRole_KEY_ROLE_RECOVERY
		}
		require.NoError(t, k.SetKey(ctx, owner, types.PQCKeyRecord{Owner: owner.String(), KeyId: i, Algorithm: types.Algorithm_ALGORITHM_ML_DSA_65, PublicKey: pub, Role: role, Status: types.KeyStatus_KEY_STATUS_LIVE, CreatedHeight: i, EffectiveHeight: i, InactiveFromHeight: i + 1}))
	}
	require.NoError(t, k.CompactTerminalKeyHistory(ctx, owner, types.AccountPolicy{Owner: owner.String()}, 64))
	counts := map[types.KeyRole]int{}
	k.IterateAllKeys(ctx, func(key types.PQCKeyRecord) bool { counts[key.Role]++; return false })
	require.Equal(t, 64, counts[types.KeyRole_KEY_ROLE_SIGNING], "all pages must be compacted")
	require.Equal(t, 64, counts[types.KeyRole_KEY_ROLE_RECOVERY])
	for _, role := range []types.KeyRole{types.KeyRole_KEY_ROLE_SIGNING, types.KeyRole_KEY_ROLE_RECOVERY} {
		history, found := k.GetKeyHistory(ctx, owner, role)
		require.True(t, found)
		require.Equal(t, uint64(2), history.CompactedCount)
	}
	// Lowering retention must also scan past the old first page.
	require.NoError(t, k.CompactTerminalKeyHistory(ctx, owner, types.AccountPolicy{Owner: owner.String()}, 16))
	counts = map[types.KeyRole]int{}
	k.IterateAllKeys(ctx, func(key types.PQCKeyRecord) bool { counts[key.Role]++; return false })
	for _, role := range []types.KeyRole{types.KeyRole_KEY_ROLE_SIGNING, types.KeyRole_KEY_ROLE_RECOVERY} {
		require.Equal(t, 16, counts[role])
		history, found := k.GetKeyHistory(ctx, owner, role)
		require.True(t, found)
		require.Equal(t, uint64(50), history.CompactedCount)
	}
}

func TestCancelledRecoveryHistoryDoesNotBlockLaterRotation(t *testing.T) {
	k, ctx := setupKeeper(t, 100)
	params := types.DefaultParams()
	require.NoError(t, k.SetParams(ctx, params))
	owner := sdk.AccAddress(bytes.Repeat([]byte{0x74}, 20))
	for id := uint64(1); id <= 2; id++ {
		pub, _ := keyPair(byte(id))
		role := types.KeyRole_KEY_ROLE_SIGNING
		if id == 2 {
			role = types.KeyRole_KEY_ROLE_RECOVERY
		}
		require.NoError(t, k.SetKey(ctx, owner, types.PQCKeyRecord{Owner: owner.String(), KeyId: id, Algorithm: types.Algorithm_ALGORITHM_ML_DSA_65, PublicKey: pub, Role: role, Status: types.KeyStatus_KEY_STATUS_LIVE, CreatedHeight: 1, EffectiveHeight: 2}))
	}
	require.NoError(t, k.SetAccountPolicy(ctx, owner, types.AccountPolicy{Owner: owner.String(), CurrentSigningKeyId: 1, RecoveryKeyId: 2, SelfEnforced: true, PolicyVersion: 1}))
	require.NoError(t, k.SetKeySequence(ctx, owner, types.AccountKeySequence{Owner: owner.String(), NextKeyId: 3}))
	server := NewMsgServer(k)
	var compacted []types.PQCKeyRecord
	for id := uint64(3); id <= 19; id++ {
		ctx = ctx.WithBlockHeight(100 + int64(id)*2)
		pub, _ := keyPair(byte(id))
		recover := &types.MsgRecoverKey{Owner: owner.String(), RecoveryKeyId: 2, RecoverySignature: make([]byte, 3309), ExpectedNewSigningKeyId: id, NewSigningAlgorithm: types.Algorithm_ALGORITHM_ML_DSA_65, NewSigningPublicKey: pub, NewSigningKeyProof: make([]byte, 3309), ExpectedRecoveryDelayBlocks: params.RecoveryDelayBlocks}
		_, err := server.RecoverKey(authorizedLifecycleContext(t, ctx, recover), recover)
		require.NoError(t, err)
		cancel := &types.MsgCancelRecovery{Owner: owner.String(), ExpectedPendingSigningKeyId: id, ExpectedPendingPolicyVersion: 2}
		_, err = server.CancelRecovery(authorizedLifecycleContext(t, ctx.WithBlockHeight(ctx.BlockHeight()+1), cancel), cancel)
		require.NoError(t, err)
		if id == 3 || id == 4 {
			key, found := k.GetKey(ctx, owner, id)
			require.True(t, found)
			compacted = append(compacted, key)
		}
	}
	history, ok := k.GetKeyHistory(ctx, owner, types.KeyRole_KEY_ROLE_SIGNING)
	require.True(t, ok)
	require.Equal(t, uint64(3), history.LastCompactedKeyId)
	require.Equal(t, uint64(1), history.CompactedCount)
	genesis := types.GenesisState{Params: params}
	k.IterateAllKeys(ctx, func(key types.PQCKeyRecord) bool { genesis.Keys = append(genesis.Keys, key); return false })
	k.IterateAllPolicies(ctx, func(policy types.AccountPolicy) bool {
		genesis.Policies = append(genesis.Policies, policy.Effective(ctx.BlockHeight()))
		return false
	})
	k.IterateAllSequences(ctx, func(sequence types.AccountKeySequence) bool {
		genesis.KeySequences = append(genesis.KeySequences, sequence)
		return false
	})
	k.IterateAllKeyHistories(ctx, func(h types.AccountKeyHistory) bool {
		genesis.KeyHistories = append(genesis.KeyHistories, h)
		return false
	})
	require.NoError(t, types.ValidateGenesis(genesis))
	require.Empty(t, k.AuditState(ctx, 100).Issues)
	for id := uint64(20); id <= 21; id++ {
		ctx = ctx.WithBlockHeight(200 + int64(id))
		pub, _ := keyPair(byte(id))
		rotate := &types.MsgRotateKey{Owner: owner.String(), ExpectedNewKeyId: id, NewAlgorithm: types.Algorithm_ALGORITHM_ML_DSA_65, NewPublicKey: pub, NewKeyProof: make([]byte, 3309)}
		cache, write := ctx.CacheContext()
		_, err := server.RotateKey(authorizedLifecycleContext(t, cache, rotate), rotate)
		require.NoError(t, err, "rotation to key %d after cancelled recoveries", id)
		write()
		if id == 20 {
			key, found := k.GetKey(ctx, owner, 1)
			require.True(t, found)
			compacted = append(compacted, key)
		}
	}

	// Once key 1 retires, it must be appended exactly once despite its lower ID.
	history, ok = k.GetKeyHistory(ctx, owner, types.KeyRole_KEY_ROLE_SIGNING)
	require.True(t, ok)
	require.Equal(t, uint64(3), history.CompactedCount)
	require.Equal(t, uint64(4), history.LastCompactedKeyId)
	var accumulator []byte
	for _, key := range compacted {
		var err error
		accumulator, err = types.AccumulateKeyHistory(accumulator, key)
		require.NoError(t, err)
	}
	require.Equal(t, accumulator, history.Accumulator, "append keys 3, 4, then the retired key 1")
	_, found := k.GetKey(ctx, owner, 1)
	require.False(t, found)
	policy, found := k.GetAccountPolicy(ctx, owner)
	require.True(t, found)
	require.NoError(t, k.CompactTerminalKeyHistory(ctx, owner, policy, params.MaxRetainedKeyRecordsPerRole))
	after, _ := k.GetKeyHistory(ctx, owner, types.KeyRole_KEY_ROLE_SIGNING)
	require.Equal(t, history, after, "repeated compaction must not append history twice")
	require.Empty(t, k.AuditState(ctx, 100).Issues)
}
