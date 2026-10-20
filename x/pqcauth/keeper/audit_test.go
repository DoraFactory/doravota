package keeper

import (
	"bytes"
	"testing"

	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/stretchr/testify/require"

	"github.com/DoraFactory/doravota/x/pqcauth/types"
)

func seedAuditableState(t testing.TB, moduleKeeper Keeper, ctx sdk.Context) sdk.AccAddress {
	t.Helper()
	require.NoError(t, moduleKeeper.SetParams(ctx, types.DefaultParams()))
	owner := sdk.AccAddress(bytes.Repeat([]byte{0x71}, 20))
	signing, _ := keyPair(71)
	recovery, _ := keyPair(72)
	for _, key := range []types.PQCKeyRecord{
		{
			Owner:           owner.String(),
			KeyId:           1,
			Algorithm:       types.Algorithm_ALGORITHM_ML_DSA_65,
			PublicKey:       signing,
			Role:            types.KeyRole_KEY_ROLE_SIGNING,
			Status:          types.KeyStatus_KEY_STATUS_LIVE,
			EffectiveHeight: 1,
		},
		{
			Owner:           owner.String(),
			KeyId:           2,
			Algorithm:       types.Algorithm_ALGORITHM_ML_DSA_65,
			PublicKey:       recovery,
			Role:            types.KeyRole_KEY_ROLE_RECOVERY,
			Status:          types.KeyStatus_KEY_STATUS_LIVE,
			EffectiveHeight: 1,
		},
	} {
		require.NoError(t, moduleKeeper.SetKey(ctx, owner, key))
	}
	require.NoError(t, moduleKeeper.SetAccountPolicy(ctx, owner, types.AccountPolicy{
		Owner:               owner.String(),
		CurrentSigningKeyId: 1,
		RecoveryKeyId:       2,
		SelfEnforced:        true,
		PolicyVersion:       1,
	}))
	require.NoError(t, moduleKeeper.SetKeySequence(ctx, owner, types.AccountKeySequence{
		Owner:     owner.String(),
		NextKeyId: 3,
	}))
	return owner
}

func TestAuditStateReportsConsistentCounts(t *testing.T) {
	moduleKeeper, ctx := setupKeeper(t, 10)
	seedAuditableState(t, moduleKeeper, ctx)

	report := moduleKeeper.AuditState(ctx, 100)
	require.True(t, report.Consistent)
	require.Equal(t, uint64(2), report.Keys)
	require.Equal(t, uint64(1), report.Policies)
	require.Equal(t, uint64(1), report.KeySequences)
}

func TestAuditStateRequiresPolicyAndSequenceForCommittedOwners(t *testing.T) {
	moduleKeeper, ctx := setupKeeper(t, 10)
	owner := seedAuditableState(t, moduleKeeper, ctx)
	ctx.KVStore(moduleKeeper.storeKey).Delete(types.AccountSequenceKey(owner))

	report := moduleKeeper.AuditState(ctx, 100)
	require.False(t, report.Consistent)
	require.ErrorIs(t, report.Error(), types.ErrInconsistentState)
	require.Contains(t, auditIssueCodes(report), "missing_key_sequence")

	ctx.KVStore(moduleKeeper.storeKey).Delete(types.AccountPolicyKey(owner))
	report = moduleKeeper.AuditState(ctx, 100)
	require.False(t, report.Consistent)
	require.Contains(t, auditIssueCodes(report), "missing_policy")
}

func TestAuditStateHandlesCorruptProtobufWithoutPanicking(t *testing.T) {
	moduleKeeper, ctx := setupKeeper(t, 10)
	ctx.KVStore(moduleKeeper.storeKey).Set(types.ParamsKey, []byte{0xff})

	require.NotPanics(t, func() {
		report := moduleKeeper.AuditState(ctx, 100)
		require.False(t, report.Consistent)
		require.Equal(t, "params_decode_failure", report.Issues[0].Code)
	})
}

func TestAuditStateDetectsStorageKeyMismatchAndUnknownRecord(t *testing.T) {
	moduleKeeper, ctx := setupKeeper(t, 10)
	owner := seedAuditableState(t, moduleKeeper, ctx)
	policy, found := moduleKeeper.GetAccountPolicy(ctx, owner)
	require.True(t, found)
	encoded, err := moduleKeeper.cdc.Marshal(&policy)
	require.NoError(t, err)
	wrongOwner := sdk.AccAddress(bytes.Repeat([]byte{0x72}, 20))
	ctx.KVStore(moduleKeeper.storeKey).Set(types.AccountPolicyKey(wrongOwner), encoded)
	ctx.KVStore(moduleKeeper.storeKey).Set([]byte{0x7f, 0x01}, []byte{0x01})

	report := moduleKeeper.AuditState(ctx, 100)
	require.False(t, report.Consistent)
	codes := auditIssueCodes(report)
	require.True(t, codes["storage_key_mismatch"])
	require.True(t, codes["unknown_storage_key"])
}

func auditIssueCodes(report types.StateAuditReport) map[string]bool {
	codes := make(map[string]bool, len(report.Issues))
	for _, issue := range report.Issues {
		codes[issue.Code] = true
	}
	return codes
}
