package keeper

import (
	"fmt"
	"sort"

	sdk "github.com/cosmos/cosmos-sdk/types"

	"github.com/DoraFactory/doravota/x/pqcauth/types"
)

// CompactTerminalKeyHistory retains a bounded number of complete, terminal key
// records per role. Every key referenced by the current or pending policy is
// pinned regardless of age and never counts toward the retention limit.
func (k Keeper) CompactTerminalKeyHistory(
	ctx sdk.Context,
	owner sdk.AccAddress,
	policy types.AccountPolicy,
	retainPerRole uint32,
) error {
	if retainPerRole == 0 {
		return fmt.Errorf("%w: terminal key retention must be positive", types.ErrInvalidParams)
	}
	pinned := map[uint64]struct{}{}
	for _, keyID := range []uint64{
		policy.CurrentSigningKeyId,
		policy.PendingSigningKeyId,
		policy.RecoveryKeyId,
		policy.PendingRecoveryKeyId,
	} {
		if keyID != 0 {
			pinned[keyID] = struct{}{}
		}
	}

	terminal := map[types.KeyRole][]types.PQCKeyRecord{
		types.KeyRole_KEY_ROLE_SIGNING:  nil,
		types.KeyRole_KEY_ROLE_RECOVERY: nil,
	}
	keys, _, err := k.GetKeysPaginated(ctx, owner, nil)
	if err != nil {
		return err
	}
	for _, key := range keys {
		if _, protected := pinned[key.KeyId]; protected || !terminalAtHeight(key, ctx.BlockHeight()) {
			continue
		}
		if key.Role != types.KeyRole_KEY_ROLE_SIGNING && key.Role != types.KeyRole_KEY_ROLE_RECOVERY {
			return fmt.Errorf("%w: invalid terminal key role %d", types.ErrInvalidKey, key.Role)
		}
		terminal[key.Role] = append(terminal[key.Role], key)
	}

	for _, role := range []types.KeyRole{
		types.KeyRole_KEY_ROLE_SIGNING,
		types.KeyRole_KEY_ROLE_RECOVERY,
	} {
		records := terminal[role]
		retentionTarget := retainPerRole
		// A rotation's current key remains active until H+1 and is therefore
		// pinned today, but becomes terminal as soon as the pending policy
		// activates. Reserve its history slot now so the retained set cannot
		// exceed the configured bound between lifecycle transactions.
		if roleWillRetireAtPendingActivation(policy, role, ctx.BlockHeight()) {
			retentionTarget--
		}
		if uint32(len(records)) <= retentionTarget {
			continue
		}
		sort.Slice(records, func(i, j int) bool { return records[i].KeyId < records[j].KeyId })
		compact := records[:len(records)-int(retentionTarget)]
		history, found := k.GetKeyHistory(ctx, owner, role)
		if !found {
			history = types.AccountKeyHistory{Owner: owner.String(), Role: role}
		}
		for _, key := range compact {
			if key.KeyId <= history.LastCompactedKeyId {
				return fmt.Errorf(
					"%w: key history is not monotonic for %s/%s/%d",
					types.ErrInconsistentState,
					owner.String(),
					role,
					key.KeyId,
				)
			}
			accumulator, err := types.AccumulateKeyHistory(history.Accumulator, key)
			if err != nil {
				return err
			}
			history.Accumulator = accumulator
			history.CompactedCount++
			if history.CompactedCount == 0 {
				return types.ErrInconsistentState.Wrap("key history count overflow")
			}
			history.LastCompactedKeyId = key.KeyId
		}
		if err := k.SetKeyHistory(ctx, owner, history); err != nil {
			return err
		}
		for _, key := range compact {
			k.DeleteKey(ctx, owner, key.KeyId)
		}
	}
	return nil
}

func roleWillRetireAtPendingActivation(
	policy types.AccountPolicy,
	role types.KeyRole,
	height int64,
) bool {
	if policy.PendingEffectiveHeight == 0 ||
		height < 0 ||
		uint64(height) >= policy.PendingEffectiveHeight {
		return false
	}
	switch role {
	case types.KeyRole_KEY_ROLE_SIGNING:
		return policy.CurrentSigningKeyId != 0 &&
			policy.PendingSigningKeyId != 0 &&
			policy.PendingSigningKeyId != policy.CurrentSigningKeyId
	case types.KeyRole_KEY_ROLE_RECOVERY:
		return policy.RecoveryKeyId != 0 &&
			policy.PendingRecoveryKeyId != 0 &&
			policy.PendingRecoveryKeyId != policy.RecoveryKeyId
	default:
		return false
	}
}

func terminalAtHeight(key types.PQCKeyRecord, height int64) bool {
	if key.Status == types.KeyStatus_KEY_STATUS_REVOKED {
		return true
	}
	return height >= 0 &&
		key.InactiveFromHeight != 0 &&
		uint64(height) >= key.InactiveFromHeight
}
