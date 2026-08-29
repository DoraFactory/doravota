package keeper

import (
	"bytes"
	"fmt"
	"sort"

	sdk "github.com/cosmos/cosmos-sdk/types"

	"github.com/DoraFactory/doravota/x/pqcauth/types"
)

// AuditState inspects raw committed module records without using the ordinary
// getters, which deliberately panic on corrupt protobuf state. This path is
// therefore suitable for pre-upgrade diagnostics and invariant reporting.
func (k Keeper) AuditState(
	ctx sdk.Context,
	maxIssues uint32,
) types.StateAuditReport {
	maxIssues = types.NormalizeStateAuditMaxIssues(maxIssues)
	report := types.NewStateAuditReport(ctx.BlockHeight())
	genesis := types.GenesisState{Params: types.DefaultParams()}
	owners := make(map[string]struct{})

	store := ctx.KVStore(k.storeKey)
	iterator := store.Iterator(nil, nil)
	defer iterator.Close()

	for ; iterator.Valid(); iterator.Next() {
		storageKey := append([]byte(nil), iterator.Key()...)
		value := iterator.Value()
		if len(storageKey) == 0 {
			report.AddIssue(maxIssues, "empty_storage_key", "", "module store contains an empty key")
			continue
		}

		switch storageKey[0] {
		case types.ParamsKey[0]:
			if !bytes.Equal(storageKey, types.ParamsKey) {
				report.AddIssue(maxIssues, "unknown_storage_key", "", fmt.Sprintf("unknown key %X", storageKey))
				continue
			}
			if err := k.cdc.Unmarshal(value, &genesis.Params); err != nil {
				report.AddIssue(maxIssues, "params_decode_failure", "", err.Error())
				genesis.Params = types.DefaultParams()
			}

		case types.AccountPolicyKeyPrefix[0]:
			report.Policies++
			var policy types.AccountPolicy
			if err := k.cdc.Unmarshal(value, &policy); err != nil {
				report.AddIssue(maxIssues, "policy_decode_failure", "", fmt.Sprintf("key %X: %v", storageKey, err))
				continue
			}
			genesis.Policies = append(genesis.Policies, policy)
			owners[policy.Owner] = struct{}{}
			k.auditStorageKey(maxIssues, &report, storageKey, policy.Owner, 0, types.KeyRole_KEY_ROLE_UNSPECIFIED)

		case types.PQCKeyRecordKeyPrefix[0]:
			report.Keys++
			var key types.PQCKeyRecord
			if err := k.cdc.Unmarshal(value, &key); err != nil {
				report.AddIssue(maxIssues, "key_decode_failure", "", fmt.Sprintf("key %X: %v", storageKey, err))
				continue
			}
			genesis.Keys = append(genesis.Keys, key)
			owners[key.Owner] = struct{}{}
			k.auditStorageKey(maxIssues, &report, storageKey, key.Owner, key.KeyId, types.KeyRole_KEY_ROLE_UNSPECIFIED)

		case types.AccountSequenceKeyPrefix[0]:
			report.KeySequences++
			var sequence types.AccountKeySequence
			if err := k.cdc.Unmarshal(value, &sequence); err != nil {
				report.AddIssue(maxIssues, "sequence_decode_failure", "", fmt.Sprintf("key %X: %v", storageKey, err))
				continue
			}
			genesis.KeySequences = append(genesis.KeySequences, sequence)
			owners[sequence.Owner] = struct{}{}
			k.auditStorageKey(maxIssues, &report, storageKey, sequence.Owner, 0, types.KeyRole_KEY_ROLE_UNSPECIFIED)

		case types.AccountKeyHistoryPrefix[0]:
			report.KeyHistories++
			var history types.AccountKeyHistory
			if err := k.cdc.Unmarshal(value, &history); err != nil {
				report.AddIssue(maxIssues, "history_decode_failure", "", fmt.Sprintf("key %X: %v", storageKey, err))
				continue
			}
			genesis.KeyHistories = append(genesis.KeyHistories, history)
			owners[history.Owner] = struct{}{}
			k.auditStorageKey(maxIssues, &report, storageKey, history.Owner, 0, history.Role)

		default:
			report.AddIssue(maxIssues, "unknown_storage_key", "", fmt.Sprintf("unknown key %X", storageKey))
		}
	}

	validated := types.AuditGenesisState(genesis, ctx.BlockHeight(), true, maxIssues)
	report.MergeIssues(maxIssues, validated)

	orderedOwners := make([]string, 0, len(owners))
	for owner := range owners {
		orderedOwners = append(orderedOwners, owner)
	}
	sort.Strings(orderedOwners)
	for _, owner := range orderedOwners {
		address, err := sdk.AccAddressFromBech32(owner)
		if err != nil || address.String() != owner {
			continue // The structured module-state validation reports this.
		}
		if err := k.RequireClassicAccount(ctx, address); err != nil {
			report.AddIssue(
				maxIssues,
				"ineligible_owner_account",
				owner,
				fmt.Sprintf("ineligible pqcauth state owner: %v", err),
			)
		}
	}
	return report
}

func (k Keeper) auditStorageKey(
	maxIssues uint32,
	report *types.StateAuditReport,
	actual []byte,
	owner string,
	keyID uint64,
	role types.KeyRole,
) {
	address, err := sdk.AccAddressFromBech32(owner)
	if err != nil || address.String() != owner {
		return
	}
	var expected []byte
	switch actual[0] {
	case types.AccountPolicyKeyPrefix[0]:
		expected = types.AccountPolicyKey(address)
	case types.PQCKeyRecordKeyPrefix[0]:
		expected = types.PQCKeyRecordKey(address, keyID)
	case types.AccountSequenceKeyPrefix[0]:
		expected = types.AccountSequenceKey(address)
	case types.AccountKeyHistoryPrefix[0]:
		expected = types.AccountKeyHistoryKey(address, role)
	}
	if !bytes.Equal(actual, expected) {
		report.AddIssue(
			maxIssues,
			"storage_key_mismatch",
			owner,
			fmt.Sprintf("record is stored at %X, expected %X", actual, expected),
		)
	}
}
