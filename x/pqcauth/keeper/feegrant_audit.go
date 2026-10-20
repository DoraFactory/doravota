package keeper

import (
	"bytes"
	"errors"
	"fmt"
	"sort"
	"time"

	storetypes "github.com/cosmos/cosmos-sdk/store/v2/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/cosmos/cosmos-sdk/x/feegrant"

	"github.com/DoraFactory/doravota/x/pqcauth/types"
)

type auditedFeegrant struct {
	granter    sdk.AccAddress
	grantee    sdk.AccAddress
	expiration *time.Time
}

// AuditStateWithFeegrant extends the raw pqcauth store audit with a
// bidirectional comparison against the canonical x/feegrant store. It is
// intentionally reserved for invariants, upgrades, and operator diagnostics;
// Ante uses bounded point/prefix reads instead of this full-store scan.
func (k Keeper) AuditStateWithFeegrant(
	ctx sdk.Context,
	source FeegrantAllowanceSource,
	maxIssues uint32,
) types.StateAuditReport {
	report := k.AuditState(ctx, maxIssues)
	k.auditFeegrantIndex(ctx, source, maxIssues, &report)
	return report
}

func (k Keeper) auditFeegrantIndex(
	ctx sdk.Context,
	source FeegrantAllowanceSource,
	maxIssues uint32,
	report *types.StateAuditReport,
) {
	if source == nil {
		report.AddIssue(maxIssues, "feegrant_source_unavailable", "", "canonical feegrant source is nil")
		return
	}

	canonical := make(map[string]auditedFeegrant)
	err := source.IterateAllFeeAllowances(sdk.WrapSDKContext(ctx), func(grant feegrant.Grant) bool {
		report.FeegrantAllowances++
		entry, decodeErr := decodeAuditedFeegrant(grant)
		if decodeErr != nil {
			report.AddIssue(
				maxIssues,
				"canonical_feegrant_decode_failure",
				grant.Granter,
				fmt.Sprintf("allowance to %q: %v", grant.Grantee, decodeErr),
			)
			return false
		}
		key := string(types.FeegrantReverseKey(entry.granter, entry.grantee))
		if _, exists := canonical[key]; exists {
			report.AddIssue(
				maxIssues,
				"duplicate_canonical_feegrant",
				entry.granter.String(),
				fmt.Sprintf("duplicate allowance to %s", entry.grantee),
			)
			return false
		}
		canonical[key] = entry
		return false
	})
	if err != nil {
		report.AddIssue(maxIssues, "feegrant_source_iteration_failure", "", err.Error())
		return
	}
	report.FeegrantIndexCompared = true

	derived := make(map[string]auditedFeegrant)
	store := ctx.KVStore(k.storeKey)
	iterator := storetypes.KVStorePrefixIterator(store, types.FeegrantReverseKeyPrefix)
	for ; iterator.Valid(); iterator.Next() {
		storageKey := append([]byte(nil), iterator.Key()...)
		granter, grantee, decodeErr := types.DecodeFeegrantReverseKey(storageKey)
		if decodeErr != nil {
			continue // AuditState reports the malformed derived record.
		}
		expiration, decodeErr := types.DecodeFeegrantIndexValue(iterator.Value())
		if decodeErr != nil {
			continue // AuditState reports the malformed derived record.
		}
		derived[string(storageKey)] = auditedFeegrant{
			granter:    granter,
			grantee:    grantee,
			expiration: expiration,
		}
	}
	iterator.Close()

	canonicalKeys := sortedFeegrantKeys(canonical)
	for _, key := range canonicalKeys {
		expected := canonical[key]
		indexed, found := derived[key]
		if !found {
			report.AddIssue(
				maxIssues,
				"missing_feegrant_reverse_index",
				expected.granter.String(),
				fmt.Sprintf("canonical allowance to %s has no derived index", expected.grantee),
			)
			continue
		}
		if !sameFeegrantExpiration(expected.expiration, indexed.expiration) {
			report.AddIssue(
				maxIssues,
				"feegrant_expiration_mismatch",
				expected.granter.String(),
				fmt.Sprintf(
					"allowance to %s has canonical expiration %s and indexed expiration %s",
					expected.grantee,
					formatFeegrantExpiration(expected.expiration),
					formatFeegrantExpiration(indexed.expiration),
				),
			)
		}
	}

	derivedKeys := sortedFeegrantKeys(derived)
	for _, key := range derivedKeys {
		if _, found := canonical[key]; found {
			continue
		}
		indexed := derived[key]
		report.AddIssue(
			maxIssues,
			"orphan_feegrant_reverse_index",
			indexed.granter.String(),
			fmt.Sprintf("derived allowance to %s has no canonical record", indexed.grantee),
		)
	}
}

func decodeAuditedFeegrant(grant feegrant.Grant) (auditedFeegrant, error) {
	granter, err := sdk.AccAddressFromBech32(grant.Granter)
	if err != nil || granter.String() != grant.Granter {
		if err == nil {
			err = errors.New("address is not canonical")
		}
		return auditedFeegrant{}, fmt.Errorf("decode granter: %w", err)
	}
	grantee, err := sdk.AccAddressFromBech32(grant.Grantee)
	if err != nil || grantee.String() != grant.Grantee {
		if err == nil {
			err = errors.New("address is not canonical")
		}
		return auditedFeegrant{}, fmt.Errorf("decode grantee: %w", err)
	}
	if bytes.Equal(granter, grantee) {
		return auditedFeegrant{}, errors.New("granter and grantee must be distinct")
	}
	allowance, err := grant.GetGrant()
	if err != nil {
		return auditedFeegrant{}, fmt.Errorf("decode allowance: %w", err)
	}
	if allowance == nil {
		return auditedFeegrant{}, errors.New("allowance is nil")
	}
	expiration, err := allowance.ExpiresAt()
	if err != nil {
		return auditedFeegrant{}, fmt.Errorf("read expiration: %w", err)
	}
	if _, err := types.EncodeFeegrantIndexValue(expiration); err != nil {
		return auditedFeegrant{}, fmt.Errorf("encode expiration: %w", err)
	}
	return auditedFeegrant{granter: granter, grantee: grantee, expiration: expiration}, nil
}

func sortedFeegrantKeys[T any](entries map[string]T) []string {
	keys := make([]string, 0, len(entries))
	for key := range entries {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func sameFeegrantExpiration(left, right *time.Time) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return left.Equal(*right)
}

func formatFeegrantExpiration(expiration *time.Time) string {
	if expiration == nil {
		return "none"
	}
	return expiration.UTC().Format(time.RFC3339Nano)
}
