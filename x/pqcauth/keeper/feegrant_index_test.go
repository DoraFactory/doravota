package keeper

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/cosmos/cosmos-sdk/x/feegrant"
	"github.com/stretchr/testify/require"

	"github.com/DoraFactory/doravota/x/pqcauth/types"
)

type feegrantSourceStub struct {
	grants []feegrant.Grant
	err    error
}

func (stub feegrantSourceStub) IterateAllFeeAllowances(
	_ context.Context,
	callback func(feegrant.Grant) bool,
) error {
	if stub.err != nil {
		return stub.err
	}
	for _, grant := range stub.grants {
		if callback(grant) {
			break
		}
	}
	return nil
}

func TestOutgoingFeegrantIndexSetReplaceAndDelete(t *testing.T) {
	moduleKeeper, ctx := setupKeeper(t, 10)
	granter := sdk.AccAddress(bytes.Repeat([]byte{0x41}, 20))
	grantee := sdk.AccAddress(bytes.Repeat([]byte{0x42}, 20))
	store := ctx.KVStore(moduleKeeper.storeKey)

	require.NoError(t, moduleKeeper.SetOutgoingFeegrant(
		ctx,
		granter,
		grantee,
		&feegrant.BasicAllowance{},
	))
	found, err := moduleKeeper.HasOutgoingFeegrant(ctx, granter)
	require.NoError(t, err)
	require.True(t, found)

	firstExpiration := time.Unix(2_000_000_000, 123).UTC()
	require.NoError(t, moduleKeeper.SetOutgoingFeegrant(
		ctx,
		granter,
		grantee,
		&feegrant.BasicAllowance{Expiration: &firstExpiration},
	))
	firstExpiryKey, err := types.FeegrantExpiryKey(firstExpiration, granter, grantee)
	require.NoError(t, err)
	require.True(t, store.Has(firstExpiryKey))

	secondExpiration := firstExpiration.Add(time.Hour)
	require.NoError(t, moduleKeeper.SetOutgoingFeegrant(
		ctx,
		granter,
		grantee,
		&feegrant.BasicAllowance{Expiration: &secondExpiration},
	))
	secondExpiryKey, err := types.FeegrantExpiryKey(secondExpiration, granter, grantee)
	require.NoError(t, err)
	require.False(t, store.Has(firstExpiryKey))
	require.True(t, store.Has(secondExpiryKey))

	require.NoError(t, moduleKeeper.DeleteOutgoingFeegrant(ctx, granter, grantee))
	require.False(t, store.Has(types.FeegrantReverseKey(granter, grantee)))
	require.False(t, store.Has(secondExpiryKey))
	found, err = moduleKeeper.HasOutgoingFeegrant(ctx, granter)
	require.NoError(t, err)
	require.False(t, found)
}

func TestPruneExpiredFeegrantIndexIsOrderedAndBounded(t *testing.T) {
	moduleKeeper, ctx := setupKeeper(t, 10)
	now := time.Unix(2_000_000_000, 0).UTC()
	ctx = ctx.WithBlockTime(now)
	granter := sdk.AccAddress(bytes.Repeat([]byte{0x51}, 20))
	grantees := []sdk.AccAddress{
		sdk.AccAddress(bytes.Repeat([]byte{0x52}, 20)),
		sdk.AccAddress(bytes.Repeat([]byte{0x53}, 20)),
		sdk.AccAddress(bytes.Repeat([]byte{0x54}, 20)),
	}
	expirations := []time.Time{now.Add(-2 * time.Second), now.Add(-time.Second), now.Add(time.Hour)}
	for index := range grantees {
		require.NoError(t, moduleKeeper.SetOutgoingFeegrant(
			ctx,
			granter,
			grantees[index],
			&feegrant.BasicAllowance{Expiration: &expirations[index]},
		))
	}

	pruned, err := moduleKeeper.PruneExpiredFeegrantIndex(ctx, 1)
	require.NoError(t, err)
	require.Equal(t, uint32(1), pruned)
	store := ctx.KVStore(moduleKeeper.storeKey)
	require.False(t, store.Has(types.FeegrantReverseKey(granter, grantees[0])))
	require.True(t, store.Has(types.FeegrantReverseKey(granter, grantees[1])))
	require.True(t, store.Has(types.FeegrantReverseKey(granter, grantees[2])))

	pruned, err = moduleKeeper.PruneExpiredFeegrantIndex(ctx, 10)
	require.NoError(t, err)
	require.Equal(t, uint32(1), pruned)
	require.False(t, store.Has(types.FeegrantReverseKey(granter, grantees[1])))
	require.True(t, store.Has(types.FeegrantReverseKey(granter, grantees[2])))
}

func TestRebuildFeegrantIndexBackfillsCanonicalAllowances(t *testing.T) {
	moduleKeeper, ctx := setupKeeper(t, 10)
	now := time.Unix(2_000_000_000, 0).UTC()
	ctx = ctx.WithBlockTime(now)
	granter := sdk.AccAddress(bytes.Repeat([]byte{0x61}, 20))
	activeGrantee := sdk.AccAddress(bytes.Repeat([]byte{0x62}, 20))
	expiredGrantee := sdk.AccAddress(bytes.Repeat([]byte{0x63}, 20))
	activeExpiration := now.Add(time.Hour)
	expiredExpiration := now.Add(-time.Hour)
	active, err := feegrant.NewGrant(
		granter,
		activeGrantee,
		&feegrant.BasicAllowance{Expiration: &activeExpiration},
	)
	require.NoError(t, err)
	expired, err := feegrant.NewGrant(
		granter,
		expiredGrantee,
		&feegrant.BasicAllowance{Expiration: &expiredExpiration},
	)
	require.NoError(t, err)

	require.NoError(t, moduleKeeper.RebuildFeegrantIndex(ctx, feegrantSourceStub{
		grants: []feegrant.Grant{active, expired},
	}))
	store := ctx.KVStore(moduleKeeper.storeKey)
	require.True(t, store.Has(types.FeegrantReverseKey(granter, activeGrantee)))
	require.True(t, store.Has(types.FeegrantReverseKey(granter, expiredGrantee)))
	report := moduleKeeper.AuditStateWithFeegrant(ctx, feegrantSourceStub{
		grants: []feegrant.Grant{active, expired},
	}, 100)
	require.NoError(t, report.Error())
	require.True(t, report.FeegrantIndexCompared)
	require.Equal(t, uint64(2), report.FeegrantAllowances)

	expected := errors.New("feegrant store unavailable")
	require.ErrorIs(t, moduleKeeper.RebuildFeegrantIndex(ctx, feegrantSourceStub{err: expected}), expected)
}

func TestFeegrantCrossModuleAuditDetectsMissingOrphanAndExpirationMismatch(t *testing.T) {
	moduleKeeper, ctx := setupKeeper(t, 10)
	granter := sdk.AccAddress(bytes.Repeat([]byte{0x64}, 20))
	missingGrantee := sdk.AccAddress(bytes.Repeat([]byte{0x65}, 20))
	orphanGrantee := sdk.AccAddress(bytes.Repeat([]byte{0x66}, 20))
	mismatchGrantee := sdk.AccAddress(bytes.Repeat([]byte{0x67}, 20))
	canonicalExpiration := time.Unix(2_100_000_000, 123).UTC()
	indexedExpiration := canonicalExpiration.Add(time.Hour)

	missing, err := feegrant.NewGrant(
		granter,
		missingGrantee,
		&feegrant.BasicAllowance{},
	)
	require.NoError(t, err)
	mismatch, err := feegrant.NewGrant(
		granter,
		mismatchGrantee,
		&feegrant.BasicAllowance{Expiration: &canonicalExpiration},
	)
	require.NoError(t, err)
	require.NoError(t, moduleKeeper.SetOutgoingFeegrant(
		ctx,
		granter,
		orphanGrantee,
		&feegrant.BasicAllowance{},
	))
	require.NoError(t, moduleKeeper.SetOutgoingFeegrant(
		ctx,
		granter,
		mismatchGrantee,
		&feegrant.BasicAllowance{Expiration: &indexedExpiration},
	))

	report := moduleKeeper.AuditStateWithFeegrant(ctx, feegrantSourceStub{
		grants: []feegrant.Grant{missing, mismatch},
	}, 100)
	require.Error(t, report.Error())
	require.True(t, report.FeegrantIndexCompared)
	require.Equal(t, uint64(2), report.FeegrantAllowances)
	require.Equal(t, uint64(2), report.FeegrantIndexes)
	codes := auditIssueCodes(report)
	require.True(t, codes["missing_feegrant_reverse_index"])
	require.True(t, codes["orphan_feegrant_reverse_index"])
	require.True(t, codes["feegrant_expiration_mismatch"])
}

func TestFeegrantCrossModuleAuditFailsClosedOnSourceError(t *testing.T) {
	moduleKeeper, ctx := setupKeeper(t, 10)
	expected := errors.New("canonical feegrant store unavailable")

	report := moduleKeeper.AuditStateWithFeegrant(
		ctx,
		feegrantSourceStub{err: expected},
		100,
	)

	require.Error(t, report.Error())
	require.False(t, report.FeegrantIndexCompared)
	require.Equal(t, "feegrant_source_iteration_failure", report.Issues[0].Code)
}

func TestFeegrantCrossModuleAuditRejectsDuplicateCanonicalRecords(t *testing.T) {
	moduleKeeper, ctx := setupKeeper(t, 10)
	granter := sdk.AccAddress(bytes.Repeat([]byte{0x6b}, 20))
	grantee := sdk.AccAddress(bytes.Repeat([]byte{0x6c}, 20))
	grant, err := feegrant.NewGrant(granter, grantee, &feegrant.BasicAllowance{})
	require.NoError(t, err)
	require.NoError(t, moduleKeeper.SetOutgoingFeegrant(
		ctx,
		granter,
		grantee,
		&feegrant.BasicAllowance{},
	))

	report := moduleKeeper.AuditStateWithFeegrant(ctx, feegrantSourceStub{
		grants: []feegrant.Grant{grant, grant},
	}, 100)

	require.Error(t, report.Error())
	require.True(t, report.FeegrantIndexCompared)
	require.Equal(t, uint64(2), report.FeegrantAllowances)
	require.Equal(t, "duplicate_canonical_feegrant", report.Issues[0].Code)
}

func TestFeegrantCrossModuleAuditCountsAllIssuesWhenTruncated(t *testing.T) {
	moduleKeeper, ctx := setupKeeper(t, 10)
	granter := sdk.AccAddress(bytes.Repeat([]byte{0x68}, 20))
	first, err := feegrant.NewGrant(
		granter,
		sdk.AccAddress(bytes.Repeat([]byte{0x69}, 20)),
		&feegrant.BasicAllowance{},
	)
	require.NoError(t, err)
	second, err := feegrant.NewGrant(
		granter,
		sdk.AccAddress(bytes.Repeat([]byte{0x6a}, 20)),
		&feegrant.BasicAllowance{},
	)
	require.NoError(t, err)

	report := moduleKeeper.AuditStateWithFeegrant(ctx, feegrantSourceStub{
		grants: []feegrant.Grant{first, second},
	}, 1)

	require.Equal(t, uint64(2), report.TotalIssues)
	require.Len(t, report.Issues, 1)
	require.True(t, report.IssuesTruncated)
}

func TestFeegrantIndexAuditDetectsOrphanExpiry(t *testing.T) {
	moduleKeeper, ctx := setupKeeper(t, 10)
	granter := sdk.AccAddress(bytes.Repeat([]byte{0x71}, 20))
	grantee := sdk.AccAddress(bytes.Repeat([]byte{0x72}, 20))
	expiration := time.Unix(2_000_000_000, 0).UTC()
	expiryKey, err := types.FeegrantExpiryKey(expiration, granter, grantee)
	require.NoError(t, err)
	ctx.KVStore(moduleKeeper.storeKey).Set(expiryKey, []byte{1})

	report := moduleKeeper.AuditState(ctx, 100)
	require.Error(t, report.Error())
	require.Equal(t, uint64(1), report.FeegrantExpiries)
	require.Equal(t, "orphan_feegrant_expiry_index", report.Issues[0].Code)
}
