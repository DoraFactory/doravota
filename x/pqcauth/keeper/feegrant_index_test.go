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

func TestRebuildFeegrantIndexBackfillsActiveAllowances(t *testing.T) {
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
	require.False(t, store.Has(types.FeegrantReverseKey(granter, expiredGrantee)))
	require.NoError(t, moduleKeeper.AuditState(ctx, 100).Error())

	expected := errors.New("feegrant store unavailable")
	require.ErrorIs(t, moduleKeeper.RebuildFeegrantIndex(ctx, feegrantSourceStub{err: expected}), expected)
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
