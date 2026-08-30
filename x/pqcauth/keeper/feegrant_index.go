package keeper

import (
	"context"
	"errors"
	"fmt"
	"time"

	storetypes "github.com/cosmos/cosmos-sdk/store/v2/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/cosmos/cosmos-sdk/x/feegrant"

	"github.com/DoraFactory/doravota/x/pqcauth/types"
)

const (
	feegrantEndBlockPruneLimit = uint32(200)
	feegrantMessagePruneLimit  = uint32(75)
)

type FeegrantAllowanceSource interface {
	IterateAllFeeAllowances(context.Context, func(feegrant.Grant) bool) error
}

func (k Keeper) SetOutgoingFeegrant(
	ctx sdk.Context,
	granter, grantee sdk.AccAddress,
	allowance feegrant.FeeAllowanceI,
) error {
	if allowance == nil {
		return errors.New("feegrant allowance is nil")
	}
	expiration, err := allowance.ExpiresAt()
	if err != nil {
		return fmt.Errorf("read feegrant expiration: %w", err)
	}
	return k.setOutgoingFeegrant(ctx, granter, grantee, expiration)
}

func (k Keeper) setOutgoingFeegrant(
	ctx sdk.Context,
	granter, grantee sdk.AccAddress,
	expiration *time.Time,
) error {
	if len(granter) == 0 || len(grantee) == 0 || granter.Equals(grantee) {
		return errors.New("feegrant reverse index requires distinct non-empty addresses")
	}
	value, err := types.EncodeFeegrantIndexValue(expiration)
	if err != nil {
		return err
	}
	var expiryKey []byte
	if expiration != nil {
		expiryKey, err = types.FeegrantExpiryKey(*expiration, granter, grantee)
		if err != nil {
			return err
		}
	}

	store := ctx.KVStore(k.storeKey)
	reverseKey := types.FeegrantReverseKey(granter, grantee)
	if previous := store.Get(reverseKey); previous != nil {
		previousExpiration, err := types.DecodeFeegrantIndexValue(previous)
		if err != nil {
			return fmt.Errorf("decode existing feegrant reverse index: %w", err)
		}
		if previousExpiration != nil {
			previousExpiryKey, err := types.FeegrantExpiryKey(*previousExpiration, granter, grantee)
			if err != nil {
				return err
			}
			store.Delete(previousExpiryKey)
		}
	}
	store.Set(reverseKey, value)
	if expiryKey != nil {
		store.Set(expiryKey, []byte{1})
	}
	return nil
}

func (k Keeper) DeleteOutgoingFeegrant(
	ctx sdk.Context,
	granter, grantee sdk.AccAddress,
) error {
	store := ctx.KVStore(k.storeKey)
	reverseKey := types.FeegrantReverseKey(granter, grantee)
	value := store.Get(reverseKey)
	if value == nil {
		return nil
	}
	expiration, err := types.DecodeFeegrantIndexValue(value)
	if err != nil {
		return fmt.Errorf("decode feegrant reverse index: %w", err)
	}
	if expiration != nil {
		expiryKey, err := types.FeegrantExpiryKey(*expiration, granter, grantee)
		if err != nil {
			return err
		}
		store.Delete(expiryKey)
	}
	store.Delete(reverseKey)
	return nil
}

func (k Keeper) HasOutgoingFeegrant(ctx sdk.Context, granter sdk.AccAddress) (bool, error) {
	store := ctx.KVStore(k.storeKey)
	iterator := storetypes.KVStorePrefixIterator(store, types.FeegrantReversePrefix(granter))
	defer iterator.Close()
	if !iterator.Valid() {
		return false, nil
	}
	indexedGranter, _, err := types.DecodeFeegrantReverseKey(iterator.Key())
	if err != nil {
		return false, fmt.Errorf("decode feegrant reverse-index key: %w", err)
	}
	if !indexedGranter.Equals(granter) {
		return false, errors.New("feegrant reverse-index granter mismatch")
	}
	if _, err := types.DecodeFeegrantIndexValue(iterator.Value()); err != nil {
		return false, fmt.Errorf("decode feegrant reverse-index value: %w", err)
	}
	return true, nil
}

func (k Keeper) PruneExpiredFeegrantIndex(
	ctx sdk.Context,
	limit uint32,
) (uint32, error) {
	if limit == 0 {
		return 0, nil
	}
	store := ctx.KVStore(k.storeKey)
	iterator := storetypes.KVStorePrefixIterator(store, types.FeegrantExpiryKeyPrefix)
	type expiredIndex struct {
		expiryKey  []byte
		reverseKey []byte
	}
	expired := make([]expiredIndex, 0, limit)
	for ; iterator.Valid() && uint32(len(expired)) < limit; iterator.Next() {
		expiration, granter, grantee, err := types.DecodeFeegrantExpiryKey(iterator.Key())
		if err != nil {
			iterator.Close()
			return 0, fmt.Errorf("decode feegrant expiry-index key: %w", err)
		}
		if !expiration.Before(ctx.BlockTime()) {
			break
		}
		reverseKey := types.FeegrantReverseKey(granter, grantee)
		value := store.Get(reverseKey)
		if value == nil {
			iterator.Close()
			return 0, fmt.Errorf("%w: feegrant expiry index has no reverse entry", types.ErrInconsistentState)
		}
		indexedExpiration, err := types.DecodeFeegrantIndexValue(value)
		if err != nil {
			iterator.Close()
			return 0, fmt.Errorf("decode feegrant reverse-index value: %w", err)
		}
		if indexedExpiration == nil || !indexedExpiration.Equal(expiration) {
			iterator.Close()
			return 0, fmt.Errorf("%w: feegrant expiry and reverse indexes disagree", types.ErrInconsistentState)
		}
		expired = append(expired, expiredIndex{
			expiryKey:  append([]byte(nil), iterator.Key()...),
			reverseKey: reverseKey,
		})
	}
	iterator.Close()
	for _, entry := range expired {
		store.Delete(entry.expiryKey)
		store.Delete(entry.reverseKey)
	}
	return uint32(len(expired)), nil
}

func (k Keeper) PruneExpiredFeegrantIndexForBlock(ctx sdk.Context) error {
	_, err := k.PruneExpiredFeegrantIndex(ctx, feegrantEndBlockPruneLimit)
	return err
}

func (k Keeper) PruneExpiredFeegrantIndexForMessage(ctx sdk.Context) error {
	_, err := k.PruneExpiredFeegrantIndex(ctx, feegrantMessagePruneLimit)
	return err
}

func (k Keeper) RebuildFeegrantIndex(
	ctx sdk.Context,
	source FeegrantAllowanceSource,
) error {
	if source == nil {
		return errors.New("feegrant allowance source is nil")
	}
	store := ctx.KVStore(k.storeKey)
	clearPrefix := func(prefix []byte) {
		iterator := storetypes.KVStorePrefixIterator(store, prefix)
		keys := make([][]byte, 0)
		for ; iterator.Valid(); iterator.Next() {
			keys = append(keys, append([]byte(nil), iterator.Key()...))
		}
		iterator.Close()
		for _, key := range keys {
			store.Delete(key)
		}
	}
	clearPrefix(types.FeegrantReverseKeyPrefix)
	clearPrefix(types.FeegrantExpiryKeyPrefix)

	var rebuildErr error
	err := source.IterateAllFeeAllowances(sdk.WrapSDKContext(ctx), func(grant feegrant.Grant) bool {
		entry, err := decodeAuditedFeegrant(grant)
		if err != nil {
			rebuildErr = fmt.Errorf(
				"decode feegrant allowance %s/%s: %w",
				grant.Granter,
				grant.Grantee,
				err,
			)
			return true
		}
		if err := k.setOutgoingFeegrant(ctx, entry.granter, entry.grantee, entry.expiration); err != nil {
			rebuildErr = fmt.Errorf("index feegrant allowance %s/%s: %w", grant.Granter, grant.Grantee, err)
			return true
		}
		return false
	})
	if err != nil {
		return fmt.Errorf("iterate feegrant allowances: %w", err)
	}
	return rebuildErr
}
