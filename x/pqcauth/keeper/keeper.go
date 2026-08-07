package keeper

import (
	"fmt"
	"math"

	"github.com/cometbft/cometbft/libs/log"
	"github.com/cosmos/cosmos-sdk/codec"
	"github.com/cosmos/cosmos-sdk/store/prefix"
	storetypes "github.com/cosmos/cosmos-sdk/store/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/cosmos/cosmos-sdk/types/query"

	"github.com/DoraFactory/doravota/x/pqcauth/types"
)

type Keeper struct {
	cdc       codec.BinaryCodec
	storeKey  storetypes.StoreKey
	authority string
}

func NewKeeper(cdc codec.BinaryCodec, storeKey storetypes.StoreKey, authority string) Keeper {
	return Keeper{
		cdc:       cdc,
		storeKey:  storeKey,
		authority: authority,
	}
}

func (k Keeper) Logger(ctx sdk.Context) log.Logger {
	return ctx.Logger().With("module", fmt.Sprintf("x/%s", types.ModuleName))
}

func (k Keeper) Codec() codec.BinaryCodec {
	return k.cdc
}

func (k Keeper) Authority() string {
	return k.authority
}

func (k Keeper) GetParams(ctx sdk.Context) types.Params {
	bz := ctx.KVStore(k.storeKey).Get(types.ParamsKey)
	if bz == nil {
		return types.DefaultParams()
	}

	var params types.Params
	if err := k.cdc.Unmarshal(bz, &params); err != nil {
		panic(fmt.Errorf("corrupt pqcauth params: %w", err))
	}
	return params
}

func (k Keeper) SetParams(ctx sdk.Context, params types.Params) error {
	if err := params.Validate(); err != nil {
		return err
	}
	bz, err := k.cdc.Marshal(&params)
	if err != nil {
		return err
	}
	ctx.KVStore(k.storeKey).Set(types.ParamsKey, bz)
	return nil
}

// NormalizeParams persists an activated H+1 parameter bundle. Future pending
// bundles remain in state until their activation height.
func (k Keeper) NormalizeParams(ctx sdk.Context) (types.Params, error) {
	raw := k.GetParams(ctx)
	effective := raw.Effective(ctx.BlockHeight())
	if !raw.Equal(effective) {
		if err := k.SetParams(ctx, effective); err != nil {
			return types.Params{}, err
		}
	}
	return effective, nil
}

func (k Keeper) GetAccountPolicy(ctx sdk.Context, owner sdk.AccAddress) (types.AccountPolicy, bool) {
	bz := ctx.KVStore(k.storeKey).Get(types.AccountPolicyKey(owner))
	if bz == nil {
		return types.AccountPolicy{}, false
	}

	var policy types.AccountPolicy
	if err := k.cdc.Unmarshal(bz, &policy); err != nil {
		panic(fmt.Errorf("corrupt pqcauth policy for %s: %w", owner.String(), err))
	}
	return policy, true
}

func (k Keeper) GetEffectiveAccountPolicy(
	ctx sdk.Context,
	owner sdk.AccAddress,
) (types.AccountPolicy, bool) {
	policy, found := k.GetAccountPolicy(ctx, owner)
	if !found {
		return types.AccountPolicy{}, false
	}
	return policy.Effective(ctx.BlockHeight()), true
}

func (k Keeper) SetAccountPolicy(ctx sdk.Context, owner sdk.AccAddress, policy types.AccountPolicy) error {
	if policy.Owner != owner.String() {
		return fmt.Errorf("%w: policy owner mismatch", types.ErrInvalidKey)
	}
	bz, err := k.cdc.Marshal(&policy)
	if err != nil {
		return err
	}
	ctx.KVStore(k.storeKey).Set(types.AccountPolicyKey(owner), bz)
	return nil
}

// NormalizeAccountPolicy persists an activated pending state before scheduling
// another H+1 transition. Future pending transitions are returned unchanged.
func (k Keeper) NormalizeAccountPolicy(
	ctx sdk.Context,
	owner sdk.AccAddress,
) (types.AccountPolicy, bool, error) {
	raw, found := k.GetAccountPolicy(ctx, owner)
	if !found {
		return types.AccountPolicy{}, false, nil
	}
	effective := raw.Effective(ctx.BlockHeight())
	if !raw.Equal(effective) {
		if err := k.SetAccountPolicy(ctx, owner, effective); err != nil {
			return types.AccountPolicy{}, false, err
		}
	}
	return effective, true, nil
}

func (k Keeper) GetKey(
	ctx sdk.Context,
	owner sdk.AccAddress,
	keyID uint64,
) (types.PQCKeyRecord, bool) {
	bz := ctx.KVStore(k.storeKey).Get(types.PQCKeyRecordKey(owner, keyID))
	if bz == nil {
		return types.PQCKeyRecord{}, false
	}

	var key types.PQCKeyRecord
	if err := k.cdc.Unmarshal(bz, &key); err != nil {
		panic(fmt.Errorf("corrupt pqcauth key %s/%d: %w", owner.String(), keyID, err))
	}
	return key, true
}

func (k Keeper) SetKey(ctx sdk.Context, owner sdk.AccAddress, key types.PQCKeyRecord) error {
	if key.Owner != owner.String() || key.KeyId == 0 {
		return fmt.Errorf("%w: key owner or identifier mismatch", types.ErrInvalidKey)
	}
	bz, err := k.cdc.Marshal(&key)
	if err != nil {
		return err
	}
	ctx.KVStore(k.storeKey).Set(types.PQCKeyRecordKey(owner, key.KeyId), bz)
	return nil
}

func (k Keeper) DeleteKey(ctx sdk.Context, owner sdk.AccAddress, keyID uint64) {
	ctx.KVStore(k.storeKey).Delete(types.PQCKeyRecordKey(owner, keyID))
}

func (k Keeper) GetActiveSigningKey(
	ctx sdk.Context,
	owner sdk.AccAddress,
) (types.PQCKeyRecord, types.AccountPolicy, bool) {
	policy, found := k.GetEffectiveAccountPolicy(ctx, owner)
	if !found || policy.CurrentSigningKeyId == 0 {
		return types.PQCKeyRecord{}, policy, false
	}
	key, found := k.GetKey(ctx, owner, policy.CurrentSigningKeyId)
	if !found || key.Role != types.KeyRole_KEY_ROLE_SIGNING || !key.IsEffective(ctx.BlockHeight()) {
		return types.PQCKeyRecord{}, policy, false
	}
	return key, policy, true
}

func (k Keeper) GetKeysPaginated(
	ctx sdk.Context,
	owner sdk.AccAddress,
	pageRequest *query.PageRequest,
) ([]types.PQCKeyRecord, *query.PageResponse, error) {
	store := prefix.NewStore(ctx.KVStore(k.storeKey), types.PQCKeyRecordPrefix(owner))
	keys := make([]types.PQCKeyRecord, 0)
	pageResponse, err := query.Paginate(store, pageRequest, func(_, value []byte) error {
		var key types.PQCKeyRecord
		if err := k.cdc.Unmarshal(value, &key); err != nil {
			return err
		}
		keys = append(keys, key)
		return nil
	})
	return keys, pageResponse, err
}

func (k Keeper) IterateAllKeys(ctx sdk.Context, callback func(types.PQCKeyRecord) bool) {
	store := prefix.NewStore(ctx.KVStore(k.storeKey), types.PQCKeyRecordKeyPrefix)
	iterator := store.Iterator(nil, nil)
	defer iterator.Close()
	for ; iterator.Valid(); iterator.Next() {
		var key types.PQCKeyRecord
		if err := k.cdc.Unmarshal(iterator.Value(), &key); err != nil {
			panic(fmt.Errorf("corrupt pqcauth key during iteration: %w", err))
		}
		if callback(key) {
			return
		}
	}
}

func (k Keeper) IterateAllPolicies(ctx sdk.Context, callback func(types.AccountPolicy) bool) {
	store := prefix.NewStore(ctx.KVStore(k.storeKey), types.AccountPolicyKeyPrefix)
	iterator := store.Iterator(nil, nil)
	defer iterator.Close()
	for ; iterator.Valid(); iterator.Next() {
		var policy types.AccountPolicy
		if err := k.cdc.Unmarshal(iterator.Value(), &policy); err != nil {
			panic(fmt.Errorf("corrupt pqcauth policy during iteration: %w", err))
		}
		if callback(policy) {
			return
		}
	}
}

func (k Keeper) IterateAllSequences(ctx sdk.Context, callback func(types.AccountKeySequence) bool) {
	store := prefix.NewStore(ctx.KVStore(k.storeKey), types.AccountSequenceKeyPrefix)
	iterator := store.Iterator(nil, nil)
	defer iterator.Close()
	for ; iterator.Valid(); iterator.Next() {
		var sequence types.AccountKeySequence
		if err := k.cdc.Unmarshal(iterator.Value(), &sequence); err != nil {
			panic(fmt.Errorf("corrupt pqcauth key sequence during iteration: %w", err))
		}
		if callback(sequence) {
			return
		}
	}
}

func (k Keeper) GetKeyHistory(
	ctx sdk.Context,
	owner sdk.AccAddress,
	role types.KeyRole,
) (types.AccountKeyHistory, bool) {
	bz := ctx.KVStore(k.storeKey).Get(types.AccountKeyHistoryKey(owner, role))
	if bz == nil {
		return types.AccountKeyHistory{}, false
	}
	var history types.AccountKeyHistory
	if err := k.cdc.Unmarshal(bz, &history); err != nil {
		panic(fmt.Errorf("corrupt pqcauth key history for %s/%s: %w", owner.String(), role, err))
	}
	return history, true
}

func (k Keeper) SetKeyHistory(
	ctx sdk.Context,
	owner sdk.AccAddress,
	history types.AccountKeyHistory,
) error {
	if history.Owner != owner.String() ||
		(history.Role != types.KeyRole_KEY_ROLE_SIGNING &&
			history.Role != types.KeyRole_KEY_ROLE_RECOVERY) ||
		history.CompactedCount == 0 ||
		history.LastCompactedKeyId == 0 ||
		len(history.Accumulator) != types.KeyHistoryAccumulatorSize {
		return fmt.Errorf("%w: invalid account key history", types.ErrInvalidKey)
	}
	bz, err := k.cdc.Marshal(&history)
	if err != nil {
		return err
	}
	ctx.KVStore(k.storeKey).Set(types.AccountKeyHistoryKey(owner, history.Role), bz)
	return nil
}

func (k Keeper) IterateAllKeyHistories(
	ctx sdk.Context,
	callback func(types.AccountKeyHistory) bool,
) {
	store := prefix.NewStore(ctx.KVStore(k.storeKey), types.AccountKeyHistoryPrefix)
	iterator := store.Iterator(nil, nil)
	defer iterator.Close()
	for ; iterator.Valid(); iterator.Next() {
		var history types.AccountKeyHistory
		if err := k.cdc.Unmarshal(iterator.Value(), &history); err != nil {
			panic(fmt.Errorf("corrupt pqcauth key history during iteration: %w", err))
		}
		if callback(history) {
			return
		}
	}
}

func (k Keeper) GetKeySequence(
	ctx sdk.Context,
	owner sdk.AccAddress,
) types.AccountKeySequence {
	bz := ctx.KVStore(k.storeKey).Get(types.AccountSequenceKey(owner))
	if bz == nil {
		return types.AccountKeySequence{Owner: owner.String(), NextKeyId: 1}
	}
	var sequence types.AccountKeySequence
	if err := k.cdc.Unmarshal(bz, &sequence); err != nil {
		panic(fmt.Errorf("corrupt pqcauth key sequence for %s: %w", owner.String(), err))
	}
	return sequence
}

func (k Keeper) SetKeySequence(
	ctx sdk.Context,
	owner sdk.AccAddress,
	sequence types.AccountKeySequence,
) error {
	if sequence.Owner != owner.String() || sequence.NextKeyId == 0 {
		return fmt.Errorf("%w: invalid account key sequence", types.ErrInvalidKey)
	}
	bz, err := k.cdc.Marshal(&sequence)
	if err != nil {
		return err
	}
	ctx.KVStore(k.storeKey).Set(types.AccountSequenceKey(owner), bz)
	return nil
}

func (k Keeper) ReserveKeyIDs(
	ctx sdk.Context,
	owner sdk.AccAddress,
	expectedFirst uint64,
	count uint64,
) ([]uint64, types.AccountKeySequence, error) {
	sequence := k.GetKeySequence(ctx, owner)
	if expectedFirst == 0 || sequence.NextKeyId != expectedFirst {
		return nil, sequence, fmt.Errorf(
			"%w: got %d, want %d",
			types.ErrUnexpectedKeyID,
			expectedFirst,
			sequence.NextKeyId,
		)
	}
	if count == 0 || count > 2 {
		return nil, sequence, types.ErrKeyLimit.Wrap("a key operation may reserve one or two identifiers")
	}
	if sequence.NextKeyId > math.MaxUint64-count {
		return nil, sequence, types.ErrKeyLimit.Wrap("key identifier overflow")
	}

	ids := make([]uint64, count)
	for i := range ids {
		ids[i] = sequence.NextKeyId + uint64(i)
	}
	sequence.NextKeyId += count
	return ids, sequence, nil
}
