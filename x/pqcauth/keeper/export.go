package keeper

import (
	"errors"

	storetypes "github.com/cosmos/cosmos-sdk/store/v2/types"
	sdk "github.com/cosmos/cosmos-sdk/types"

	"github.com/DoraFactory/doravota/x/pqcauth/types"
)

// ValidateZeroHeightExport fails closed until a coordinated height-rebasing
// policy exists for PQC keys, delayed recovery and governance schedules. Merely
// normalizing effective policies leaves key windows at their original heights.
// Call before any export preparation mutates the cached application state.
func (k Keeper) ValidateZeroHeightExport(ctx sdk.Context) error {
	unsupported := func() error {
		return errors.New("zero-height export is unsupported with PQCAuth account state or height-based parameters; export without --for-zero-height to preserve activation and recovery heights")
	}
	store := ctx.KVStore(k.storeKey)
	for _, prefix := range [][]byte{
		types.AccountPolicyKeyPrefix, types.PQCKeyRecordKeyPrefix,
		types.AccountSequenceKeyPrefix, types.AccountKeyHistoryPrefix,
	} {
		iterator := storetypes.KVStorePrefixIterator(store, prefix)
		found := iterator.Valid()
		iterator.Close()
		if found {
			return unsupported()
		}
	}
	params := k.GetParams(ctx).Effective(ctx.BlockHeight())
	if params.PendingActivationHeight != 0 || params.RegistrationCutoffHeight != 0 || params.EmergencyExpiresHeight != 0 {
		return unsupported()
	}
	return nil
}
