package keeper

import (
	"encoding/json"
	"fmt"

	"github.com/cometbft/cometbft/libs/log"
	"github.com/cosmos/cosmos-sdk/codec"
	storetypes "github.com/cosmos/cosmos-sdk/store/types"
	sdk "github.com/cosmos/cosmos-sdk/types"

	"github.com/DoraFactory/doravota/x/sponsor-contract-tx/types"
)

// Keeper maintains the link to storage and exposes getter/setter methods for the various parts of the state machine
type Keeper struct {
	cdc      codec.BinaryCodec
	storeKey storetypes.StoreKey
}

// NewKeeper creates a new sponsor Keeper instance
func NewKeeper(cdc codec.BinaryCodec, storeKey storetypes.StoreKey) *Keeper {
	return &Keeper{
		cdc:      cdc,
		storeKey: storeKey,
	}
}

// Logger returns a module-specific logger
func (k Keeper) Logger(ctx sdk.Context) log.Logger {
	return ctx.Logger().With("module", fmt.Sprintf("x/%s", types.ModuleName))
}

// SetSponsor sets a sponsor in the store
func (k Keeper) SetSponsor(ctx sdk.Context, sponsor types.ContractSponsor) {
	store := ctx.KVStore(k.storeKey)
	key := types.GetSponsorKey(sponsor.ContractAddress)
	bz, err := json.Marshal(sponsor)
	if err != nil {
		panic(err)
	}
	store.Set(key, bz)
}

// GetSponsor returns a sponsor from the store
func (k Keeper) GetSponsor(ctx sdk.Context, contractAddr string) (types.ContractSponsor, bool) {
	store := ctx.KVStore(k.storeKey)
	key := types.GetSponsorKey(contractAddr)
	bz := store.Get(key)
	if bz == nil {
		return types.ContractSponsor{}, false
	}

	var sponsor types.ContractSponsor
	if err := json.Unmarshal(bz, &sponsor); err != nil {
		panic(err)
	}
	return sponsor, true
}

// HasSponsor checks if a sponsor exists in the store
func (k Keeper) HasSponsor(ctx sdk.Context, contractAddr string) bool {
	store := ctx.KVStore(k.storeKey)
	key := types.GetSponsorKey(contractAddr)
	return store.Has(key)
}

// DeleteSponsor removes a sponsor from the store
func (k Keeper) DeleteSponsor(ctx sdk.Context, contractAddr string) {
	store := ctx.KVStore(k.storeKey)
	key := types.GetSponsorKey(contractAddr)
	store.Delete(key)
}

// IsSponsored checks if a contract is sponsored (key method for AnteHandler)
func (k Keeper) IsSponsored(ctx sdk.Context, contractAddr string) bool {
	sponsor, found := k.GetSponsor(ctx, contractAddr)
	if !found {
		return false
	}
	return sponsor.IsSponsored
}

// GetAllSponsors returns all sponsors from the store
func (k Keeper) GetAllSponsors(ctx sdk.Context) []types.ContractSponsor {
	store := ctx.KVStore(k.storeKey)
	iterator := sdk.KVStorePrefixIterator(store, types.SponsorKeyPrefix)
	defer iterator.Close()

	var sponsors []types.ContractSponsor
	for ; iterator.Valid(); iterator.Next() {
		var sponsor types.ContractSponsor
		if err := json.Unmarshal(iterator.Value(), &sponsor); err != nil {
			panic(err)
		}
		sponsors = append(sponsors, sponsor)
	}

	return sponsors
}
