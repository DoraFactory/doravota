package keeper

import (
	"encoding/json"
	"fmt"

	wasmtypes "github.com/CosmWasm/wasmd/x/wasm/types"
	"github.com/cometbft/cometbft/libs/log"
	"github.com/cosmos/cosmos-sdk/codec"
	"github.com/cosmos/cosmos-sdk/store/prefix"
	storetypes "github.com/cosmos/cosmos-sdk/store/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/cosmos/cosmos-sdk/types/query"

	"github.com/DoraFactory/doravota/x/sponsor-contract-tx/types"
)

// WasmKeeperInterface defines the interface we need from wasm keeper
type WasmKeeperInterface interface {
	GetContractInfo(ctx sdk.Context, contractAddress sdk.AccAddress) *wasmtypes.ContractInfo
	QuerySmart(ctx sdk.Context, contractAddr sdk.AccAddress, req []byte) ([]byte, error)
}

// Keeper maintains the link to storage and exposes getter/setter methods for the various parts of the state machine
type Keeper struct {
	cdc        codec.BinaryCodec
	storeKey   storetypes.StoreKey
	wasmKeeper WasmKeeperInterface
}

// NewKeeper creates a new sponsor Keeper instance
func NewKeeper(cdc codec.BinaryCodec, storeKey storetypes.StoreKey, wasmKeeper WasmKeeperInterface) *Keeper {
	return &Keeper{
		cdc:        cdc,
		storeKey:   storeKey,
		wasmKeeper: wasmKeeper,
	}
}

// Logger returns a module-specific logger
func (k Keeper) Logger(ctx sdk.Context) log.Logger {
	return ctx.Logger().With("module", fmt.Sprintf("x/%s", types.ModuleName))
}

// CheckContractPolicy calls the contract's CheckPolicy query to verify if user is eligible
func (k Keeper) CheckContractPolicy(ctx sdk.Context, contractAddr string, userAddr sdk.AccAddress) (bool, error) {
	// prepare query smart contract message
	queryMsg := map[string]interface{}{
		"check_policy": map[string]interface{}{
			"address": userAddr.String(),
		},
	}

	queryBytes, err := json.Marshal(queryMsg)
	if err != nil {
		return false, fmt.Errorf("failed to marshal query message: %w", err)
	}

	// call contract query method
	contractAccAddr, err := sdk.AccAddressFromBech32(contractAddr)
	if err != nil {
		return false, fmt.Errorf("invalid contract address: %w", err)
	}

	result, err := k.wasmKeeper.QuerySmart(ctx, contractAccAddr, queryBytes)
	if err != nil {
		return false, fmt.Errorf("failed to query contract: %w", err)
	}

	// parse query result
	var response struct {
		Eligible bool `json:"eligible"`
	}
	if err := json.Unmarshal(result, &response); err != nil {
		return false, fmt.Errorf("failed to unmarshal query response: %w", err)
	}

	return response.Eligible, nil
}

// SetSponsor sets a sponsor in the store
func (k Keeper) SetSponsor(ctx sdk.Context, sponsor types.ContractSponsor) {
	store := ctx.KVStore(k.storeKey)
	key := types.GetSponsorKey(sponsor.ContractAddress)
	bz := k.cdc.MustMarshal(&sponsor)
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
	
	// Try protobuf unmarshaling first (new format)
	err := k.cdc.Unmarshal(bz, &sponsor)
	if err != nil {
		// Fall back to JSON unmarshaling for backward compatibility (old format)
		err = json.Unmarshal(bz, &sponsor)
		if err != nil {
			panic(fmt.Errorf("failed to unmarshal sponsor data for contract %s: %w", contractAddr, err))
		}
		// Auto-migrate: save in protobuf format
		k.SetSponsor(ctx, sponsor)
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

// IsContractAdmin checks if the given address is the admin of the contract
func (k Keeper) IsContractAdmin(ctx sdk.Context, contractAddr string, userAddr sdk.AccAddress) (bool, error) {
	// Convert contract address string to AccAddress
	contractAccAddr, err := sdk.AccAddressFromBech32(contractAddr)
	if err != nil {
		return false, fmt.Errorf("invalid contract address: %w", err)
	}

	// Get contract info from wasm keeper
	contractInfo := k.wasmKeeper.GetContractInfo(ctx, contractAccAddr)
	if contractInfo == nil {
		return false, fmt.Errorf("contract not found: %s", contractAddr)
	}

	// Check if the user is the admin
	return contractInfo.Admin == userAddr.String(), nil
}

// GetAllSponsors returns all sponsors in the store
func (k Keeper) GetAllSponsors(ctx sdk.Context) []types.ContractSponsor {
	var sponsors []types.ContractSponsor

	k.IterateSponsors(ctx, func(sponsor types.ContractSponsor) bool {
		sponsors = append(sponsors, sponsor)
		return false // continue iteration
	})

	return sponsors
}

// IterateSponsors iterates over all sponsors and calls the provided callback function
func (k Keeper) IterateSponsors(ctx sdk.Context, cb func(sponsor types.ContractSponsor) (stop bool)) {
	store := prefix.NewStore(ctx.KVStore(k.storeKey), types.SponsorKeyPrefix)
	iterator := sdk.KVStorePrefixIterator(store, []byte{})
	defer iterator.Close()

	for ; iterator.Valid(); iterator.Next() {
		var sponsor types.ContractSponsor
		
		// Try protobuf unmarshaling first (new format)
		err := k.cdc.Unmarshal(iterator.Value(), &sponsor)
		if err != nil {
			// Fall back to JSON unmarshaling for backward compatibility (old format)
			err = json.Unmarshal(iterator.Value(), &sponsor)
			if err != nil {
				// Skip invalid entries and log error
				continue
			}
		}

		if cb(sponsor) {
			break
		}
	}
}

// GetSponsorsPaginated returns sponsors with pagination support
func (k Keeper) GetSponsorsPaginated(ctx sdk.Context, pageReq *query.PageRequest) ([]*types.ContractSponsor, *query.PageResponse, error) {
	var sponsors []*types.ContractSponsor

	store := prefix.NewStore(ctx.KVStore(k.storeKey), types.SponsorKeyPrefix)

	pageRes, err := query.Paginate(store, pageReq, func(key []byte, value []byte) error {
		var sponsor types.ContractSponsor
		
		// Try protobuf unmarshaling first (new format)
		err := k.cdc.Unmarshal(value, &sponsor)
		if err != nil {
			// Fall back to JSON unmarshaling for backward compatibility (old format)
			err = json.Unmarshal(value, &sponsor)
			if err != nil {
				return fmt.Errorf("failed to unmarshal sponsor data: %w", err)
			}
		}
		
		sponsors = append(sponsors, &sponsor)
		return nil
	})

	if err != nil {
		return nil, nil, err
	}

	return sponsors, pageRes, nil
}

// GetSponsorsByStatus returns sponsors filtered by sponsorship status
func (k Keeper) GetSponsorsByStatus(ctx sdk.Context, isSponsored bool) []types.ContractSponsor {
	var sponsors []types.ContractSponsor

	k.IterateSponsors(ctx, func(sponsor types.ContractSponsor) bool {
		if sponsor.IsSponsored == isSponsored {
			sponsors = append(sponsors, sponsor)
		}
		return false // continue iteration
	})

	return sponsors
}

// GetSponsorCount returns the total number of sponsors
func (k Keeper) GetSponsorCount(ctx sdk.Context) uint64 {
	var count uint64

	k.IterateSponsors(ctx, func(sponsor types.ContractSponsor) bool {
		count++
		return false // continue iteration
	})

	return count
}

// GetActiveSponsorCount returns the number of active sponsors
func (k Keeper) GetActiveSponsorCount(ctx sdk.Context) uint64 {
	var count uint64

	k.IterateSponsors(ctx, func(sponsor types.ContractSponsor) bool {
		if sponsor.IsSponsored {
			count++
		}
		return false // continue iteration
	})

	return count
}

// GetParams returns the module parameters
func (k Keeper) GetParams(ctx sdk.Context) types.Params {
	store := ctx.KVStore(k.storeKey)
	bz := store.Get(types.ParamsKey)
	if bz == nil {
		return types.DefaultParams()
	}

	var params types.Params
	k.cdc.MustUnmarshal(bz, &params)
	return params
}

// SetParams sets the module parameters
func (k Keeper) SetParams(ctx sdk.Context, params types.Params) {
	store := ctx.KVStore(k.storeKey)
	bz := k.cdc.MustMarshal(&params)
	store.Set(types.ParamsKey, bz)
}
