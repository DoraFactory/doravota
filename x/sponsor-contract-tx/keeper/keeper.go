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
	// NOTE: JSON is required for CosmWasm smart contract communication
	// CosmWasm contracts expect JSON queries and return JSON responses
	// This cannot be changed to protobuf without breaking contract compatibility

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
func (k Keeper) SetSponsor(ctx sdk.Context, sponsor types.ContractSponsor) error {
	store := ctx.KVStore(k.storeKey)
	key := types.GetSponsorKey(sponsor.ContractAddress)

	bz, err := k.cdc.Marshal(&sponsor)
	if err != nil {
		return fmt.Errorf("failed to marshal sponsor: %w", err)
	}

	store.Set(key, bz)
	return nil
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
	err := k.cdc.Unmarshal(bz, &sponsor)
	if err != nil {
		// Log error and return empty sponsor instead of panicking
		k.Logger(ctx).Error("failed to unmarshal sponsor data", "contract", contractAddr, "error", err)
		return types.ContractSponsor{}, false
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
func (k Keeper) DeleteSponsor(ctx sdk.Context, contractAddr string) error {
	store := ctx.KVStore(k.storeKey)
	key := types.GetSponsorKey(contractAddr)
	store.Delete(key)
	return nil
}

// IsSponsored checks if a contract is sponsored (key method for AnteHandler)
func (k Keeper) IsSponsored(ctx sdk.Context, contractAddr string) bool {
	sponsor, found := k.GetSponsor(ctx, contractAddr)
	return found && sponsor.IsSponsored
}

// ValidateContractExists checks if a contract exists and is valid
func (k Keeper) ValidateContractExists(ctx sdk.Context, contractAddr string) error {
	// Convert contract address string to AccAddress
	contractAccAddr, err := sdk.AccAddressFromBech32(contractAddr)
	if err != nil {
		return fmt.Errorf("invalid contract address: %w", err)
	}

	// Get contract info from wasm keeper
	contractInfo := k.wasmKeeper.GetContractInfo(ctx, contractAccAddr)
	if contractInfo == nil {
		return types.ErrContractNotFound.Wrapf("contract not found: %s", contractAddr)
	}

	return nil
}

// IsContractAdmin checks if the given address is the admin of the contract
func (k Keeper) IsContractAdmin(ctx sdk.Context, contractAddr string, userAddr sdk.AccAddress) (bool, error) {
	// First validate that contract exists
	if err := k.ValidateContractExists(ctx, contractAddr); err != nil {
		return false, err
	}

	// Convert contract address string to AccAddress
	contractAccAddr, err := sdk.AccAddressFromBech32(contractAddr)
	if err != nil {
		return false, fmt.Errorf("invalid contract address: %w", err)
	}

	// Get contract info from wasm keeper (we know it exists from validation above)
	contractInfo := k.wasmKeeper.GetContractInfo(ctx, contractAccAddr)

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

		err := k.cdc.Unmarshal(iterator.Value(), &sponsor)
		if err != nil {
			// Skip invalid entries and log error
			k.Logger(ctx).Error("failed to unmarshal sponsor data during iteration", "error", err)
			continue
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

		err := k.cdc.Unmarshal(value, &sponsor)
		if err != nil {
			return fmt.Errorf("failed to unmarshal sponsor data: %w", err)
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

	// Removed read-path event to reduce noise

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
func (k Keeper) SetParams(ctx sdk.Context, params types.Params) error {
	store := ctx.KVStore(k.storeKey)
	bz, err := k.cdc.Marshal(&params)
	if err != nil {
		return fmt.Errorf("failed to marshal params: %w", err)
	}
	store.Set(types.ParamsKey, bz)
	return nil
}

// === User Grant Usage Management ===

// GetUserGrantUsage returns the grant usage for a specific user and contract
func (k Keeper) GetUserGrantUsage(ctx sdk.Context, userAddr, contractAddr string) types.UserGrantUsage {
	store := ctx.KVStore(k.storeKey)
	key := types.GetUserGrantUsageKey(userAddr, contractAddr)
	bz := store.Get(key)

	if bz == nil {
		// Return new usage record if not found
		return types.NewUserGrantUsage(userAddr, contractAddr)
	}

	var usage types.UserGrantUsage
	err := k.cdc.Unmarshal(bz, &usage)
	if err != nil {
		// Log error and return new usage record
		k.Logger(ctx).Error("failed to unmarshal user grant usage", "user", userAddr, "contract", contractAddr, "error", err)
		return types.NewUserGrantUsage(userAddr, contractAddr)
	}

	return usage
}

// SetUserGrantUsage sets the grant usage for a specific user and contract
func (k Keeper) SetUserGrantUsage(ctx sdk.Context, usage types.UserGrantUsage) error {
	store := ctx.KVStore(k.storeKey)
	key := types.GetUserGrantUsageKey(usage.UserAddress, usage.ContractAddress)

	bz, err := k.cdc.Marshal(&usage)
	if err != nil {
		return fmt.Errorf("failed to marshal user grant usage: %w", err)
	}
	store.Set(key, bz)
	return nil
}

// UpdateUserGrantUsage updates the user's grant usage by adding the consumed amount
func (k Keeper) UpdateUserGrantUsage(ctx sdk.Context, userAddr, contractAddr string, consumedAmount sdk.Coins) error {
	usage := k.GetUserGrantUsage(ctx, userAddr, contractAddr)

	// Convert []*sdk.Coin to sdk.Coins for calculation
	currentUsed := sdk.Coins{}
	for _, coin := range usage.TotalGrantUsed {
		if coin != nil {
			currentUsed = currentUsed.Add(*coin)
		}
	}

	// Add consumed amount
	newTotal := currentUsed.Add(consumedAmount...)

	// Convert back to []*sdk.Coin
	usage.TotalGrantUsed = make([]*sdk.Coin, len(newTotal))
	for i, coin := range newTotal {
		usage.TotalGrantUsed[i] = &coin
	}

	usage.LastUsedTime = ctx.BlockTime().Unix()
	if err := k.SetUserGrantUsage(ctx, usage); err != nil {
		return fmt.Errorf("failed to set user grant usage: %w", err)
	}

	// Emit sponsor usage updated event
	ctx.EventManager().EmitEvent(
		sdk.NewEvent(
			types.EventTypeSponsorUsage,
			sdk.NewAttribute(types.AttributeKeyUser, userAddr),
			sdk.NewAttribute(types.AttributeKeyContractAddress, contractAddr),
			sdk.NewAttribute(types.AttributeKeySponsorAmount, consumedAmount.String()),
		),
	)

	return nil
}

// GetMaxGrantPerUser returns the maximum grant amount per user for a contract
func (k Keeper) GetMaxGrantPerUser(ctx sdk.Context, contractAddr string) sdk.Coins {
	sponsor, found := k.GetSponsor(ctx, contractAddr)
	if !found || len(sponsor.MaxGrantPerUser) == 0 {
		// Return default limit if not configured - 1 DORA = 10^18 peaka
		amount, _ := sdk.NewIntFromString("1000000000000000000")
		return sdk.NewCoins(sdk.NewCoin("peaka", amount)) // 1 DORA default
	}

	// Convert from protobuf Coin to sdk.Coins
	coins := make(sdk.Coins, len(sponsor.MaxGrantPerUser))
	for i, coin := range sponsor.MaxGrantPerUser {
		coins[i] = *coin // Dereference the pointer
	}

	return coins
}

// CheckUserGrantLimit checks if a user can use the requested grant amount
func (k Keeper) CheckUserGrantLimit(ctx sdk.Context, userAddr, contractAddr string, requestedAmount sdk.Coins) error {
	// Get user's current usage
	usage := k.GetUserGrantUsage(ctx, userAddr, contractAddr)

	// Get the maximum grant limit for this contract
	maxLimit := k.GetMaxGrantPerUser(ctx, contractAddr)

	// Convert []*sdk.Coin to sdk.Coins for calculation
	currentUsed := sdk.Coins{}
	for _, coin := range usage.TotalGrantUsed {
		if coin != nil {
			currentUsed = currentUsed.Add(*coin)
		}
	}

	// Calculate total after this transaction
	totalAfterTx := currentUsed.Add(requestedAmount...)

	// Check if it exceeds the limit
	if !maxLimit.IsAllGTE(totalAfterTx) {
		return types.ErrUserGrantLimitExceeded.Wrapf(
			"user %s grant limit exceeded for contract %s: used %s + requested %s > limit %s",
			userAddr,
			contractAddr,
			usage.TotalGrantUsed,
			requestedAmount,
			maxLimit,
		)
	}

	return nil
}
