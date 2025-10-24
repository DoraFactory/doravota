package keeper

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	errorsmod "cosmossdk.io/errors"
	wasmtypes "github.com/CosmWasm/wasmd/x/wasm/types"
	"github.com/cometbft/cometbft/libs/log"
	"github.com/cosmos/cosmos-sdk/codec"
	"github.com/cosmos/cosmos-sdk/store/prefix"
	storetypes "github.com/cosmos/cosmos-sdk/store/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
	sdkerrors "github.com/cosmos/cosmos-sdk/types/errors"
    "github.com/cosmos/cosmos-sdk/types/query"

    "github.com/DoraFactory/doravota/x/sponsor-contract-tx/types"
)

// (legacy ContractMessage and policy probe helpers removed)

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

	// authority is the address capable of executing governance proposals
	// typically the gov module account
	authority string
}

// NewKeeper creates a new sponsor Keeper instance
func NewKeeper(cdc codec.BinaryCodec, storeKey storetypes.StoreKey, wasmKeeper WasmKeeperInterface, authority string) *Keeper {
	return &Keeper{
		cdc:        cdc,
		storeKey:   storeKey,
		wasmKeeper: wasmKeeper,
		authority:  authority,
	}
}

// Logger returns a module-specific logger
func (k Keeper) Logger(ctx sdk.Context) log.Logger {
	return ctx.Logger().With("module", fmt.Sprintf("x/%s", types.ModuleName))
}

// Cdc exposes the keeper codec for internal module usage (e.g., genesis export)
func (k Keeper) Cdc() codec.BinaryCodec { return k.cdc }

// GetAuthority returns the authority address for governance
func (k Keeper) GetAuthority() string {
	return k.authority
}

// ComputeMethodDigest computes sha256(contract_address || "method:" || method_names_in_order)
func (k Keeper) ComputeMethodDigest(contractAddr string, methodNames []string) string {
	h := sha256.New()
	h.Write([]byte(contractAddr))
	h.Write([]byte("method:"))
	for i, m := range methodNames {
		h.Write([]byte(m))
		if i < len(methodNames)-1 {
			h.Write([]byte{"\x00"[0]}) // separator to avoid collisions
		}
	}
	return "m:" + hex.EncodeToString(h.Sum(nil))
}

// EffectiveTicketTTLForContract computes the effective TTL in blocks for a contract, honoring per-sponsor override and global cap
func (k Keeper) EffectiveTicketTTLForContract(ctx sdk.Context, contractAddr string) uint32 {
	eff := k.GetParams(ctx).PolicyTicketTtlBlocks
	if eff == 0 {
		eff = 1
	}
	return eff
}

// === Ticket storage ===

func (k Keeper) GetPolicyTicket(ctx sdk.Context, contractAddr, userAddr, digest string) (types.PolicyTicket, bool) {
	store := ctx.KVStore(k.storeKey)
	key := types.GetPolicyTicketKey(contractAddr, userAddr, digest)
	bz := store.Get(key)
	if bz == nil {
		return types.PolicyTicket{}, false
	}
	var t types.PolicyTicket
	if err := k.cdc.Unmarshal(bz, &t); err != nil {
		k.Logger(ctx).Error("failed to unmarshal policy ticket", "err", err)
		return types.PolicyTicket{}, false
	}
	return t, true
}

func (k Keeper) SetPolicyTicket(ctx sdk.Context, t types.PolicyTicket) error {
	store := ctx.KVStore(k.storeKey)
	key := types.GetPolicyTicketKey(t.ContractAddress, t.UserAddress, t.Digest)
	bz, err := k.cdc.Marshal(&t)
	if err != nil {
		return err
	}
	store.Set(key, bz)
	return nil
}

// IteratePolicyTickets iterates over all stored policy tickets and invokes cb for each.
// If cb returns true, iteration stops early.
func (k Keeper) IteratePolicyTickets(ctx sdk.Context, cb func(key []byte, t types.PolicyTicket) (stop bool)) {
	store := prefix.NewStore(ctx.KVStore(k.storeKey), types.PolicyTicketKeyPrefix)
	it := sdk.KVStorePrefixIterator(store, []byte{})
	defer it.Close()
	for ; it.Valid(); it.Next() {
		var t types.PolicyTicket
		if err := k.cdc.Unmarshal(it.Value(), &t); err != nil {
			k.Logger(ctx).Error("failed to unmarshal policy ticket during iteration", "err", err)
			continue
		}
		if cb(it.Key(), t) {
			break
		}
	}
}

// GetPolicyTicketsPaginated returns policy tickets filtered by contract and optional user with pagination.
// contractAddr must be non-empty and a valid bech32 address; userAddr may be empty (to list all users).
func (k Keeper) GetPolicyTicketsPaginated(ctx sdk.Context, contractAddr, userAddr string, pageReq *query.PageRequest) ([]*types.PolicyTicket, *query.PageResponse, error) {
    if err := types.ValidateContractAddress(contractAddr); err != nil {
        return nil, nil, err
    }
    if userAddr != "" {
        if _, err := sdk.AccAddressFromBech32(userAddr); err != nil {
            return nil, nil, errorsmod.Wrap(sdkerrors.ErrInvalidAddress, "invalid user address")
        }
    }
    pstore := prefix.NewStore(ctx.KVStore(k.storeKey), types.PolicyTicketKeyPrefix)
    // Build prefix: contract + "/" [+ user + "/" when provided]
    p := append([]byte{}, []byte(contractAddr)...)
    p = append(p, '/')
    if userAddr != "" {
        p = append(p, []byte(userAddr)...)
        p = append(p, '/')
    }
    sub := prefix.NewStore(pstore, p)
    var out []*types.PolicyTicket
    pageRes, err := query.Paginate(sub, pageReq, func(key, value []byte) error {
        var t types.PolicyTicket
        if err := k.cdc.Unmarshal(value, &t); err != nil {
            return err
        }
        tt := t
        out = append(out, &tt)
        return nil
    })
    if err != nil {
        return nil, nil, err
    }
    return out, pageRes, nil
}

// CountLiveTicketsForUserContract returns the number of unconsumed, unexpired tickets for (contract,user).
// Capacity limits removed: whitelist-based issuance provides sufficient control.
// HasAnyLiveMethodTicket returns true if there exists at least one unconsumed, unexpired
// method-bound ticket for (contract,user). This is a fast-path existence check for CheckTx.
func (k Keeper) HasAnyLiveMethodTicket(ctx sdk.Context, contractAddr, userAddr string) bool {
	store := prefix.NewStore(ctx.KVStore(k.storeKey), types.PolicyTicketKeyPrefix)
	// Prefix: contract + "/" + user + "/"
	p := append([]byte{}, []byte(contractAddr)...)
	p = append(p, '/')
	p = append(p, []byte(userAddr)...)
	p = append(p, '/')
	it := sdk.KVStorePrefixIterator(store, p)
	defer it.Close()
	now := uint64(ctx.BlockHeight())
	for ; it.Valid(); it.Next() {
		var t types.PolicyTicket
		if err := k.cdc.Unmarshal(it.Value(), &t); err != nil {
			continue
		}
		if t.Consumed {
			continue
		}
		if now > t.ExpiryHeight {
			continue
		}
		if len(t.Digest) >= 2 && t.Digest[0] == 'm' && t.Digest[1] == ':' {
			return true
		}
	}
	return false
}

// ConsumePolicyTicket marks a policy ticket as consumed if present and valid
func (k Keeper) ConsumePolicyTicket(ctx sdk.Context, contractAddr, userAddr, digest string) error {
	t, ok := k.GetPolicyTicket(ctx, contractAddr, userAddr, digest)
	if !ok {
		return errorsmod.Wrap(sdkerrors.ErrInvalidRequest, "ticket not found")
	}
	if t.Consumed {
		return nil
	}
	// New semantics:
	// 1 -> single-use; >1 -> multi-use; 0 -> no usable ticket
	if t.UsesRemaining == 0 {
		return errorsmod.Wrap(sdkerrors.ErrInvalidRequest, "ticket has no remaining uses")
	}
	if t.UsesRemaining > 1 {
		t.UsesRemaining -= 1
		if t.UsesRemaining == 0 {
			t.Consumed = true
		}
	} else {
		t.UsesRemaining = 0
		t.Consumed = true
	}
	return k.SetPolicyTicket(ctx, t)
}

// ConsumePolicyTicketsBulk validates that for each digest there are at least the required
// uses remaining and tickets are unconsumed and unexpired, and then consumes them. Either
// all tickets are consumed or the operation fails without partial consumption.
func (k Keeper) ConsumePolicyTicketsBulk(ctx sdk.Context, contractAddr, userAddr string, counts map[string]uint32) error {
	now := uint64(ctx.BlockHeight())
	updated := make(map[string]types.PolicyTicket, len(counts))
	// Validate and compute updated state in-memory
	for md, cnt := range counts {
		t, ok := k.GetPolicyTicket(ctx, contractAddr, userAddr, md)
		if !ok {
			return errorsmod.Wrap(sdkerrors.ErrInvalidRequest, "ticket not found")
		}
		if t.Consumed {
			return errorsmod.Wrap(sdkerrors.ErrInvalidRequest, "ticket already consumed")
		}
		if now > t.ExpiryHeight {
			return errorsmod.Wrap(sdkerrors.ErrInvalidRequest, "ticket expired")
		}
		if t.UsesRemaining < cnt {
			return errorsmod.Wrap(sdkerrors.ErrInvalidRequest, "insufficient ticket uses")
		}
		// apply in-memory
		t.UsesRemaining -= cnt
		if t.UsesRemaining == 0 {
			t.Consumed = true
		}
		updated[md] = t
	}
	// Apply updates to store
	for md, t := range updated {
		if err := k.SetPolicyTicket(ctx, t); err != nil {
			return err
		}
		_ = md
	}
	return nil
}

// DeletePolicyTicket removes a policy ticket by composite key
func (k Keeper) DeletePolicyTicket(ctx sdk.Context, contractAddr, userAddr, digest string) {
	store := ctx.KVStore(k.storeKey)
	key := types.GetPolicyTicketKey(contractAddr, userAddr, digest)
	store.Delete(key)
}

// RevokePolicyTicket removes a policy ticket for (contract,user,digest) if it exists and is not consumed.
// If the ticket is already consumed or does not exist, it returns an error to signal no-op.
func (k Keeper) RevokePolicyTicket(ctx sdk.Context, contractAddr, userAddr, digest string) error {
	t, ok := k.GetPolicyTicket(ctx, contractAddr, userAddr, digest)
	if !ok {
		return errorsmod.Wrap(sdkerrors.ErrInvalidRequest, "ticket not found")
	}
	if t.Consumed {
		return errorsmod.Wrap(sdkerrors.ErrInvalidRequest, "ticket already consumed")
	}
	k.DeletePolicyTicket(ctx, contractAddr, userAddr, digest)
	return nil
}

// GarbageCollect removes up to maxTickets expired tickets per call to avoid state bloat.
func (k Keeper) GarbageCollect(ctx sdk.Context, maxTickets int) {
	now := uint64(ctx.BlockHeight())
	// Tickets
	removed := 0
    if maxTickets > 0 {
        pstore := prefix.NewStore(ctx.KVStore(k.storeKey), types.PolicyTicketKeyPrefix)
        it := sdk.KVStorePrefixIterator(pstore, []byte{})
        defer it.Close()
        for ; it.Valid(); it.Next() {
            var t types.PolicyTicket
            if err := k.cdc.Unmarshal(it.Value(), &t); err != nil {
                k.Logger(ctx).Error("failed to unmarshal policy ticket during GC", "err", err)
                continue
            }
            // Remove tickets strictly past their expiry height. No special-case for 0;
            // if a ticket somehow has expiry 0, it is considered expired as soon as
            // block height advances beyond 0. Issued tickets always have TTL > 0.
            if now > t.ExpiryHeight {
                pstore.Delete(it.Key())
                removed++
                if removed >= maxTickets {
                    break
                }
            }
        }
    }
}

// SetSponsor sets a sponsor in the store
func (k Keeper) SetSponsor(ctx sdk.Context, sponsor types.ContractSponsor) error {
	// Normalize MaxGrantPerUser before storing to merge duplicates
	normalized, err := types.NormalizeMaxGrantPerUser(sponsor.MaxGrantPerUser)
	if err != nil {
		return errorsmod.Wrap(err, "failed to normalize max grant per user")
	}
	sponsor.MaxGrantPerUser = normalized

	store := ctx.KVStore(k.storeKey)
	key := types.GetSponsorKey(sponsor.ContractAddress)

	bz, err := k.cdc.Marshal(&sponsor)
	if err != nil {
		return errorsmod.Wrap(err, "failed to marshal sponsor")
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
		return errorsmod.Wrap(sdkerrors.ErrInvalidAddress, fmt.Sprintf("invalid contract address: %s", err.Error()))
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
		return false, errorsmod.Wrap(sdkerrors.ErrInvalidAddress, fmt.Sprintf("invalid contract address: %s", err.Error()))
	}

	// Get contract info from wasm keeper (we know it exists from validation above)
	contractInfo := k.wasmKeeper.GetContractInfo(ctx, contractAccAddr)

	// Check if the user is the admin
	return contractInfo.Admin == userAddr.String(), nil
}

// IsSponsorManager checks whether the caller is authorized to manage sponsorship
// for the given contract. Authorization rule:
// - If contract Admin exists: only current Admin is authorized
// - If Admin is cleared: the original Sponsor.CreatorAddress is authorized (fallback)
func (k Keeper) IsSponsorManager(ctx sdk.Context, contractAddr string, caller sdk.AccAddress) (bool, error) {
	// Validate contract exists
	if err := k.ValidateContractExists(ctx, contractAddr); err != nil {
		return false, err
	}
	// Current admin wins
	if ok, err := k.IsContractAdmin(ctx, contractAddr, caller); err != nil {
		return false, err
	} else if ok {
		return true, nil
	}
	// Check if admin cleared, then fallback to sponsor creator
	contractAccAddr, err := sdk.AccAddressFromBech32(contractAddr)
	if err != nil {
		return false, errorsmod.Wrap(sdkerrors.ErrInvalidAddress, fmt.Sprintf("invalid contract address: %s", err.Error()))
	}
	cinfo := k.wasmKeeper.GetContractInfo(ctx, contractAccAddr)
	if cinfo == nil {
		return false, types.ErrContractNotFound.Wrapf("contract not found: %s", contractAddr)
	}
	if cinfo.Admin == "" {
		sponsor, found := k.GetSponsor(ctx, contractAddr)
		if !found {
			return false, nil
		}
		if sponsor.CreatorAddress == caller.String() {
			return true, nil
		}
	}
	return false, nil
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

// IterateUserGrantUsages iterates over all user grant usage entries and calls the provided callback
func (k Keeper) IterateUserGrantUsages(ctx sdk.Context, cb func(usage types.UserGrantUsage) (stop bool)) {
	store := prefix.NewStore(ctx.KVStore(k.storeKey), types.UserGrantUsageKeyPrefix)
	iterator := sdk.KVStorePrefixIterator(store, []byte{})
	defer iterator.Close()

	for ; iterator.Valid(); iterator.Next() {
		var usage types.UserGrantUsage

		if err := k.cdc.Unmarshal(iterator.Value(), &usage); err != nil {
			k.Logger(ctx).Error("failed to unmarshal user grant usage during iteration", "error", err)
			continue
		}

		if cb(usage) {
			break
		}
	}
}

// GetAllUserGrantUsages returns every user grant usage entry in the store
func (k Keeper) GetAllUserGrantUsages(ctx sdk.Context) []types.UserGrantUsage {
	var usages []types.UserGrantUsage

	k.IterateUserGrantUsages(ctx, func(usage types.UserGrantUsage) bool {
		usages = append(usages, usage)
		return false
	})

	return usages
}

// GetSponsorsPaginated returns sponsors with pagination support
func (k Keeper) GetSponsorsPaginated(ctx sdk.Context, pageReq *query.PageRequest) ([]*types.ContractSponsor, *query.PageResponse, error) {
	var sponsors []*types.ContractSponsor

	store := prefix.NewStore(ctx.KVStore(k.storeKey), types.SponsorKeyPrefix)

	pageRes, err := query.Paginate(store, pageReq, func(key []byte, value []byte) error {
		var sponsor types.ContractSponsor

		err := k.cdc.Unmarshal(value, &sponsor)
		if err != nil {
			return errorsmod.Wrap(err, "failed to unmarshal sponsor data")
		}

		sponsors = append(sponsors, &sponsor)
		return nil
	})

	if err != nil {
		return nil, nil, err
	}

	return sponsors, pageRes, nil
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
		return errorsmod.Wrap(err, "failed to marshal params")
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
		return errorsmod.Wrap(err, "failed to marshal user grant usage")
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
		coinCopy := coin
		usage.TotalGrantUsed[i] = &coinCopy
	}

	usage.LastUsedTime = ctx.BlockTime().Unix()
	if err := k.SetUserGrantUsage(ctx, usage); err != nil {
		return errorsmod.Wrap(err, "failed to set user grant usage")
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
// Returns an error if no sponsor exists or MaxGrantPerUser is not configured when sponsorship is enabled
func (k Keeper) GetMaxGrantPerUser(ctx sdk.Context, contractAddr string) (sdk.Coins, error) {
	sponsor, found := k.GetSponsor(ctx, contractAddr)
	if !found {
		return sdk.Coins{}, errorsmod.Wrap(types.ErrSponsorNotFound, fmt.Sprintf("no sponsor configuration found for contract %s", contractAddr))
	}

	// If sponsorship is disabled, max_grant_per_user is not relevant
	if !sponsor.IsSponsored {
		return sdk.Coins{}, errorsmod.Wrap(types.ErrSponsorshipDisabled, fmt.Sprintf("sponsorship is disabled for contract %s", contractAddr))
	}

	if len(sponsor.MaxGrantPerUser) == 0 {
		return sdk.Coins{}, errorsmod.Wrap(sdkerrors.ErrInvalidRequest, fmt.Sprintf("max_grant_per_user is required but not configured for contract %s", contractAddr))
	}

	// Convert from protobuf Coin to sdk.Coins
	coins := make(sdk.Coins, len(sponsor.MaxGrantPerUser))
	for i, coin := range sponsor.MaxGrantPerUser {
		coins[i] = *coin // Dereference the pointer
	}

	return coins, nil
}

// CheckUserGrantLimit checks if a user can use the requested grant amount
func (k Keeper) CheckUserGrantLimit(ctx sdk.Context, userAddr, contractAddr string, requestedAmount sdk.Coins) error {
	// Get user's current usage
	usage := k.GetUserGrantUsage(ctx, userAddr, contractAddr)

	// Get the maximum grant limit for this contract
	maxLimit, err := k.GetMaxGrantPerUser(ctx, contractAddr)
	if err != nil {
		return errorsmod.Wrap(err, "failed to get max grant per user")
	}

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
