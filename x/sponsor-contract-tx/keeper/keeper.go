package keeper

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"

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

// WasmKeeper exposes the module dependency for simulation wiring.
func (k Keeper) WasmKeeper() types.WasmKeeperInterface { return k.wasmKeeper }

// GetAuthority returns the authority address for governance
func (k Keeper) GetAuthority() string {
	return k.authority
}

// ComputeMethodDigest computes sha256(contract_address || "method:" || method_names_in_order)
func (k Keeper) ComputeMethodDigest(contractAddr string, methodNames []string) string {
	contractAddr = types.CanonicalAddressOrOriginal(contractAddr)
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

// ComputeMethodDigestSingle computes sha256(contract_address || "method:" || method_name) for a single method.
// This avoids temporary slice allocation when only one method name is involved.
func (k Keeper) ComputeMethodDigestSingle(contractAddr, methodName string) string {
	contractAddr = types.CanonicalAddressOrOriginal(contractAddr)
	h := sha256.New()
	h.Write([]byte(contractAddr))
	h.Write([]byte("method:"))
	h.Write([]byte(methodName))
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

// GetActivePolicyTicket returns a ticket only when it belongs to the current
// Sponsor lifecycle. Historical tickets remain in storage for bounded GC, but
// can never authorize a transaction after Sponsor deletion.
func (k Keeper) GetActivePolicyTicket(ctx sdk.Context, contractAddr, userAddr, digest string) (types.PolicyTicket, bool) {
	ticket, found := k.GetPolicyTicket(ctx, contractAddr, userAddr, digest)
	if !found {
		return types.PolicyTicket{}, false
	}
	sponsor, found := k.GetSponsor(ctx, contractAddr)
	if !found {
		// Preserve low-level legacy/test behavior only when this contract has
		// never had a lifecycle. Deleted Sponsors always retain a non-zero
		// generation tombstone and therefore cannot take this path.
		if k.GetSponsorGeneration(ctx, contractAddr) == 0 && ticket.Generation == 0 {
			return ticket, true
		}
		return types.PolicyTicket{}, false
	}
	if sponsor.Generation == 0 || ticket.Generation != sponsor.Generation {
		return types.PolicyTicket{}, false
	}
	return ticket, true
}

// SetPolicyTicket is the low-level storage primitive retained for legacy test
// fixtures. Runtime code must use SetActivePolicyTicket; genesis import must
// use SetPolicyTicketForGenesis.
func (k Keeper) SetPolicyTicket(ctx sdk.Context, t types.PolicyTicket) error {
	store := ctx.KVStore(k.storeKey)
	t.ContractAddress = types.CanonicalAddressOrOriginal(t.ContractAddress)
	t.UserAddress = types.CanonicalAddressOrOriginal(t.UserAddress)
	if t.Generation == 0 {
		if sponsor, found := k.GetSponsor(ctx, t.ContractAddress); found {
			t.Generation = sponsor.Generation
		}
	}
	key := types.GetPolicyTicketKey(t.ContractAddress, t.UserAddress, t.Digest)
	bz, err := k.cdc.Marshal(&t)
	if err != nil {
		return err
	}
	// If a caller replaces a ticket with a different expiry height, remove the
	// previous index first. This keeps the secondary index canonical and also
	// prevents a stale expiry entry from targeting the renewed ticket.
	if previousBz := store.Get(key); previousBz != nil {
		var previous types.PolicyTicket
		if err := k.cdc.Unmarshal(previousBz, &previous); err == nil && previous.ExpiryHeight != t.ExpiryHeight {
			previousIndex := types.GetExpiryIndexKey(
				previous.ExpiryHeight,
				previous.ContractAddress,
				previous.UserAddress,
				previous.Digest,
			)
			store.Delete(previousIndex)
		}
	}
	store.Set(key, bz)
	// maintain expiry index for fast GC by expiry height
	idx := types.GetExpiryIndexKey(t.ExpiryHeight, t.ContractAddress, t.UserAddress, t.Digest)
	store.Set(idx, []byte{})
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
		if err := types.ValidateCanonicalAddress(userAddr); err != nil {
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
	sponsor, found := k.GetSponsor(ctx, contractAddr)
	currentGeneration := uint64(0)
	if found {
		currentGeneration = sponsor.Generation
	} else if k.GetSponsorGeneration(ctx, contractAddr) != 0 {
		return []*types.PolicyTicket{}, &query.PageResponse{}, nil
	}
	pageRes, err := query.FilteredPaginate(sub, pageReq, func(key, value []byte, accumulate bool) (bool, error) {
		var t types.PolicyTicket
		if err := k.cdc.Unmarshal(value, &t); err != nil {
			return false, err
		}
		matchesCurrentGeneration := t.Generation == currentGeneration
		if matchesCurrentGeneration && accumulate {
			tt := t
			out = append(out, &tt)
		}
		return matchesCurrentGeneration, nil
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
// HasAnyLiveMethodTicket removed; ante now checks exact digests derived from tx methods.

// ConsumePolicyTicket marks a policy ticket as consumed if present and valid
func (k Keeper) ConsumePolicyTicket(ctx sdk.Context, contractAddr, userAddr, digest string) error {
	t, ok := k.GetActivePolicyTicket(ctx, contractAddr, userAddr, digest)
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
		// last use -> mark consumed and keep record until expiry (GC will remove)
		t.UsesRemaining = 0
		t.Consumed = true
	}
	return k.setCurrentOrLegacyPolicyTicket(ctx, t)
}

// ConsumePolicyTicketsBulk validates that for each digest there are at least the required
// uses remaining and tickets are unconsumed and unexpired, and then consumes them. Either
// all tickets are consumed or the operation fails without partial consumption.
func (k Keeper) ConsumePolicyTicketsBulk(ctx sdk.Context, contractAddr, userAddr string, counts map[string]uint32) error {
	if len(counts) == 0 {
		return errorsmod.Wrap(sdkerrors.ErrInvalidRequest, "ticket consumption counts cannot be empty")
	}

	now := uint64(ctx.BlockHeight())
	digests := make([]string, 0, len(counts))
	for digest := range counts {
		digests = append(digests, digest)
	}
	sort.Strings(digests)

	updated := make([]types.PolicyTicket, 0, len(digests))
	// Validate and compute updated state in-memory
	for _, digest := range digests {
		count := counts[digest]
		if digest == "" {
			return errorsmod.Wrap(sdkerrors.ErrInvalidRequest, "ticket digest cannot be empty")
		}
		if count == 0 {
			return errorsmod.Wrapf(
				sdkerrors.ErrInvalidRequest,
				"ticket %s consumption count must be positive",
				digest,
			)
		}
		t, ok := k.GetActivePolicyTicket(ctx, contractAddr, userAddr, digest)
		if !ok {
			return errorsmod.Wrapf(sdkerrors.ErrInvalidRequest, "ticket %s not found", digest)
		}
		if t.Consumed {
			return errorsmod.Wrapf(sdkerrors.ErrInvalidRequest, "ticket %s already consumed", digest)
		}
		if now > t.ExpiryHeight {
			return errorsmod.Wrapf(sdkerrors.ErrInvalidRequest, "ticket %s expired", digest)
		}
		if t.UsesRemaining < count {
			return errorsmod.Wrapf(sdkerrors.ErrInvalidRequest, "ticket %s has insufficient uses", digest)
		}
		// apply in-memory
		t.UsesRemaining -= count
		if t.UsesRemaining == 0 {
			t.Consumed = true
		}
		updated = append(updated, t)
	}

	// Apply updates through a nested cache so direct Keeper callers receive
	// the same all-or-nothing guarantee as callers running inside an Ante cache.
	cacheCtx, write := ctx.CacheContext()
	for _, t := range updated {
		if err := k.setCurrentOrLegacyPolicyTicket(cacheCtx, t); err != nil {
			return err
		}
	}
	write()
	return nil
}

// DeletePolicyTicket removes a policy ticket by composite key
func (k Keeper) DeletePolicyTicket(ctx sdk.Context, contractAddr, userAddr, digest string) {
	store := ctx.KVStore(k.storeKey)
	// try delete expiry index if ticket present
	if t, ok := k.GetPolicyTicket(ctx, contractAddr, userAddr, digest); ok {
		idx := types.GetExpiryIndexKey(t.ExpiryHeight, contractAddr, userAddr, digest)
		store.Delete(idx)
	}
	key := types.GetPolicyTicketKey(contractAddr, userAddr, digest)
	store.Delete(key)
}

// RevokePolicyTicket removes a policy ticket for (contract,user,digest) if it exists and is not consumed.
// If the ticket is already consumed or does not exist, it returns an error to signal no-op.
func (k Keeper) RevokePolicyTicket(ctx sdk.Context, contractAddr, userAddr, digest string) error {
	t, ok := k.GetActivePolicyTicket(ctx, contractAddr, userAddr, digest)
	if !ok {
		return errorsmod.Wrap(sdkerrors.ErrInvalidRequest, "ticket not found")
	}
	if t.Consumed {
		return errorsmod.Wrap(sdkerrors.ErrInvalidRequest, "ticket already consumed")
	}
	k.DeletePolicyTicket(ctx, contractAddr, userAddr, digest)
	return nil
}

type expiryIndexCandidate struct {
	indexKey     []byte
	ticketKey    []byte
	expiryHeight uint64
	malformed    bool
}

type garbageCollectionResult struct {
	scanned        int
	removed        int
	invalidIndexes int
}

// GarbageCollectByExpiry removes expired policy tickets through the globally
// ordered expiry index. Both index inspection and deletion are bounded, so the
// work performed in BeginBlock is independent of the current chain height.
func (k Keeper) GarbageCollectByExpiry(ctx sdk.Context, maxEntries int) {
	result := k.garbageCollectByExpiry(ctx, maxEntries)
	if result.invalidIndexes > 0 {
		k.Logger(ctx).Error(
			"removed invalid policy ticket expiry indexes",
			"count", result.invalidIndexes,
		)
	}
}

func (k Keeper) garbageCollectByExpiry(ctx sdk.Context, maxEntries int) garbageCollectionResult {
	var result garbageCollectionResult
	if maxEntries <= 0 || ctx.BlockHeight() <= 0 {
		return result
	}

	limit := maxEntries
	if limit > int(types.MaxTicketGCPerBlock) {
		limit = int(types.MaxTicketGCPerBlock)
	}

	now := uint64(ctx.BlockHeight())
	store := ctx.KVStore(k.storeKey)
	expiryStore := prefix.NewStore(store, types.ExpiryIndexKeyPrefix)
	iterator := expiryStore.Iterator(nil, nil)
	candidates := make([]expiryIndexCandidate, 0, limit)

	for ; iterator.Valid() && result.scanned < limit; iterator.Next() {
		indexKey := append([]byte(nil), iterator.Key()...)
		result.scanned++

		expiryHeight, ticketKey, ok := types.ParseExpiryIndexKey(indexKey)
		if !ok {
			candidates = append(candidates, expiryIndexCandidate{
				indexKey:  indexKey,
				malformed: true,
			})
			continue
		}

		// A ticket remains valid at its expiry height. Since the index is
		// ordered by big-endian expiry height, all following entries are also
		// unexpired and can be skipped for this block.
		if expiryHeight >= now {
			break
		}

		candidates = append(candidates, expiryIndexCandidate{
			indexKey:     indexKey,
			ticketKey:    append([]byte(nil), ticketKey...),
			expiryHeight: expiryHeight,
		})
	}
	iterator.Close()

	ticketStore := prefix.NewStore(store, types.PolicyTicketKeyPrefix)
	for _, candidate := range candidates {
		if candidate.malformed {
			expiryStore.Delete(candidate.indexKey)
			result.invalidIndexes++
			continue
		}

		bz := ticketStore.Get(candidate.ticketKey)
		if bz == nil {
			expiryStore.Delete(candidate.indexKey)
			result.invalidIndexes++
			continue
		}

		var ticket types.PolicyTicket
		if err := k.cdc.Unmarshal(bz, &ticket); err != nil {
			// The index cannot be trusted to identify a corrupt primary value.
			// Remove only the index so GC continues to make bounded progress.
			expiryStore.Delete(candidate.indexKey)
			result.invalidIndexes++
			continue
		}

		expectedKey := types.GetPolicyTicketKey(ticket.ContractAddress, ticket.UserAddress, ticket.Digest)
		expectedTicketKey := expectedKey[len(types.PolicyTicketKeyPrefix):]
		if ticket.ExpiryHeight != candidate.expiryHeight ||
			!bytes.Equal(expectedTicketKey, candidate.ticketKey) {
			// This is an obsolete or inconsistent index. Never use it to delete
			// a ticket that may have been renewed under the same primary key.
			expiryStore.Delete(candidate.indexKey)
			result.invalidIndexes++
			continue
		}

		ticketStore.Delete(candidate.ticketKey)
		expiryStore.Delete(candidate.indexKey)
		result.removed++
	}

	return result
}

// SetSponsor is the low-level storage primitive retained for legacy test
// fixtures. Runtime code must use SetActiveSponsor; genesis import must use
// SetSponsorForGenesis.
func (k Keeper) SetSponsor(ctx sdk.Context, sponsor types.ContractSponsor) error {
	sponsor.ContractAddress = types.CanonicalAddressOrOriginal(sponsor.ContractAddress)
	sponsor.CreatorAddress = types.CanonicalAddressOrOriginal(sponsor.CreatorAddress)
	sponsor.SponsorAddress = types.CanonicalAddressOrOriginal(sponsor.SponsorAddress)
	if sponsor.TicketIssuerAddress != "" {
		sponsor.TicketIssuerAddress = types.CanonicalAddressOrOriginal(sponsor.TicketIssuerAddress)
	}

	// Normalize MaxGrantPerUser before storing to merge duplicates
	normalized, err := types.NormalizeMaxGrantPerUser(sponsor.MaxGrantPerUser)
	if err != nil {
		return errorsmod.Wrap(err, "failed to normalize max grant per user")
	}
	sponsor.MaxGrantPerUser = normalized

	if err := k.bindSponsorGeneration(ctx, &sponsor); err != nil {
		return errorsmod.Wrap(err, "failed to bind sponsor generation")
	}

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
	sponsor, found := k.GetSponsor(ctx, contractAddr)
	if !found {
		return nil
	}
	if err := k.rotateSponsorGeneration(ctx, sponsor); err != nil {
		return errorsmod.Wrap(err, "failed to rotate sponsor generation")
	}
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
	if err := types.ValidateContractAddress(contractAddr); err != nil {
		return err
	}
	contractAccAddr, _ := types.AccAddressFromCanonicalBech32(contractAddr)

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
	contractAccAddr, _ := types.AccAddressFromCanonicalBech32(contractAddr)

	// Get contract info from wasm keeper (we know it exists from validation above)
	contractInfo := k.wasmKeeper.GetContractInfo(ctx, contractAccAddr)

	// Check if the user is the admin
	return contractInfo.Admin == userAddr.String(), nil
}

// HasContractAdmin reports whether the contract still has a current Wasm
// admin. Active Sponsor state is not valid after the contract permanently
// clears its admin.
func (k Keeper) HasContractAdmin(ctx sdk.Context, contractAddr string) (bool, error) {
	if err := k.ValidateContractExists(ctx, contractAddr); err != nil {
		return false, err
	}

	contractAccAddr, _ := types.AccAddressFromCanonicalBech32(contractAddr)
	contractInfo := k.wasmKeeper.GetContractInfo(ctx, contractAccAddr)
	return contractInfo.Admin != "", nil
}

// IsSponsorManager checks whether the caller is authorized to manage sponsorship
// for the given contract. Authorization rule:
//   - Only the current Wasm contract Admin is authorized.
//   - Clearing the contract Admin never revives authority for the original
//     Sponsor creator.
func (k Keeper) IsSponsorManager(ctx sdk.Context, contractAddr string, caller sdk.AccAddress) (bool, error) {
	return k.IsContractAdmin(ctx, contractAddr, caller)
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
	if err := params.Validate(); err != nil {
		return errorsmod.Wrap(err, "invalid sponsor params")
	}
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
		usage := types.NewUserGrantUsage(userAddr, contractAddr)
		if sponsor, found := k.GetSponsor(ctx, contractAddr); found {
			usage.Generation = sponsor.Generation
		}
		return usage
	}

	var usage types.UserGrantUsage
	err := k.cdc.Unmarshal(bz, &usage)
	if err != nil {
		// Log error and return new usage record
		k.Logger(ctx).Error("failed to unmarshal user grant usage", "user", userAddr, "contract", contractAddr, "error", err)
		usage := types.NewUserGrantUsage(userAddr, contractAddr)
		if sponsor, found := k.GetSponsor(ctx, contractAddr); found {
			usage.Generation = sponsor.Generation
		}
		return usage
	}

	sponsor, found := k.GetSponsor(ctx, contractAddr)
	if !found {
		if k.GetSponsorGeneration(ctx, contractAddr) == 0 && usage.Generation == 0 {
			return usage
		}
		return types.NewUserGrantUsage(userAddr, contractAddr)
	}
	if sponsor.Generation == 0 || usage.Generation != sponsor.Generation {
		current := types.NewUserGrantUsage(userAddr, contractAddr)
		current.Generation = sponsor.Generation
		return current
	}

	return usage
}

// SetUserGrantUsage is the low-level storage primitive retained for legacy test
// fixtures. Runtime code must use SetActiveUserGrantUsage; genesis import must
// use SetUserGrantUsageForGenesis.
func (k Keeper) SetUserGrantUsage(ctx sdk.Context, usage types.UserGrantUsage) error {
	store := ctx.KVStore(k.storeKey)
	usage.UserAddress = types.CanonicalAddressOrOriginal(usage.UserAddress)
	usage.ContractAddress = types.CanonicalAddressOrOriginal(usage.ContractAddress)
	if usage.Generation == 0 {
		if sponsor, found := k.GetSponsor(ctx, usage.ContractAddress); found {
			usage.Generation = sponsor.Generation
		}
	}
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
	sponsor, found := k.GetSponsor(ctx, contractAddr)
	if !found {
		if k.GetSponsorGeneration(ctx, contractAddr) != 0 {
			return errorsmod.Wrap(types.ErrSponsorNotFound, "cannot update usage without an active sponsor lifecycle")
		}
	} else {
		if sponsor.Generation == 0 {
			return errorsmod.Wrap(types.ErrSponsorNotFound, "cannot update usage without an active sponsor lifecycle")
		}
		usage.Generation = sponsor.Generation
	}

	currentUsed, err := grantUsageAmount(usage.TotalGrantUsed)
	if err != nil {
		return errorsmod.Wrap(err, "invalid existing user grant usage")
	}
	consumed, err := sponsorshipCoinAmount(consumedAmount)
	if err != nil {
		return errorsmod.Wrap(err, "invalid consumed amount")
	}
	newTotal, err := currentUsed.SafeAdd(consumed)
	if err != nil {
		return errorsmod.Wrap(sdkerrors.ErrInvalidCoins, "user grant usage amount overflow")
	}

	// Convert back to []*sdk.Coin
	usage.TotalGrantUsed = []*sdk.Coin{}
	if !newTotal.IsZero() {
		coin := sdk.NewCoin(types.SponsorshipDenom, newTotal)
		usage.TotalGrantUsed = []*sdk.Coin{&coin}
	}

	usage.LastUsedTime = stateUnixTime(ctx)
	if found {
		if err := k.SetActiveUserGrantUsage(ctx, usage); err != nil {
			return errorsmod.Wrap(err, "failed to set user grant usage")
		}
	} else {
		// Compatibility for contracts that have never entered a Sponsor
		// lifecycle. Deleted Sponsors have a non-zero tombstone and are rejected
		// above, so their usage can never be revived through this path.
		if err := k.SetUserGrantUsage(ctx, usage); err != nil {
			return errorsmod.Wrap(err, "failed to set legacy user grant usage")
		}
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

	currentUsed, err := grantUsageAmount(usage.TotalGrantUsed)
	if err != nil {
		return errorsmod.Wrap(err, "invalid existing user grant usage")
	}
	requested, err := sponsorshipCoinAmount(requestedAmount)
	if err != nil {
		return errorsmod.Wrap(err, "invalid requested grant amount")
	}
	maxAmount, err := sponsorshipCoinAmount(maxLimit)
	if err != nil {
		return errorsmod.Wrap(err, "invalid max grant per user")
	}

	// Compare against the remaining allowance without adding first. This avoids
	// sdk.Int overflow when a caller supplies a near-maximum requested amount.
	remaining, err := maxAmount.SafeSub(currentUsed)
	if err != nil || remaining.IsNegative() || requested.GT(remaining) {
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

func sponsorshipCoinAmount(coins sdk.Coins) (sdk.Int, error) {
	if !coins.IsValid() {
		return sdk.Int{}, errorsmod.Wrap(sdkerrors.ErrInvalidCoins, "coins must be valid and sorted")
	}
	if coins.Empty() {
		return sdk.ZeroInt(), nil
	}
	if len(coins) != 1 || coins[0].Denom != types.SponsorshipDenom {
		return sdk.Int{}, errorsmod.Wrapf(
			sdkerrors.ErrInvalidCoins,
			"only %q denomination is supported",
			types.SponsorshipDenom,
		)
	}
	return coins[0].Amount, nil
}

func grantUsageAmount(coins []*sdk.Coin) (sdk.Int, error) {
	total := sdk.ZeroInt()
	seen := false
	for _, coin := range coins {
		if coin == nil {
			return sdk.Int{}, errorsmod.Wrap(sdkerrors.ErrInvalidCoins, "user grant usage coin cannot be nil")
		}
		if coin.Denom != types.SponsorshipDenom {
			return sdk.Int{}, errorsmod.Wrapf(
				sdkerrors.ErrInvalidCoins,
				"only %q denomination is supported",
				types.SponsorshipDenom,
			)
		}
		if seen {
			return sdk.Int{}, errorsmod.Wrap(sdkerrors.ErrInvalidCoins, "duplicate user grant usage denomination")
		}
		if coin.Amount.IsNegative() {
			return sdk.Int{}, errorsmod.Wrap(sdkerrors.ErrInvalidCoins, "user grant usage amount cannot be negative")
		}
		next, err := total.SafeAdd(coin.Amount)
		if err != nil {
			return sdk.Int{}, errorsmod.Wrap(sdkerrors.ErrInvalidCoins, "user grant usage amount overflow")
		}
		total = next
		seen = true
	}
	return total, nil
}
