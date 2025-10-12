package keeper

import (
    "bytes"
    "encoding/json"
    "fmt"
    "math"

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

// ContractMessage represents a parsed contract execution message
type ContractMessage struct {
	MsgType string
	MsgData string
}

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

// CheckContractPolicy calls the contract's CheckPolicy query to verify if user is eligible
// It checks ALL contract execution messages for the specified contract to prevent hitchhiking attacks
func (k Keeper) CheckContractPolicy(ctx sdk.Context, contractAddr string, userAddr sdk.AccAddress, tx sdk.Tx) (*types.CheckContractPolicyResult, error) {
	// NOTE: JSON is required for CosmWasm smart contract communication
	// CosmWasm contracts expect JSON queries and return JSON responses
	// This cannot be changed to protobuf without breaking contract compatibility

	// Extract all contract messages for security - prevent hitchhiking attacks
	contractMessages, err := k.extractAllContractMessages(tx, contractAddr)
	if err != nil {
		return nil, errorsmod.Wrap(err, "failed to extract contract messages")
	}

	if len(contractMessages) == 0 {
		return nil, errorsmod.Wrap(types.ErrContractNotFound, fmt.Sprintf("no contract execution messages found for contract %s", contractAddr))
	}

	contractAccAddr, err := sdk.AccAddressFromBech32(contractAddr)
	if err != nil {
		return nil, errorsmod.Wrap(sdkerrors.ErrInvalidAddress, fmt.Sprintf("invalid contract address: %s", err.Error()))
	}

	// Check EVERY contract message for permission - critical for security
	for i, contractMsg := range contractMessages {
		// prepare query smart contract message with enhanced parameters
		queryMsg := map[string]interface{}{
			"check_policy": map[string]interface{}{
				"sender":   userAddr.String(),
				"msg_data": contractMsg.MsgData,
			},
		}

		queryBytes, err := json.Marshal(queryMsg)
		if err != nil {
			return nil, errorsmod.Wrap(err, fmt.Sprintf("failed to marshal query message for message %d", i))
		}

		// Record gas before contract query
		gasBefore := ctx.GasMeter().GasConsumed()

		k.Logger(ctx).Debug("executing contract policy query",
			"contract", contractAddr,
			"user", userAddr.String(),
			"message_index", i,
			"message_type", contractMsg.MsgType,
			"gas_before_query", gasBefore,
		)

		result, err := k.wasmKeeper.QuerySmart(ctx, contractAccAddr, queryBytes)

		// Record gas after contract query
		gasAfter := ctx.GasMeter().GasConsumed()
		gasUsedForQuery := gasAfter - gasBefore

		k.Logger(ctx).Debug("contract policy query completed",
			"contract", contractAddr,
			"user", userAddr.String(),
			"message_index", i,
			"message_type", contractMsg.MsgType,
			"gas_before_query", gasBefore,
			"gas_after_query", gasAfter,
			"gas_used_for_query", gasUsedForQuery,
		)

		if err != nil {
			k.Logger(ctx).Error("contract policy query failed",
				"contract", contractAddr,
				"user", userAddr.String(),
				"message_index", i,
				"message_type", contractMsg.MsgType,
				"gas_used_for_query", gasUsedForQuery,
				"error", err.Error(),
			)
			return nil, errorsmod.Wrap(err, fmt.Sprintf("failed to query contract for message %d (%s)", i, contractMsg.MsgType))
		}

		// parse query result
		var response struct {
			Eligible bool    `json:"eligible"`
			Reason   *string `json:"reason"`
		}
		if err := json.Unmarshal(result, &response); err != nil {
			return nil, errorsmod.Wrap(err, fmt.Sprintf("failed to unmarshal query response for message %d", i))
		}

		// If ANY message is not eligible, return with detailed reason
		if !response.Eligible {
			reason := "no reason provided"
			if response.Reason != nil {
				reason = *response.Reason
			}
			k.Logger(ctx).Info("message not eligible for sponsorship",
				"contract", contractAddr,
				"user", userAddr.String(),
				"message_index", i,
				"message_type", contractMsg.MsgType,
				"reason", reason,
			)
			// Return detailed reason in result structure
			detailedReason := fmt.Sprintf("message %d (%s) not eligible: %s", i, contractMsg.MsgType, reason)
			return &types.CheckContractPolicyResult{
				Eligible: false,
				Reason:   detailedReason,
			}, nil
		}

		k.Logger(ctx).Debug("message eligible for sponsorship",
			"contract", contractAddr,
			"user", userAddr.String(),
			"message_index", i,
			"message_type", contractMsg.MsgType,
		)
	}

	// All messages are eligible
	return &types.CheckContractPolicyResult{
		Eligible: true,
		Reason:   "",
	}, nil
}

// extractAllContractMessages extracts ALL contract execution messages for the specified contract
// This prevents hitchhiking attacks where unauthorized messages are bundled with authorized ones
func (k Keeper) extractAllContractMessages(tx sdk.Tx, targetContractAddr string) ([]ContractMessage, error) {
	var contractMessages []ContractMessage

	for _, msg := range tx.GetMsgs() {
		if execMsg, ok := msg.(*wasmtypes.MsgExecuteContract); ok {
			if execMsg.Contract == targetContractAddr {
				// Parse the contract message to extract type and data deterministically
				// Use RawMessage to avoid lossy conversions and ensure we operate on the
				// exact bytes present in the signed transaction.
				var msgMap map[string]json.RawMessage
				if err := json.Unmarshal(execMsg.Msg, &msgMap); err != nil {
					return nil, errorsmod.Wrap(err, "failed to parse contract message")
				}

				// Enforce exactly one top-level key to avoid non-determinism.
				if len(msgMap) != 1 {
					return nil, errorsmod.Wrap(sdkerrors.ErrInvalidRequest, "execute message must contain exactly one top-level field")
				}

				// Retrieve the sole key deterministically (len==1 guarantees determinism)
				var msgType string
				for k := range msgMap { // single iteration
					msgType = k
				}

				// Use the original raw bytes for MsgData to preserve canonical ordering from the tx
				contractMessages = append(contractMessages, ContractMessage{
					MsgType: msgType,
					MsgData: string(execMsg.Msg),
				})
			}
		}
	}

	return contractMessages, nil
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

// RunFailedAttemptsGC performs a deterministic GC pass over FailedAttempts records,
// deleting up to 'limit' entries that are no longer blocked and whose sliding window
// has expired at current block height.
func (k Keeper) RunFailedAttemptsGC(ctx sdk.Context, limit int) int {
	if limit <= 0 {
		return 0
	}
	curH := ctx.BlockHeight()
	params := k.GetParams(ctx)

	// Collect keys to delete first to avoid mutating during iteration
	store := prefix.NewStore(ctx.KVStore(k.storeKey), types.FailedAttemptsKeyPrefix)
	it := store.Iterator(nil, nil)
	defer it.Close()

	toDelete := make([][]byte, 0, limit)
	for it.Valid() && len(toDelete) < limit {
		key := append([]byte{}, it.Key()...)
		val := it.Value()
		var rec types.FailedAttempts
		if err := k.cdc.Unmarshal(val, &rec); err == nil {
			if rec.UntilHeight < curH {
				if rec.WindowStartHeight == 0 || (curH-rec.WindowStartHeight) > int64(params.GlobalWindowBlocks) {
					toDelete = append(toDelete, key)
				}
			}
		} else {
			// Corrupted entries: safe to delete deterministically
			toDelete = append(toDelete, key)
		}
		it.Next()
	}

	for _, key := range toDelete {
		store.Delete(key)
	}
	return len(toDelete)
}

// GetAllFailedAttemptsEntries returns all failed-attempts entries as (contract,user,record) tuples
func (k Keeper) GetAllFailedAttemptsEntries(ctx sdk.Context) []*types.FailedAttemptsEntry {
	store := prefix.NewStore(ctx.KVStore(k.storeKey), types.FailedAttemptsKeyPrefix)
	it := store.Iterator(nil, nil)
	defer it.Close()
	var res []*types.FailedAttemptsEntry
	for ; it.Valid(); it.Next() {
		key := it.Key()
		// key format: contract + "/" + user
		sep := bytes.IndexByte(key, '/')
		if sep <= 0 || sep >= len(key)-1 {
			continue
		}
		contract := string(key[:sep])
		user := string(key[sep+1:])
		var rec types.FailedAttempts
		if err := k.cdc.Unmarshal(it.Value(), &rec); err != nil {
			continue
		}
		entry := &types.FailedAttemptsEntry{
			ContractAddress: contract,
			UserAddress:     user,
			Record:          &rec,
		}
		res = append(res, entry)
	}
	return res
}

// === Global Failed Attempts (Abuse Tracking) ===

// GetFailedAttempts retrieves the global failed attempts record for a contract/user.
// Pure read; never mutates state.
func (k Keeper) GetFailedAttempts(ctx sdk.Context, contractAddr, userAddr string) (types.FailedAttempts, bool) {
	store := ctx.KVStore(k.storeKey)
	key := types.FailedAttemptsKey(contractAddr, userAddr)
	bz := store.Get(key)
	if bz == nil {
		return types.FailedAttempts{}, false
	}

	var rec types.FailedAttempts
	if err := k.cdc.Unmarshal(bz, &rec); err != nil {
		// Pure-read getter: do not mutate state here; just log and treat as not found
		k.Logger(ctx).Error("failed to unmarshal failed attempts record", "contract", contractAddr, "user", userAddr, "err", err)
		return types.FailedAttempts{}, false
	}
	return rec, true
}

// SetFailedAttempts sets the global failed attempts record for a contract/user.
func (k Keeper) SetFailedAttempts(ctx sdk.Context, contractAddr, userAddr string, rec types.FailedAttempts) {
	store := ctx.KVStore(k.storeKey)
	key := types.FailedAttemptsKey(contractAddr, userAddr)
	bz := k.cdc.MustMarshal(&rec)
	store.Set(key, bz)
}

// ClearFailedAttempts removes the record for a contract/user.
func (k Keeper) ClearFailedAttempts(ctx sdk.Context, contractAddr, userAddr string) {
	store := ctx.KVStore(k.storeKey)
	key := types.FailedAttemptsKey(contractAddr, userAddr)
	store.Delete(key)
}

// IsGloballyBlocked returns whether the user is currently globally blocked for the contract
// and the remaining blocks until unblocked. Determined solely by block height.
func (k Keeper) IsGloballyBlocked(ctx sdk.Context, contractAddr, userAddr string) (bool, int64) {
	params := k.GetParams(ctx)
	if !params.AbuseTrackingEnabled {
		return false, 0
	}

	rec, found := k.GetFailedAttempts(ctx, contractAddr, userAddr)
	if !found {
		return false, 0
	}

	curH := ctx.BlockHeight()
	if rec.UntilHeight > curH {
		remain := rec.UntilHeight - curH
		return true, remain
	}
	return false, 0
}

// IncrementFailedAttempts applies sliding-window counting and exponential backoff cooldown.
// Returns whether the user is now blocked and the until-height. Uses ctx.BlockHeight exclusively.
func (k Keeper) IncrementFailedAttempts(ctx sdk.Context, contractAddr, userAddr string) (bool, int64, error) {
	params := k.GetParams(ctx)
	if !params.AbuseTrackingEnabled {
		return false, 0, nil
	}

	curH := ctx.BlockHeight()

	rec, found := k.GetFailedAttempts(ctx, contractAddr, userAddr)
	if !found {
		rec = types.FailedAttempts{ // initialize fresh window
			Count:              0,
			WindowStartHeight:  curH,
			UntilHeight:        0,
			LastCooldownBlocks: 0,
		}
	}

	// Reset counting window if expired
	if rec.WindowStartHeight == 0 || (curH-rec.WindowStartHeight) > int64(params.GlobalWindowBlocks) {
		rec.Count = 0
		rec.WindowStartHeight = curH
	}

	// Increment count for this failure within window
	rec.Count++

	// If threshold not reached, persist and return
	if rec.Count < params.GlobalThreshold {
		k.SetFailedAttempts(ctx, contractAddr, userAddr, rec)
		return false, 0, nil
	}

	// Threshold reached: compute cooldown duration with multiplicative backoff
    // Compute next cooldown blocks using fixed-point (milli) to avoid float nondeterminism
    var ttlBlocks int64
    if rec.LastCooldownBlocks == 0 {
        ttlBlocks = int64(params.GlobalBaseBlocks)
    } else {
        // ceil(last * factor)
        last := int64(rec.LastCooldownBlocks)
        milli := int64(params.GlobalBackoffMilli)
        ttlBlocks = (last*milli + 999) / 1000
    }
    if ttlBlocks < int64(params.GlobalBaseBlocks) {
        ttlBlocks = int64(params.GlobalBaseBlocks)
    }
    if ttlBlocks > int64(params.GlobalMaxBlocks) {
        ttlBlocks = int64(params.GlobalMaxBlocks)
    }
    // Defensive: saturating add to avoid theoretical overflow in extreme scenarios
    if ttlBlocks > 0 && curH > math.MaxInt64-ttlBlocks {
        rec.UntilHeight = math.MaxInt64
    } else {
        rec.UntilHeight = curH + ttlBlocks
    }
    rec.LastCooldownBlocks = uint32(ttlBlocks)

	// Reset window/count after starting cooldown as per spec
	rec.Count = 0
	rec.WindowStartHeight = curH

	k.SetFailedAttempts(ctx, contractAddr, userAddr, rec)

	return true, rec.UntilHeight, nil
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
