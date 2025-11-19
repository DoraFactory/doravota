package sponsor_test

import (
    "encoding/json"
    "testing"

    abci "github.com/cometbft/cometbft/abci/types"
    dbm "github.com/cometbft/cometbft-db"
    "github.com/cometbft/cometbft/libs/log"
    tmproto "github.com/cometbft/cometbft/proto/tendermint/types"
    "github.com/cosmos/cosmos-sdk/codec"
    codectypes "github.com/cosmos/cosmos-sdk/codec/types"
    "github.com/cosmos/cosmos-sdk/store"
    storetypes "github.com/cosmos/cosmos-sdk/store/types"
    sdk "github.com/cosmos/cosmos-sdk/types"
    "github.com/stretchr/testify/require"
    authtypes "github.com/cosmos/cosmos-sdk/x/auth/types"

    sponsor "github.com/DoraFactory/doravota/x/sponsor-contract-tx"
    "github.com/DoraFactory/doravota/x/sponsor-contract-tx/keeper"
    "github.com/DoraFactory/doravota/x/sponsor-contract-tx/types"
    wasmtypes "github.com/CosmWasm/wasmd/x/wasm/types"
    "github.com/cosmos/cosmos-sdk/types/address"
)

// minimalBankKeeper satisfies the interface but is unused in this test
type minimalBankKeeper struct{}
func (minimalBankKeeper) SpendableCoins(ctx sdk.Context, addr sdk.AccAddress) sdk.Coins { return nil }
func (minimalBankKeeper) SendCoins(ctx sdk.Context, fromAddr sdk.AccAddress, toAddr sdk.AccAddress, amt sdk.Coins) error { return nil }
func (minimalBankKeeper) SendCoinsFromModuleToAccount(ctx sdk.Context, senderModule string, recipientAddr sdk.AccAddress, amt sdk.Coins) error { return nil }
func (minimalBankKeeper) SendCoinsFromAccountToModule(ctx sdk.Context, senderAddr sdk.AccAddress, recipientModule string, amt sdk.Coins) error { return nil }
func (minimalBankKeeper) MintCoins(ctx sdk.Context, moduleName string, amt sdk.Coins) error { return nil }
func (minimalBankKeeper) BurnCoins(ctx sdk.Context, moduleName string, amt sdk.Coins) error { return nil }
func (minimalBankKeeper) GetAllBalances(ctx sdk.Context, addr sdk.AccAddress) sdk.Coins { return nil }
func (minimalBankKeeper) GetBalance(ctx sdk.Context, addr sdk.AccAddress, denom string) sdk.Coin { return sdk.Coin{} }
func (minimalBankKeeper) BlockedAddr(addr sdk.AccAddress) bool { return false }

// minimalAuthKeeper satisfies the AuthKeeper interface
type minimalAuthKeeper struct{}
func (minimalAuthKeeper) GetAccount(ctx sdk.Context, addr sdk.AccAddress) authtypes.AccountI { return nil }
func (minimalAuthKeeper) SetAccount(ctx sdk.Context, acc authtypes.AccountI) {}
func (minimalAuthKeeper) NewAccountWithAddress(ctx sdk.Context, addr sdk.AccAddress) authtypes.AccountI { return nil }
func (minimalAuthKeeper) GetModuleAddress(moduleName string) sdk.AccAddress { return nil }
func (minimalAuthKeeper) GetModuleAccount(ctx sdk.Context, moduleName string) authtypes.ModuleAccountI { return nil }

// minimalWasmKeeper always reports contract exists (for this module-level GC test)
type minimalWasmKeeper struct{}
func (minimalWasmKeeper) GetContractInfo(ctx sdk.Context, contractAddress sdk.AccAddress) *wasmtypes.ContractInfo {
    return &wasmtypes.ContractInfo{Creator: "creator"}
}
func (minimalWasmKeeper) QuerySmart(ctx sdk.Context, contractAddr sdk.AccAddress, req []byte) ([]byte, error) {
    return nil, nil
}

// TestAppModuleBeginBlock_GarbageCollect ensures BeginBlock triggers bounded GC of expired tickets
func TestAppModuleBeginBlock_GarbageCollect(t *testing.T) {
    // Setup keeper
    registry := codectypes.NewInterfaceRegistry()
    cdc := codec.NewProtoCodec(registry)
    storeKey := sdk.NewKVStoreKey(types.StoreKey)
    db := dbm.NewMemDB()
    ms := store.NewCommitMultiStore(db)
    ms.MountStoreWithDB(storeKey, storetypes.StoreTypeIAVL, nil)
    require.NoError(t, ms.LoadLatestVersion())
    // mock wasm: always exists
    mw := &minimalWasmKeeper{}
    k := keeper.NewKeeper(cdc, storeKey, mw, "cosmos10d07y265gmmuvt4z0w9aw880jnsr700j6zn9kn")
    ctx := sdk.NewContext(ms, tmproto.Header{Height: 10}, false, log.NewNopLogger())

    // Insert an expired ticket
    tkt := types.PolicyTicket{ContractAddress: "c", UserAddress: "u", Digest: "d", ExpiryHeight: 5}
    require.NoError(t, k.SetPolicyTicket(ctx, tkt))
    if _, ok := k.GetPolicyTicket(ctx, "c", "u", "d"); !ok { t.Fatalf("ticket not inserted") }

    // Build app module and call BeginBlock
    am := sponsor.NewAppModule(cdc, *k, minimalBankKeeper{}, minimalAuthKeeper{})
    am.BeginBlock(ctx, abci.RequestBeginBlock{})

    // Ticket should be GC'd
    _, ok := k.GetPolicyTicket(ctx, "c", "u", "d")
    require.False(t, ok)
}

// TestAppModule_GenesisRawJSONRoundTrip verifies AppModule.InitGenesis/ExportGenesis with raw JSON
func TestAppModule_GenesisRawJSONRoundTrip(t *testing.T) {
    // Setup keeper and module
    registry := codectypes.NewInterfaceRegistry()
    cdc := codec.NewProtoCodec(registry)
    storeKey := sdk.NewKVStoreKey(types.StoreKey)
    db := dbm.NewMemDB()
    ms := store.NewCommitMultiStore(db)
    ms.MountStoreWithDB(storeKey, storetypes.StoreTypeIAVL, nil)
    require.NoError(t, ms.LoadLatestVersion())
    mw := &minimalWasmKeeper{}
    k := keeper.NewKeeper(cdc, storeKey, mw, "cosmos10d07y265gmmuvt4z0w9aw880jnsr700j6zn9kn")
    am := sponsor.NewAppModule(cdc, *k, minimalBankKeeper{}, minimalAuthKeeper{})
    ctx := sdk.NewContext(ms, tmproto.Header{}, false, log.NewNopLogger())

    // Build a genesis state (params + sponsors + user usages)
    mk := func(seed byte) sdk.AccAddress {
        b := make([]byte, 20)
        for i := range b { b[i] = seed }
        return sdk.AccAddress(b)
    }
    contract1 := mk(1).String()
    contract2 := mk(2).String()
    creator := mk(3).String()
    user1 := mk(4).String()
    ca1, _ := sdk.AccAddressFromBech32(contract1)
    ca2, _ := sdk.AccAddressFromBech32(contract2)
    sp1 := sdk.AccAddress(address.Derive(ca1, []byte("sponsor"))).String()
    sp2 := sdk.AccAddress(address.Derive(ca2, []byte("sponsor"))).String()

    params := types.DefaultParams()
    params.SponsorshipEnabled = true
    // Removed: PolicyProbeGasPrice
    params.PolicyTicketTtlBlocks = 7
    params.MaxMethodTicketUsesPerIssue = 9

    gs := &types.GenesisState{
        Params: &params,
        Sponsors: []*types.ContractSponsor{
            {ContractAddress: contract1, CreatorAddress: creator, SponsorAddress: sp1, IsSponsored: true, MaxGrantPerUser: []*sdk.Coin{{Denom: types.SponsorshipDenom, Amount: sdk.NewInt(1)}}},
            {ContractAddress: contract2, CreatorAddress: creator, SponsorAddress: sp2, IsSponsored: false},
        },
        UserGrantUsages: []*types.UserGrantUsage{
            {UserAddress: user1, ContractAddress: contract1, TotalGrantUsed: []*sdk.Coin{{Denom: types.SponsorshipDenom, Amount: sdk.NewInt(3)}}},
        },
    }

    // Marshal to raw JSON and init via AppModule
    bz, err := json.Marshal(gs)
    require.NoError(t, err)
    am.InitGenesis(ctx, cdc, bz)

    // Export via AppModule and compare relevant fields
    out := am.ExportGenesis(ctx, cdc)
    var exported types.GenesisState
    require.NoError(t, json.Unmarshal(out, &exported))

    // Params should match
    require.NotNil(t, exported.Params)
    require.Equal(t, params.SponsorshipEnabled, exported.Params.SponsorshipEnabled)
    // Removed: PolicyProbeGasPrice
    require.Equal(t, params.PolicyTicketTtlBlocks, exported.Params.PolicyTicketTtlBlocks)
    require.Equal(t, params.MaxMethodTicketUsesPerIssue, exported.Params.MaxMethodTicketUsesPerIssue)

    // Sponsors count matches and entries present
    require.Len(t, exported.Sponsors, 2)
    // Usages count matches and entry present
    require.Len(t, exported.UserGrantUsages, 1)
}

// TestAppModuleBeginBlock_GCRespectsCap ensures BeginBlock respects TicketGcPerBlock cap
func TestAppModuleBeginBlock_GCRespectsCap(t *testing.T) {
    // Setup keeper and module
    registry := codectypes.NewInterfaceRegistry()
    cdc := codec.NewProtoCodec(registry)
    storeKey := sdk.NewKVStoreKey(types.StoreKey)
    db := dbm.NewMemDB()
    ms := store.NewCommitMultiStore(db)
    ms.MountStoreWithDB(storeKey, storetypes.StoreTypeIAVL, nil)
    require.NoError(t, ms.LoadLatestVersion())
    mw := &minimalWasmKeeper{}
    k := keeper.NewKeeper(cdc, storeKey, mw, "cosmos10d07y265gmmuvt4z0w9aw880jnsr700j6zn9kn")
    am := sponsor.NewAppModule(cdc, *k, minimalBankKeeper{}, minimalAuthKeeper{})
    ctx := sdk.NewContext(ms, tmproto.Header{Height: 100}, false, log.NewNopLogger())

    // Set GC cap to 1 per block
    params := types.DefaultParams()
    params.TicketGcPerBlock = 1
    require.NoError(t, k.SetParams(ctx, params))

    // Insert multiple expired tickets
    ts := []types.PolicyTicket{
        {ContractAddress: "c", UserAddress: "u", Digest: "d1", ExpiryHeight: 50},
        {ContractAddress: "c", UserAddress: "u", Digest: "d2", ExpiryHeight: 60},
        {ContractAddress: "c", UserAddress: "u", Digest: "d3", ExpiryHeight: 70},
    }
    for _, tkt := range ts {
        require.NoError(t, k.SetPolicyTicket(ctx, tkt))
    }

    // First BeginBlock removes at most 1
    am.BeginBlock(ctx, abci.RequestBeginBlock{})
    // Expect 2 remain
    _, ok1 := k.GetPolicyTicket(ctx, "c", "u", "d1")
    _, ok2 := k.GetPolicyTicket(ctx, "c", "u", "d2")
    _, ok3 := k.GetPolicyTicket(ctx, "c", "u", "d3")
    remaining := 0
    for _, ok := range []bool{ok1, ok2, ok3} {
        if ok { remaining++ }
    }
    require.Equal(t, 2, remaining)

    // Second BeginBlock removes another 1
    am.BeginBlock(ctx, abci.RequestBeginBlock{})
    remaining = 0
    for _, dg := range []string{"d1","d2","d3"} {
        if _, ok := k.GetPolicyTicket(ctx, "c", "u", dg); ok { remaining++ }
    }
    require.Equal(t, 1, remaining)
}
