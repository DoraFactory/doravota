package keeper

import (
	"testing"

	wasmtypes "github.com/CosmWasm/wasmd/x/wasm/types"
	"github.com/cometbft/cometbft/libs/log"
	tmproto "github.com/cometbft/cometbft/proto/tendermint/types"
	"github.com/cosmos/cosmos-sdk/codec"
	codectypes "github.com/cosmos/cosmos-sdk/codec/types"
	"github.com/cosmos/cosmos-sdk/store"
	storetypes "github.com/cosmos/cosmos-sdk/store/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
	authkeeper "github.com/cosmos/cosmos-sdk/x/auth/keeper"
	authtypes "github.com/cosmos/cosmos-sdk/x/auth/types"
	bankkeeper "github.com/cosmos/cosmos-sdk/x/bank/keeper"
	banktypes "github.com/cosmos/cosmos-sdk/x/bank/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	dbm "github.com/cometbft/cometbft-db"

	"github.com/DoraFactory/doravota/x/sponsor-contract-tx/types"
)

// setupKeeperWithDeps sets up keeper with auth/bank keepers for withdraw tests
func setupKeeperWithDeps(t *testing.T) (Keeper, sdk.Context, *MockWasmKeeper, authkeeper.AccountKeeper, bankkeeper.Keeper) {
	t.Helper()

	// Interface registry and codec
	interfaceRegistry := codectypes.NewInterfaceRegistry()
	authtypes.RegisterInterfaces(interfaceRegistry)
	banktypes.RegisterInterfaces(interfaceRegistry)
	wasmtypes.RegisterInterfaces(interfaceRegistry)
	types.RegisterInterfaces(interfaceRegistry)
	cdc := codec.NewProtoCodec(interfaceRegistry)

	// Stores
	sponsorStoreKey := sdk.NewKVStoreKey(types.StoreKey)
	authStoreKey := sdk.NewKVStoreKey(authtypes.StoreKey)
	bankStoreKey := sdk.NewKVStoreKey(banktypes.StoreKey)

	db := dbm.NewMemDB()
	cms := store.NewCommitMultiStore(db)
	cms.MountStoreWithDB(sponsorStoreKey, storetypes.StoreTypeIAVL, db)
	cms.MountStoreWithDB(authStoreKey, storetypes.StoreTypeIAVL, db)
	cms.MountStoreWithDB(bankStoreKey, storetypes.StoreTypeIAVL, db)
	require.NoError(t, cms.LoadLatestVersion())

	ctx := sdk.NewContext(cms, tmproto.Header{Height: 1}, false, log.NewNopLogger())

	// Keepers
	mockWasmKeeper := NewMockWasmKeeper()

	maccPerms := map[string][]string{
		authtypes.FeeCollectorName: nil,
		types.ModuleName:           {authtypes.Minter, authtypes.Burner},
	}

	accountKeeper := authkeeper.NewAccountKeeper(
		cdc,
		authStoreKey,
		authtypes.ProtoBaseAccount,
		maccPerms,
		"dora",
		authtypes.NewModuleAddress("gov").String(),
	)

	bankKeeper := bankkeeper.NewBaseKeeper(
		cdc,
		bankStoreKey,
		accountKeeper,
		nil,
		authtypes.NewModuleAddress("gov").String(),
	)

	// Create module account for sponsor module (for minting)
	sponsorModuleAcc := authtypes.NewEmptyModuleAccount(types.ModuleName, authtypes.Minter, authtypes.Burner)
	accountKeeper.SetAccount(ctx, sponsorModuleAcc)

	// Create keeper
	k := NewKeeper(cdc, sponsorStoreKey, mockWasmKeeper, authtypes.NewModuleAddress("gov").String())

	return *k, ctx, mockWasmKeeper, accountKeeper, bankKeeper
}

func setupMsgServerEnv(t *testing.T) (Keeper, sdk.Context, types.MsgServer, *MockWasmKeeper, bankkeeper.Keeper) {
    keeper, ctx, mockWasmKeeper, authKeeper, bankKeeper := setupKeeperWithDeps(t)
    msgServer := NewMsgServerImplWithDeps(keeper, bankKeeper, authKeeper)
    return keeper, ctx, msgServer, mockWasmKeeper, bankKeeper
}

func TestIssuePolicyTicket_UsesClampAndDecrement(t *testing.T) {
    keeper, ctx, msgServer, mockWasmKeeper, _ := setupMsgServerEnv(t)

    // Set params with a known cap
    p := types.DefaultParams()
    p.MaxMethodTicketUsesPerIssue = 3
    require.NoError(t, keeper.SetParams(ctx, p))

    // Prepare valid bech32 addresses
    contract := sdk.AccAddress([]byte("contract_issue_method____")).String()
    creator := sdk.AccAddress([]byte("creator_issue_method_____"))
    user := sdk.AccAddress([]byte("user_issue_method________"))

    // Mock contract info with admin = creator
    mockWasmKeeper.SetContractInfo(contract, creator.String())
    // Require sponsor exists for issuance
    require.NoError(t, keeper.SetSponsor(ctx, types.ContractSponsor{ContractAddress: contract, IsSponsored: true}))

    // Issue with uses well above the cap (e.g., 10 > 3) and one method
    resp, err := msgServer.IssuePolicyTicket(sdk.WrapSDKContext(ctx), &types.MsgIssuePolicyTicket{
        Creator:         creator.String(),
        ContractAddress: contract,
        UserAddress:     user.String(),
        Method:          "do",
        Uses:            10,
    })
    require.NoError(t, err)
    require.NotNil(t, resp)
    require.True(t, resp.Created)
    require.NotNil(t, resp.Ticket)
    // Clamped to 3
    require.Equal(t, uint32(3), resp.Ticket.UsesRemaining)

    // Fetch from store; should match
    tkt, ok := keeper.GetPolicyTicket(ctx, contract, user.String(), resp.Ticket.Digest)
    require.True(t, ok)
    require.Equal(t, uint32(3), tkt.UsesRemaining)
    require.False(t, tkt.Consumed)

    // Consume twice; uses should decrement, not consumed yet
    require.NoError(t, keeper.ConsumePolicyTicket(ctx, contract, user.String(), tkt.Digest))
    tkt, _ = keeper.GetPolicyTicket(ctx, contract, user.String(), tkt.Digest)
    require.Equal(t, uint32(2), tkt.UsesRemaining)
    require.False(t, tkt.Consumed)

    require.NoError(t, keeper.ConsumePolicyTicket(ctx, contract, user.String(), tkt.Digest))
    tkt, _ = keeper.GetPolicyTicket(ctx, contract, user.String(), tkt.Digest)
    require.Equal(t, uint32(1), tkt.UsesRemaining)
    require.False(t, tkt.Consumed)

    // Final consume: reaches 0 and consumed=true
    require.NoError(t, keeper.ConsumePolicyTicket(ctx, contract, user.String(), tkt.Digest))
    tkt, _ = keeper.GetPolicyTicket(ctx, contract, user.String(), tkt.Digest)
    require.Equal(t, uint32(0), tkt.UsesRemaining)
    require.True(t, tkt.Consumed)
}

func TestIssuePolicyTicket_UsesZeroTreatedAsOne(t *testing.T) {
    keeper, ctx, msgServer, mockWasmKeeper, _ := setupMsgServerEnv(t)

    // Default params default to 3; keep it
    p := types.DefaultParams()
    p.MaxMethodTicketUsesPerIssue = 3
    require.NoError(t, keeper.SetParams(ctx, p))

    // Valid addresses
    contract := sdk.AccAddress([]byte("contract_issue_method_u0")).String()
    creator := sdk.AccAddress([]byte("creator_issue_method_u0")).String()
    user := sdk.AccAddress([]byte("user_issue_method_u0__")).String()

    mockWasmKeeper.SetContractInfo(contract, creator)
    // Require sponsor exists for issuance
    require.NoError(t, keeper.SetSponsor(ctx, types.ContractSponsor{ContractAddress: contract, IsSponsored: true}))

    // Issue with uses = 0 (or omitted), treated as 1
    resp, err := msgServer.IssuePolicyTicket(sdk.WrapSDKContext(ctx), &types.MsgIssuePolicyTicket{
        Creator:         creator,
        ContractAddress: contract,
        UserAddress:     user,
        Method:          "call",
        Uses:            0,
    })
    require.NoError(t, err)
    require.True(t, resp.Created)
    require.Equal(t, uint32(1), resp.Ticket.UsesRemaining)

    // Consume once -> consumed
    require.NoError(t, keeper.ConsumePolicyTicket(ctx, contract, user, resp.Ticket.Digest))
    tkt, _ := keeper.GetPolicyTicket(ctx, contract, user, resp.Ticket.Digest)
    require.Equal(t, uint32(0), tkt.UsesRemaining)
    require.True(t, tkt.Consumed)
}


// Removed: probe window tests

func TestKeeper_GarbageCollect_ExpiredOnly(t *testing.T) {
    keeper, ctx, _, accountKeeper, bankKeeper := setupKeeperWithDeps(t)
    _ = accountKeeper; _ = bankKeeper
    // Ensure we have a positive block height to avoid uint underflow when computing expired heights
    ctx = ctx.WithBlockHeight(ctx.BlockHeight() + 10)
    // insert tickets: one expired, one alive
    now := uint64(ctx.BlockHeight())
    t1 := types.PolicyTicket{ContractAddress: "c1", UserAddress: "u1", Digest: "d1", ExpiryHeight: now - 1}
    t2 := types.PolicyTicket{ContractAddress: "c2", UserAddress: "u2", Digest: "d2", ExpiryHeight: now + 10}
    require.NoError(t, keeper.SetPolicyTicket(ctx, t1))
    require.NoError(t, keeper.SetPolicyTicket(ctx, t2))

    // run GC deleting all expired items
    keeper.GarbageCollectByExpiry(ctx, 10)
    // expired items removed/invalidated, alive remain
    _, ok := keeper.GetPolicyTicket(ctx, "c1", "u1", "d1"); require.False(t, ok)
    _, ok = keeper.GetPolicyTicket(ctx, "c2", "u2", "d2"); require.True(t, ok)
    // Removed negative probe cache assertions
}

func TestMsgServer_RevokePolicyTicket(t *testing.T) {
    keeper, ctx, msgServer, mockWasmKeeper, bankKeeper := setupMsgServerEnv(t)
    _ = bankKeeper
    // Params
    params := types.DefaultParams()
    require.NoError(t, keeper.SetParams(ctx, params))
    // Contract admin
    admin := sdk.AccAddress([]byte("admin_addr_revoke__________"))
    contract := sdk.AccAddress([]byte("contract_addr_revoke_______"))
    mockWasmKeeper.SetContractInfo(contract.String(), admin.String())
    // Sponsor exists
    require.NoError(t, keeper.SetSponsor(ctx, types.ContractSponsor{ContractAddress: contract.String(), IsSponsored: true}))

    // Create a ticket to revoke
    user := sdk.AccAddress([]byte("user_addr_revoke___________")).String()
    digest := "abcd"
    tkt := types.PolicyTicket{ContractAddress: contract.String(), UserAddress: user, Digest: digest, ExpiryHeight: uint64(ctx.BlockHeight()+10), Method: "ping"}
    require.NoError(t, keeper.SetPolicyTicket(ctx, tkt))

    // Revoke by admin
    ctx = ctx.WithEventManager(sdk.NewEventManager())
    _, err := msgServer.RevokePolicyTicket(sdk.WrapSDKContext(ctx), &types.MsgRevokePolicyTicket{
        Creator:         admin.String(),
        ContractAddress: contract.String(),
        UserAddress:     user,
        Digest:          digest,
    })
    require.NoError(t, err)
    // Ticket gone
    _, ok := keeper.GetPolicyTicket(ctx, contract.String(), user, digest)
    require.False(t, ok)
    // Event emitted
    found := false
    for _, ev := range ctx.EventManager().Events() {
        if ev.Type != types.EventTypePolicyTicketRevoked { continue }
        attrs := map[string]string{}
        for _, a := range ev.Attributes { attrs[a.Key] = a.Value }
        if attrs[types.AttributeKeyMethod] == "ping" {
            found = true
            break
        }
    }
    require.True(t, found, "revoked event should include method attribute")

    // Revoke again -> error (not found)
    _, err = msgServer.RevokePolicyTicket(sdk.WrapSDKContext(ctx), &types.MsgRevokePolicyTicket{
        Creator:         admin.String(),
        ContractAddress: contract.String(),
        UserAddress:     user,
        Digest:          digest,
    })
    require.Error(t, err)

    // Create consumed ticket -> error
    tkt2 := types.PolicyTicket{ContractAddress: contract.String(), UserAddress: user, Digest: "efgh", ExpiryHeight: uint64(ctx.BlockHeight()+10), Consumed: true}
    require.NoError(t, keeper.SetPolicyTicket(ctx, tkt2))
    _, err = msgServer.RevokePolicyTicket(sdk.WrapSDKContext(ctx), &types.MsgRevokePolicyTicket{
        Creator:         admin.String(),
        ContractAddress: contract.String(),
        UserAddress:     user,
        Digest:          "efgh",
    })
    require.Error(t, err)

    // Unauthorized creator -> error
    notAdmin := sdk.AccAddress([]byte("not_admin_______________"))
    // ensure contract admin remains admin; attempt revoke
    _, err = msgServer.RevokePolicyTicket(sdk.WrapSDKContext(ctx), &types.MsgRevokePolicyTicket{
        Creator:         notAdmin.String(),
        ContractAddress: contract.String(),
        UserAddress:     user,
        Digest:          "nope",
    })
    require.Error(t, err)
}

// Non-admin ticket issuer is authorized to revoke tickets
func TestRevokePolicyTicket_IssuerAuthorized(t *testing.T) {
    keeper, ctx, msgServer, mockWasmKeeper, _ := setupMsgServerEnv(t)

    // Setup contract with admin A and ticket issuer B
    admin := sdk.AccAddress([]byte("admin_rev_issuer_auth____")).String()
    issuer := sdk.AccAddress([]byte("issuer_rev_issuer_auth___")).String()
    user := sdk.AccAddress([]byte("user_rev_issuer_auth_____"))
    contract := sdk.AccAddress([]byte("contract_rev_issuer_____"))

    mockWasmKeeper.SetContractInfo(contract.String(), admin)
    // Set sponsor with ticket issuer address
    require.NoError(t, keeper.SetSponsor(ctx, types.ContractSponsor{ContractAddress: contract.String(), IsSponsored: true, TicketIssuerAddress: issuer}))

    // Create a live ticket to revoke
    digest := "abcd"
    tkt := types.PolicyTicket{ContractAddress: contract.String(), UserAddress: user.String(), Digest: digest, ExpiryHeight: uint64(ctx.BlockHeight()+10)}
    require.NoError(t, keeper.SetPolicyTicket(ctx, tkt))

    // Revoke by issuer (not admin)
    _, err := msgServer.RevokePolicyTicket(sdk.WrapSDKContext(ctx), &types.MsgRevokePolicyTicket{
        Creator:         issuer,
        ContractAddress: contract.String(),
        UserAddress:     user.String(),
        Digest:          digest,
    })
    require.NoError(t, err)

    // Ticket should be removed
    _, ok := keeper.GetPolicyTicket(ctx, contract.String(), user.String(), digest)
    require.False(t, ok)
}

func TestMsgServer_SetSponsor(t *testing.T) {
	_, ctx, server, _, _ := setupMsgServerEnv(t)

	msg := &types.MsgSetSponsor{
		Creator:         "dora1xyz000000000000000000000000000000000000000000000000000000x",
		ContractAddress: "dora1abc000000000000000000000000000000000000000000000000000000x",
		IsSponsored:     true,
	}

	// This will fail due to invalid contract address format
	_, err := server.SetSponsor(sdk.WrapSDKContext(ctx), msg)
	require.Error(t, err)
	// With enhanced validation, this now fails at contract address validation
	assert.Contains(t, err.Error(), "invalid contract address")
}

func TestMsgServer_UpdateSponsor(t *testing.T) {
	keeper, ctx, server, _, _ := setupMsgServerEnv(t)

	contractAddr := "dora1abc000000000000000000000000000000000000000000000000000000x"

	// First set a sponsor
	sponsor := types.ContractSponsor{
		ContractAddress: contractAddr,
		IsSponsored:     true,
	}
	keeper.SetSponsor(ctx, sponsor)

	// Update the sponsor - this will fail due to admin validation
	msg := &types.MsgUpdateSponsor{
		Creator:         "dora1xyz000000000000000000000000000000000000000000000000000000x",
		ContractAddress: contractAddr,
		IsSponsored:     false,
	}

	_, err := server.UpdateSponsor(sdk.WrapSDKContext(ctx), msg)
	require.Error(t, err)
	// With enhanced validation, this now fails at contract address validation
	assert.Contains(t, err.Error(), "invalid contract address")
}

// Enabling sponsorship requires max_grant_per_user to be provided when none exists
func TestUpdateSponsor_EnableRequiresGrant(t *testing.T) {
    keeper, ctx, server, mockWasmKeeper, _ := setupMsgServerEnv(t)

    // Set up contract & admin
    contractAddr := sdk.AccAddress([]byte("contract_enable_req____")).String()
    adminAddr := sdk.AccAddress([]byte("admin_enable_req______")).String()
    mockWasmKeeper.SetContractInfo(contractAddr, adminAddr)

    // Initial sponsor: disabled, no max_grant_per_user
    require.NoError(t, keeper.SetSponsor(ctx, types.ContractSponsor{ContractAddress: contractAddr, IsSponsored: false}))

    // Try to enable without providing MaxGrantPerUser -> should error
    msg := &types.MsgUpdateSponsor{Creator: adminAddr, ContractAddress: contractAddr, IsSponsored: true}
    _, err := server.UpdateSponsor(sdk.WrapSDKContext(ctx), msg)
    require.Error(t, err)
    require.Contains(t, err.Error(), "max_grant_per_user is required")
}

func TestMsgServer_DeleteSponsor(t *testing.T) {
	keeper, ctx, server, _, _ := setupMsgServerEnv(t)

	contractAddr := "dora1abc000000000000000000000000000000000000000000000000000000x"

	// First set a sponsor
	sponsor := types.ContractSponsor{
		ContractAddress: contractAddr,
		IsSponsored:     true,
	}
	keeper.SetSponsor(ctx, sponsor)

	// Delete the sponsor - this will fail due to admin validation
	msg := &types.MsgDeleteSponsor{
		Creator:         "dora1xyz000000000000000000000000000000000000000000000000000000x",
		ContractAddress: contractAddr,
	}

	_, err := server.DeleteSponsor(sdk.WrapSDKContext(ctx), msg)
	require.Error(t, err)
	// With enhanced validation, this now fails at contract address validation
	assert.Contains(t, err.Error(), "invalid contract address")
}

func TestMsgServerEventEmission(t *testing.T) {
	_, ctx, msgServer, _, _ := setupMsgServerEnv(t)

	// Create event manager for testing
	eventManager := sdk.NewEventManager()
	ctx = ctx.WithEventManager(eventManager)

	// Test SetSponsor event - this will fail due to admin validation
	msg := &types.MsgSetSponsor{
		Creator:         "dora1xyz000000000000000000000000000000000000000000000000000000x",
		ContractAddress: "dora1abc000000000000000000000000000000000000000000000000000000x",
		IsSponsored:     true,
	}

	_, err := msgServer.SetSponsor(sdk.WrapSDKContext(ctx), msg)
	require.Error(t, err)
	// With enhanced validation, this now fails at contract address validation
	assert.Contains(t, err.Error(), "invalid contract address")

	// No events should be emitted when the operation fails
	events := eventManager.Events()
	require.Len(t, events, 0)
}

func TestMsgServerUpdateEventEmission(t *testing.T) {
	keeper, ctx, msgServer, _, _ := setupMsgServerEnv(t)

	// First set a sponsor
	contractAddr := "dora1abc000000000000000000000000000000000000000000000000000000x"
	sponsor := types.ContractSponsor{
		ContractAddress: contractAddr,
		IsSponsored:     true,
	}
	keeper.SetSponsor(ctx, sponsor)

	// Create event manager for testing
	eventManager := sdk.NewEventManager()
	ctx = ctx.WithEventManager(eventManager)

	// Test UpdateSponsor event - this will fail due to admin validation
	msg := &types.MsgUpdateSponsor{
		Creator:         "dora1xyz000000000000000000000000000000000000000000000000000000x",
		ContractAddress: contractAddr,
		IsSponsored:     false,
	}

	_, err := msgServer.UpdateSponsor(sdk.WrapSDKContext(ctx), msg)
	require.Error(t, err)
	// With enhanced validation, this now fails at contract address validation
	assert.Contains(t, err.Error(), "invalid contract address")

	// No events should be emitted when the operation fails
	events := eventManager.Events()
	require.Len(t, events, 0)
}

func TestMsgServerDeleteEventEmission(t *testing.T) {
	keeper, ctx, msgServer, _, _ := setupMsgServerEnv(t)

	// First set a sponsor
	contractAddr := "dora1abc000000000000000000000000000000000000000000000000000000x"
	sponsor := types.ContractSponsor{
		ContractAddress: contractAddr,
		IsSponsored:     true,
	}
	keeper.SetSponsor(ctx, sponsor)

	// Create event manager for testing
	eventManager := sdk.NewEventManager()
	ctx = ctx.WithEventManager(eventManager)

	// Test DeleteSponsor event - this will fail due to admin validation
	msg := &types.MsgDeleteSponsor{
		Creator:         "dora1xyz000000000000000000000000000000000000000000000000000000x",
		ContractAddress: contractAddr,
	}

	_, err := msgServer.DeleteSponsor(sdk.WrapSDKContext(ctx), msg)
	require.Error(t, err)
	// With enhanced validation, this now fails at contract address validation
	assert.Contains(t, err.Error(), "invalid contract address")

	// No events should be emitted when the operation fails
	events := eventManager.Events()
	require.Len(t, events, 0)
}

func TestMsgServerWorkflow(t *testing.T) {
	keeper, ctx, msgServer, _, _ := setupMsgServerEnv(t)

	contractAddr := "dora1abc000000000000000000000000000000000000000000000000000000x"
	signer := "dora1xyz000000000000000000000000000000000000000000000000000000x"

	// Note: With admin validation, all these operations will fail because
	// the mock wasm keeper doesn't provide contract info, so admin verification fails

	// 1. Set sponsor - will fail due to admin validation
	setMsg := &types.MsgSetSponsor{
		Creator:         signer,
		ContractAddress: contractAddr,
		IsSponsored:     true,
	}

	_, err := msgServer.SetSponsor(sdk.WrapSDKContext(ctx), setMsg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid contract address")

	// Since SetSponsor failed, the sponsor is not created
	assert.False(t, keeper.IsSponsored(ctx, contractAddr))
	assert.False(t, keeper.HasSponsor(ctx, contractAddr))

	// Create a sponsor directly for testing Update/Delete operations
	sponsor := types.ContractSponsor{
		ContractAddress: contractAddr,
		IsSponsored:     true,
	}
	keeper.SetSponsor(ctx, sponsor)

	// Verify sponsor is set correctly
	assert.True(t, keeper.IsSponsored(ctx, contractAddr))
	assert.True(t, keeper.HasSponsor(ctx, contractAddr))

	// 2. Update sponsor - will fail due to admin validation
	updateMsg := &types.MsgUpdateSponsor{
		Creator:         signer,
		ContractAddress: contractAddr,
		IsSponsored:     false,
	}

	_, err = msgServer.UpdateSponsor(sdk.WrapSDKContext(ctx), updateMsg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid contract address")

	// 3. Delete sponsor - will fail due to admin validation
	deleteMsg := &types.MsgDeleteSponsor{
		Creator:         signer,
		ContractAddress: contractAddr,
	}

	_, err = msgServer.DeleteSponsor(sdk.WrapSDKContext(ctx), deleteMsg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid contract address")

	// The sponsor still exists because delete failed
	assert.True(t, keeper.HasSponsor(ctx, contractAddr))
}

func TestMsgServerMultipleSponsors(t *testing.T) {
	keeper, ctx, msgServer, _, _ := setupMsgServerEnv(t)

	signer := "dora1xyz000000000000000000000000000000000000000000000000000000x"
	contracts := []string{
		"dora1abc000000000000000000000000000000000000000000000000000000x",
		"dora1def000000000000000000000000000000000000000000000000000000x",
		"dora1ghi000000000000000000000000000000000000000000000000000000x",
	}

	// Note: With admin validation, SetSponsor operations will fail
	// because the mock wasm keeper doesn't provide contract info

	// Try to set multiple sponsors - all will fail due to contract address validation
	for _, contractAddr := range contracts {
		msg := &types.MsgSetSponsor{
			Creator:         signer,
			ContractAddress: contractAddr,
			IsSponsored:     true,
		}

		_, err := msgServer.SetSponsor(sdk.WrapSDKContext(ctx), msg)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid contract address")
	}

	// Since all SetSponsor operations failed, no sponsors should exist
	allSponsors := keeper.GetAllSponsors(ctx)
	require.Len(t, allSponsors, 0)

	// Create sponsors directly for testing other operations
	for i, contractAddr := range contracts {
		sponsor := types.ContractSponsor{
			ContractAddress: contractAddr,
			IsSponsored:     i%2 == 0, // alternate between true and false
		}
		keeper.SetSponsor(ctx, sponsor)
	}

	// Verify all sponsors are set correctly
	allSponsors = keeper.GetAllSponsors(ctx)
	require.Len(t, allSponsors, 3)

	// Check individual sponsor states
	assert.True(t, keeper.IsSponsored(ctx, contracts[0]))  // index 0, should be true
	assert.False(t, keeper.IsSponsored(ctx, contracts[1])) // index 1, should be false
	assert.True(t, keeper.IsSponsored(ctx, contracts[2]))  // index 2, should be true

	// Verify sponsor contracts
	for _, contractAddr := range contracts {
		sponsor, found := keeper.GetSponsor(ctx, contractAddr)
		require.True(t, found)
		assert.Equal(t, contractAddr, sponsor.ContractAddress)
	}

	// Try to update one sponsor - will fail due to contract address validation
	updateMsg := &types.MsgUpdateSponsor{
		Creator:         signer,
		ContractAddress: contracts[1],
		IsSponsored:     true,
	}

	_, err := msgServer.UpdateSponsor(sdk.WrapSDKContext(ctx), updateMsg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid contract address")

	// The sponsor state should remain unchanged because update failed
	assert.False(t, keeper.IsSponsored(ctx, contracts[1]))

	// Try to delete one sponsor - will fail due to contract address validation
	deleteMsg := &types.MsgDeleteSponsor{
		Creator:         signer,
		ContractAddress: contracts[0],
	}

	_, err = msgServer.DeleteSponsor(sdk.WrapSDKContext(ctx), deleteMsg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid contract address")

	// The sponsor should still exist because delete failed
	assert.True(t, keeper.HasSponsor(ctx, contracts[0]))
	assert.True(t, keeper.IsSponsored(ctx, contracts[0]))

	// Final state should be unchanged - all 3 sponsors still exist
	allSponsors = keeper.GetAllSponsors(ctx)
	require.Len(t, allSponsors, 3)
}

// When no ticket issuer is set, only the contract admin can issue tickets.
func TestIssuePolicyTicket_Auth_AdminOnlyWhenNoIssuer(t *testing.T) {
    keeper, ctx, msgServer, mockWasmKeeper, _ := setupMsgServerEnv(t)

    // Params
    params := types.DefaultParams()
    require.NoError(t, keeper.SetParams(ctx, params))

    // Prepare addresses
    admin := sdk.AccAddress([]byte("admin_issue_noissuer_____"))
    other := sdk.AccAddress([]byte("other_issue_noissuer_____"))
    user := sdk.AccAddress([]byte("user_issue_noissuer______"))
    contract := sdk.AccAddress([]byte("contract_issue_noissuer__"))

    // Contract admin set
    mockWasmKeeper.SetContractInfo(contract.String(), admin.String())
    // Sponsor exists but no issuer configured
    require.NoError(t, keeper.SetSponsor(ctx, types.ContractSponsor{ContractAddress: contract.String(), IsSponsored: true}))

    // Non-admin attempt -> unauthorized
    _, err := msgServer.IssuePolicyTicket(sdk.WrapSDKContext(ctx), &types.MsgIssuePolicyTicket{
        Creator:         other.String(),
        ContractAddress: contract.String(),
        UserAddress:     user.String(),
        Method:          "inc",
        Uses:            1,
    })
    require.Error(t, err)

    // Admin issues successfully
    _, err = msgServer.IssuePolicyTicket(sdk.WrapSDKContext(ctx), &types.MsgIssuePolicyTicket{
        Creator:         admin.String(),
        ContractAddress: contract.String(),
        UserAddress:     user.String(),
        Method:          "inc",
        Uses:            1,
    })
    require.NoError(t, err)
}

// When a ticket issuer is set, both admin and issuer are authorized to issue tickets.
func TestIssuePolicyTicket_Auth_IssuerAndAdminAllowed(t *testing.T) {
    keeper, ctx, msgServer, mockWasmKeeper, _ := setupMsgServerEnv(t)
    params := types.DefaultParams()
    require.NoError(t, keeper.SetParams(ctx, params))

    admin := sdk.AccAddress([]byte("admin_issue_issuer_auth___")).String()
    issuer := sdk.AccAddress([]byte("issuer_issue_issuer_auth__")).String()
    user := sdk.AccAddress([]byte("user_issue_issuer_auth____")).String()
    contract := sdk.AccAddress([]byte("contract_issue_issuer____")).String()

    mockWasmKeeper.SetContractInfo(contract, admin)
    // Configure sponsor with issuer
    require.NoError(t, keeper.SetSponsor(ctx, types.ContractSponsor{ContractAddress: contract, IsSponsored: true, TicketIssuerAddress: issuer}))

    // Issuer can issue (method inc)
    _, err := msgServer.IssuePolicyTicket(sdk.WrapSDKContext(ctx), &types.MsgIssuePolicyTicket{
        Creator:         issuer,
        ContractAddress: contract,
        UserAddress:     user,
        Method:          "inc",
        Uses:            1,
    })
    require.NoError(t, err)

    // Admin can issue too, for a different method (dec)
    _, err = msgServer.IssuePolicyTicket(sdk.WrapSDKContext(ctx), &types.MsgIssuePolicyTicket{
        Creator:         admin,
        ContractAddress: contract,
        UserAddress:     user,
        Method:          "dec",
        Uses:            1,
    })
    require.NoError(t, err)

    // Admin attempting to re-issue the same method should be rejected due to active ticket conflict
    _, err = msgServer.IssuePolicyTicket(sdk.WrapSDKContext(ctx), &types.MsgIssuePolicyTicket{
        Creator:         admin,
        ContractAddress: contract,
        UserAddress:     user,
        Method:          "inc",
        Uses:            1,
    })
    require.Error(t, err)
    require.Contains(t, err.Error(), "active policy ticket already exists")
}

// Issuing requires an existing sponsor entry.
func TestIssuePolicyTicket_RequireSponsor(t *testing.T) {
    keeper, ctx, msgServer, mockWasmKeeper, _ := setupMsgServerEnv(t)
    // Params
    require.NoError(t, keeper.SetParams(ctx, types.DefaultParams()))

    admin := sdk.AccAddress([]byte("admin_issue_require_______")).String()
    user := sdk.AccAddress([]byte("user_issue_require________")).String()
    contract := sdk.AccAddress([]byte("contract_issue_require____")).String()
    mockWasmKeeper.SetContractInfo(contract, admin)

    // No sponsor set -> should fail
    _, err := msgServer.IssuePolicyTicket(sdk.WrapSDKContext(ctx), &types.MsgIssuePolicyTicket{
        Creator:         admin,
        ContractAddress: contract,
        UserAddress:     user,
        Method:          "inc",
        Uses:            1,
    })
    require.Error(t, err)
}

// Uses clamp should emit the clamped event with requested and clamped_to attributes.
func TestIssuePolicyTicket_ClampEmitsEvent(t *testing.T) {
    keeper, ctx, msgServer, mockWasmKeeper, _ := setupMsgServerEnv(t)
    p := types.DefaultParams()
    p.MaxMethodTicketUsesPerIssue = 2
    require.NoError(t, keeper.SetParams(ctx, p))

    admin := sdk.AccAddress([]byte("admin_issue_clamp_event___")).String()
    user := sdk.AccAddress([]byte("user_issue_clamp_event____")).String()
    contract := sdk.AccAddress([]byte("contract_issue_clamp_ev__")).String()
    mockWasmKeeper.SetContractInfo(contract, admin)
    require.NoError(t, keeper.SetSponsor(ctx, types.ContractSponsor{ContractAddress: contract, IsSponsored: true}))

    // Capture events
    ctx = ctx.WithEventManager(sdk.NewEventManager())
    _, err := msgServer.IssuePolicyTicket(sdk.WrapSDKContext(ctx), &types.MsgIssuePolicyTicket{
        Creator:         admin,
        ContractAddress: contract,
        UserAddress:     user,
        Method:          "do",
        Uses:            10, // > 2
    })
    require.NoError(t, err)

    // Find clamp event
    found := false
    for _, ev := range ctx.EventManager().Events() {
        if ev.Type != types.EventTypeTicketUsesClamped { continue }
        attrs := map[string]string{}
        for _, a := range ev.Attributes { attrs[a.Key] = a.Value }
        if attrs[types.AttributeKeyRequestedUses] == "10" && attrs[types.AttributeKeyClampedTo] == "2" {
            found = true
            break
        }
    }
    require.True(t, found, "should emit clamped event with requested and clamped_to")
}

// Re-issuing the same method for the same (contract,user) should be rejected when a live ticket exists.
func TestIssuePolicyTicket_ReturnExisting_WithoutMutation(t *testing.T) {
    keeper, ctx, msgServer, mockWasmKeeper, _ := setupMsgServerEnv(t)
    p := types.DefaultParams()
    p.MaxMethodTicketUsesPerIssue = 5
    p.PolicyTicketTtlBlocks = 30
    require.NoError(t, keeper.SetParams(ctx, p))

    admin := sdk.AccAddress([]byte("admin_issue_return_exist__")).String()
    user := sdk.AccAddress([]byte("user_issue_return_exist___")).String()
    contract := sdk.AccAddress([]byte("contract_issue_return____")).String()
    mockWasmKeeper.SetContractInfo(contract, admin)
    require.NoError(t, keeper.SetSponsor(ctx, types.ContractSponsor{ContractAddress: contract, IsSponsored: true}))

    // First issue
    resp1, err := msgServer.IssuePolicyTicket(sdk.WrapSDKContext(ctx), &types.MsgIssuePolicyTicket{
        Creator:         admin,
        ContractAddress: contract,
        UserAddress:     user,
        Method:          "inc",
        Uses:            3,
    })
    require.NoError(t, err)
    require.True(t, resp1.Created)
    // keep digest locally if needed in future checks (not required for conflict path)

    // Second issue (same method) should fail with conflict
    ctx = ctx.WithEventManager(sdk.NewEventManager())
    resp2, err := msgServer.IssuePolicyTicket(sdk.WrapSDKContext(ctx), &types.MsgIssuePolicyTicket{
        Creator:         admin,
        ContractAddress: contract,
        UserAddress:     user,
        Method:          "inc",
        Uses:            4,
    })
    require.Error(t, err)
    require.Nil(t, resp2)
    require.Contains(t, err.Error(), "active policy ticket already exists")
    // Conflict event emitted
    evs := ctx.EventManager().Events()
    hasConflict := false
    for _, ev := range evs {
        if ev.Type == types.EventTypePolicyTicketIssueConflict {
            hasConflict = true
            break
        }
    }
    require.True(t, hasConflict)
}

// If an existing ticket is expired or consumed, a new ticket should be created when issuing again.
func TestIssuePolicyTicket_ReplaceExpiredOrConsumed(t *testing.T) {
    keeper, ctx, msgServer, mockWasmKeeper, _ := setupMsgServerEnv(t)
    p := types.DefaultParams()
    p.PolicyTicketTtlBlocks = 20
    require.NoError(t, keeper.SetParams(ctx, p))

    admin := sdk.AccAddress([]byte("admin_issue_replace_exist_"))
    user := sdk.AccAddress([]byte("user_issue_replace_exist__"))
    contract := sdk.AccAddress([]byte("contract_issue_replace___"))
    mockWasmKeeper.SetContractInfo(contract.String(), admin.String())
    require.NoError(t, keeper.SetSponsor(ctx, types.ContractSponsor{ContractAddress: contract.String(), IsSponsored: true}))

    // Insert an expired ticket for method "inc"
    md := keeper.ComputeMethodDigest(contract.String(), []string{"inc"})
    expired := types.PolicyTicket{ContractAddress: contract.String(), UserAddress: user.String(), Digest: md, ExpiryHeight: uint64(ctx.BlockHeight()), UsesRemaining: 1, Method: "inc"}
    require.NoError(t, keeper.SetPolicyTicket(ctx, expired))

    // Issue again -> should create a new one
    resp, err := msgServer.IssuePolicyTicket(sdk.WrapSDKContext(ctx), &types.MsgIssuePolicyTicket{
        Creator:         admin.String(),
        ContractAddress: contract.String(),
        UserAddress:     user.String(),
        Method:          "inc",
        Uses:            2,
    })
    require.NoError(t, err)
    require.True(t, resp.Created)
    require.Equal(t, md, resp.Ticket.Digest)
    require.False(t, resp.Ticket.Consumed)
    require.Greater(t, resp.Ticket.ExpiryHeight, uint64(ctx.BlockHeight()))

    // Now mark as consumed and try again
    consumed := resp.Ticket
    consumed.UsesRemaining = 0
    consumed.Consumed = true
    require.NoError(t, keeper.SetPolicyTicket(ctx, *consumed))
    resp2, err := msgServer.IssuePolicyTicket(sdk.WrapSDKContext(ctx), &types.MsgIssuePolicyTicket{
        Creator:         admin.String(),
        ContractAddress: contract.String(),
        UserAddress:     user.String(),
        Method:          "inc",
        Uses:            1,
    })
    require.NoError(t, err)
    require.True(t, resp2.Created)
    require.Equal(t, md, resp2.Ticket.Digest)
    require.False(t, resp2.Ticket.Consumed)
}

// Issuance should reject method names exceeding max_method_name_bytes.
func TestIssuePolicyTicket_MethodNameTooLong_Rejected(t *testing.T) {
    keeper, ctx, msgServer, mockWasmKeeper, _ := setupMsgServerEnv(t)
    // Set small method name limit
    p := types.DefaultParams()
    p.MaxMethodNameBytes = 4
    require.NoError(t, keeper.SetParams(ctx, p))

    admin := sdk.AccAddress([]byte("admin_issue_long_method__")).String()
    user := sdk.AccAddress([]byte("user_issue_long_method___")).String()
    contract := sdk.AccAddress([]byte("contract_issue_long_meth")).String()
    mockWasmKeeper.SetContractInfo(contract, admin)
    require.NoError(t, keeper.SetSponsor(ctx, types.ContractSponsor{ContractAddress: contract, IsSponsored: true}))

    // Long method name -> should error
    _, err := msgServer.IssuePolicyTicket(sdk.WrapSDKContext(ctx), &types.MsgIssuePolicyTicket{
        Creator:         admin,
        ContractAddress: contract,
        UserAddress:     user,
        Method:          "longname",
        Uses:            1,
    })
    require.Error(t, err)
}

// TestMsgServerAdminPermissions tests that only contract admins can manage sponsors
func TestMsgServerAdminPermissions(t *testing.T) {
	keeper, ctx, msgServer, mockWasmKeeper, _ := setupMsgServerEnv(t)

	// Generate base addresses for different test cases
	baseContractAddr := "base_contract_addr"
	adminAddr := sdk.AccAddress([]byte("test_admin_address_12")).String()

	// Test SetSponsor - invalid creator address
	t.Run("SetSponsor with invalid creator address", func(t *testing.T) {
		contractAddr := sdk.AccAddress([]byte(baseContractAddr + "_1")).String()
		msg := &types.MsgSetSponsor{
			Creator:         "invalid-address",
			ContractAddress: contractAddr,
			IsSponsored:     true,
		}

		_, err := msgServer.SetSponsor(sdk.WrapSDKContext(ctx), msg)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "contract not found")
	})

	// Test SetSponsor - contract not found (mock wasm keeper returns nil)
	t.Run("SetSponsor with non-existent contract", func(t *testing.T) {
		contractAddr := sdk.AccAddress([]byte(baseContractAddr + "_2")).String()
		msg := &types.MsgSetSponsor{
			Creator:         adminAddr,
			ContractAddress: contractAddr,
			IsSponsored:     true,
		}

		_, err := msgServer.SetSponsor(sdk.WrapSDKContext(ctx), msg)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "contract not found")
	})

	// Test SetSponsor - user is not contract admin
	t.Run("SetSponsor with non-admin user", func(t *testing.T) {
		contractAddr := sdk.AccAddress([]byte(baseContractAddr + "_3")).String()
		// Set up a contract with a different admin
		realAdminAddr := sdk.AccAddress([]byte("real_admin_address_12")).String()
		mockWasmKeeper.SetContractInfo(contractAddr, realAdminAddr)

		msg := &types.MsgSetSponsor{
			Creator:         adminAddr, // different from real admin
			ContractAddress: contractAddr,
			IsSponsored:     true,
		}

		_, err := msgServer.SetSponsor(sdk.WrapSDKContext(ctx), msg)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "only contract admin can set sponsor")
	})

	// Test SetSponsor - success with contract admin
	t.Run("SetSponsor with contract admin", func(t *testing.T) {
		contractAddr := sdk.AccAddress([]byte(baseContractAddr + "_4")).String()
		// Set up the contract with adminAddr as admin
		mockWasmKeeper.SetContractInfo(contractAddr, adminAddr)

		// Create MaxGrantPerUser since IsSponsored is true
		maxGrant := sdk.NewCoins(sdk.NewCoin("peaka", sdk.NewInt(1000000)))
		pbCoins := make([]*sdk.Coin, len(maxGrant))
		for i, coin := range maxGrant {
			newCoin := sdk.Coin{
				Denom:  coin.Denom,
				Amount: coin.Amount,
			}
			pbCoins[i] = &newCoin
		}

		msg := &types.MsgSetSponsor{
			Creator:         adminAddr,
			ContractAddress: contractAddr,
			IsSponsored:     true,
			MaxGrantPerUser: pbCoins,
		}

		_, err := msgServer.SetSponsor(sdk.WrapSDKContext(ctx), msg)
		require.NoError(t, err)

		// Verify the sponsor was set
		sponsor, found := keeper.GetSponsor(ctx, contractAddr)
		assert.True(t, found)
		assert.True(t, sponsor.IsSponsored)
	})

	// Test UpdateSponsor - sponsor not found (sponsor check happens first)
	t.Run("UpdateSponsor with non-existent contract", func(t *testing.T) {
		contractAddr := sdk.AccAddress([]byte(baseContractAddr + "_5")).String()
		msg := &types.MsgUpdateSponsor{
			Creator:         adminAddr,
			ContractAddress: contractAddr,
			IsSponsored:     false,
		}

		_, err := msgServer.UpdateSponsor(sdk.WrapSDKContext(ctx), msg)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "contract not found")
	})

	// Test DeleteSponsor - contract not found
	t.Run("DeleteSponsor with non-existent contract", func(t *testing.T) {
		contractAddr := sdk.AccAddress([]byte(baseContractAddr + "_6")).String()
		msg := &types.MsgDeleteSponsor{
			Creator:         adminAddr,
			ContractAddress: contractAddr,
		}

		_, err := msgServer.DeleteSponsor(sdk.WrapSDKContext(ctx), msg)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "contract not found")
	})
}

// TestMsgServerInvalidAddresses tests error handling for invalid addresses
func TestMsgServerInvalidAddresses(t *testing.T) {
	_, ctx, msgServer, _, _ := setupMsgServerEnv(t)

	invalidAddr := "invalid-bech32-address"
	contractAddr := sdk.AccAddress([]byte("test_contract_addr_12")).String()

	testCases := []struct {
		name        string
		msgType     string
		creator     string
		contract    string
		expectError string
	}{
		{
			name:        "SetSponsor invalid creator",
			msgType:     "set",
			creator:     invalidAddr,
			contract:    contractAddr,
			expectError: "contract not found",
		},
		{
			name:        "UpdateSponsor invalid creator",
			msgType:     "update",
			creator:     invalidAddr,
			contract:    contractAddr,
			expectError: "contract not found",
		},
		{
			name:        "DeleteSponsor invalid creator",
			msgType:     "delete",
			creator:     invalidAddr,
			contract:    contractAddr,
			expectError: "contract not found",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var err error

			switch tc.msgType {
			case "set":
				msg := &types.MsgSetSponsor{
					Creator:         tc.creator,
					ContractAddress: tc.contract,
					IsSponsored:     true,
				}
				_, err = msgServer.SetSponsor(sdk.WrapSDKContext(ctx), msg)
			case "update":
				msg := &types.MsgUpdateSponsor{
					Creator:         tc.creator,
					ContractAddress: tc.contract,
					IsSponsored:     false,
				}
				_, err = msgServer.UpdateSponsor(sdk.WrapSDKContext(ctx), msg)
			case "delete":
				msg := &types.MsgDeleteSponsor{
					Creator:         tc.creator,
					ContractAddress: tc.contract,
				}
				_, err = msgServer.DeleteSponsor(sdk.WrapSDKContext(ctx), msg)
			}

			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.expectError)
		})
	}
}

// TestMsgServerPermissionDenied tests unauthorized access scenarios
func TestMsgServerPermissionDenied(t *testing.T) {
	keeper, ctx, msgServer, _, _ := setupMsgServerEnv(t)

	contractAddr := "dora1contract123"
	nonAdminAddr := "dora1user456"

	// These tests will fail because the mock wasm keeper returns nil for GetContractInfo
	// In a real scenario with proper mocking, we would test that non-admin users are rejected

	t.Run("SetSponsor permission denied", func(t *testing.T) {
		msg := &types.MsgSetSponsor{
			Creator:         nonAdminAddr,
			ContractAddress: contractAddr,
			IsSponsored:     true,
		}

		_, err := msgServer.SetSponsor(sdk.WrapSDKContext(ctx), msg)
		require.Error(t, err)
		// The contract address used here is not valid bech32, so contract address validation fails first
		assert.Contains(t, err.Error(), "invalid contract address")
	})

	// First create a sponsor to test update/delete scenarios
	// Note: This will also fail due to mock limitations, but shows the test structure
	sponsor := types.ContractSponsor{
		ContractAddress: contractAddr,
		IsSponsored:     true,
	}
	keeper.SetSponsor(ctx, sponsor)

	t.Run("UpdateSponsor permission denied", func(t *testing.T) {
		msg := &types.MsgUpdateSponsor{
			Creator:         nonAdminAddr,
			ContractAddress: contractAddr,
			IsSponsored:     false,
		}

		_, err := msgServer.UpdateSponsor(sdk.WrapSDKContext(ctx), msg)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid contract address")
	})

	t.Run("DeleteSponsor permission denied", func(t *testing.T) {
		msg := &types.MsgDeleteSponsor{
			Creator:         nonAdminAddr,
			ContractAddress: contractAddr,
		}

		_, err := msgServer.DeleteSponsor(sdk.WrapSDKContext(ctx), msg)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid contract address")
	})
}

// TestMsgServerAdminAuthorizationDemo demonstrates how admin authorization works
// Note: This test documents the expected behavior with mock limitations
func TestMsgServerAdminAuthorizationDemo(t *testing.T) {
	keeper, ctx, msgServer, _, _ := setupMsgServerEnv(t)

	// Test data
	contractAddr := "dora1contract123"
	adminAddr := "dora1admin123"
	nonAdminAddr := "dora1hacker456"

	// Test case 1: Invalid address format
	t.Run("Invalid creator address format should be rejected", func(t *testing.T) {
		msg := &types.MsgSetSponsor{
			Creator:         "not-a-valid-bech32",
			ContractAddress: contractAddr,
			IsSponsored:     true,
		}

		_, err := msgServer.SetSponsor(sdk.WrapSDKContext(ctx), msg)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid contract address")

		// Verify no sponsor was created
		assert.False(t, keeper.HasSponsor(ctx, contractAddr))
	})

	// Test case 2: Contract admin validation (with current mock limitations)
	t.Run("Contract admin validation process", func(t *testing.T) {
		msg := &types.MsgSetSponsor{
			Creator:         adminAddr,
			ContractAddress: contractAddr,
			IsSponsored:     true,
		}

		_, err := msgServer.SetSponsor(sdk.WrapSDKContext(ctx), msg)
		require.Error(t, err)

		// The contract address used here is not valid bech32, so contract address validation fails first
		assert.Contains(t, err.Error(), "invalid contract address")

		// Verify no sponsor was created due to auth failure
		assert.False(t, keeper.HasSponsor(ctx, contractAddr))
	})

	// Test case 3: All three operations should have the same auth behavior
	testOps := []struct {
		name string
		fn   func() error
	}{
		{
			name: "SetSponsor",
			fn: func() error {
				msg := &types.MsgSetSponsor{
					Creator:         nonAdminAddr,
					ContractAddress: contractAddr,
					IsSponsored:     true,
				}
				_, err := msgServer.SetSponsor(sdk.WrapSDKContext(ctx), msg)
				return err
			},
		},
		{
			name: "UpdateSponsor",
			fn: func() error {
				// First create a sponsor for update test
				sponsor := types.ContractSponsor{
					ContractAddress: contractAddr,
					IsSponsored:     true,
				}
				keeper.SetSponsor(ctx, sponsor)

				msg := &types.MsgUpdateSponsor{
					Creator:         nonAdminAddr,
					ContractAddress: contractAddr,
					IsSponsored:     false,
				}
				_, err := msgServer.UpdateSponsor(sdk.WrapSDKContext(ctx), msg)
				return err
			},
		},
		{
			name: "DeleteSponsor",
			fn: func() error {
				// Ensure sponsor exists for delete test
				sponsor := types.ContractSponsor{
					ContractAddress: contractAddr,
					IsSponsored:     true,
				}
				keeper.SetSponsor(ctx, sponsor)

				msg := &types.MsgDeleteSponsor{
					Creator:         nonAdminAddr,
					ContractAddress: contractAddr,
				}
				_, err := msgServer.DeleteSponsor(sdk.WrapSDKContext(ctx), msg)
				return err
			},
		},
	}

	for _, testOp := range testOps {
		t.Run(testOp.name+" admin check", func(t *testing.T) {
			err := testOp.fn()
			require.Error(t, err, "Operation should fail due to contract address validation")
			assert.Contains(t, err.Error(), "invalid contract address",
				"Error should indicate contract address validation failure")
		})
	}
}

func TestMsgServerWithMaxGrantPerUser(t *testing.T) {
	keeper, ctx, msgServer, mockWasmKeeper, _ := setupMsgServerEnv(t)

	// Set up a valid contract and admin
	contractAddr := sdk.AccAddress([]byte("test_contract_addr_12")).String()
	adminAddr := sdk.AccAddress([]byte("test_admin_address_12")).String()

	// Set up mock wasm keeper
	mockWasmKeeper.SetContractInfo(contractAddr, adminAddr)

	t.Run("SetSponsor with max grant per user", func(t *testing.T) {
		// Create message with max grant per user
		maxGrant := sdk.NewCoins(
			sdk.NewCoin("peaka", sdk.NewInt(1000000)),
		)
		pbCoins := make([]*sdk.Coin, len(maxGrant))
		for i, coin := range maxGrant {
			newCoin := sdk.Coin{
				Denom:  coin.Denom,
				Amount: coin.Amount,
			}
			pbCoins[i] = &newCoin
		}

		msg := &types.MsgSetSponsor{
			Creator:         adminAddr,
			ContractAddress: contractAddr,
			IsSponsored:     true,
			MaxGrantPerUser: pbCoins,
		}

		resp, err := msgServer.SetSponsor(ctx, msg)
		require.NoError(t, err)
		require.NotNil(t, resp)

		// Verify sponsor was set with correct max grant per user
		sponsor, found := keeper.GetSponsor(ctx, contractAddr)
		require.True(t, found)
		require.True(t, sponsor.IsSponsored)
		require.Len(t, sponsor.MaxGrantPerUser, 1)

		// Check the saved max grant per user
		actualMaxGrant, err := keeper.GetMaxGrantPerUser(ctx, contractAddr)
		require.NoError(t, err)
		expectedMaxGrant := maxGrant.Sort()
		actualMaxGrant = actualMaxGrant.Sort()
		require.Equal(t, expectedMaxGrant, actualMaxGrant)
	})

	t.Run("UpdateSponsor with max grant per user", func(t *testing.T) {
		// Update with different max grant per user
		newMaxGrant := sdk.NewCoins(sdk.NewCoin("peaka", sdk.NewInt(2000000)))
		pbCoins := make([]*sdk.Coin, len(newMaxGrant))
		for i, coin := range newMaxGrant {
			newCoin := sdk.Coin{
				Denom:  coin.Denom,
				Amount: coin.Amount,
			}
			pbCoins[i] = &newCoin
		}

		msg := &types.MsgUpdateSponsor{
			Creator:         adminAddr,
			ContractAddress: contractAddr,
			IsSponsored:     true,
			MaxGrantPerUser: pbCoins,
		}

		resp, err := msgServer.UpdateSponsor(ctx, msg)
		require.NoError(t, err)
		require.NotNil(t, resp)

		// Verify max grant per user was updated
		actualMaxGrant, err := keeper.GetMaxGrantPerUser(ctx, contractAddr)
		require.NoError(t, err)
		require.Equal(t, newMaxGrant, actualMaxGrant)
	})
}

// TestMsgServerSponsorAddressGeneration tests that sponsor_address is correctly derived
func TestMsgServerSponsorAddressGeneration(t *testing.T) {
	keeper, ctx, msgServer, mockWasmKeeper, _ := setupMsgServerEnv(t)

	// Set up a valid contract and admin
	contractAddr := sdk.AccAddress([]byte("test_contract_addr_12")).String()
	adminAddr := sdk.AccAddress([]byte("test_admin_address_12")).String()

	// Set up mock wasm keeper
	mockWasmKeeper.SetContractInfo(contractAddr, adminAddr)

	t.Run("SetSponsor generates correct sponsor_address", func(t *testing.T) {
		// Create message
		maxGrant := sdk.NewCoins(sdk.NewCoin("peaka", sdk.NewInt(1000000)))
		pbCoins := make([]*sdk.Coin, len(maxGrant))
		for i, coin := range maxGrant {
			newCoin := sdk.Coin{
				Denom:  coin.Denom,
				Amount: coin.Amount,
			}
			pbCoins[i] = &newCoin
		}

		msg := &types.MsgSetSponsor{
			Creator:         adminAddr,
			ContractAddress: contractAddr,
			IsSponsored:     true,
			MaxGrantPerUser: pbCoins,
		}

		resp, err := msgServer.SetSponsor(ctx, msg)
		require.NoError(t, err)
		require.NotNil(t, resp)

		// Verify sponsor was created with sponsor_address
		sponsor, found := keeper.GetSponsor(ctx, contractAddr)
		require.True(t, found)
		require.True(t, sponsor.IsSponsored)
		require.NotEmpty(t, sponsor.SponsorAddress, "sponsor_address should be generated")

		// Verify the sponsor_address is a valid address
		_, err = sdk.AccAddressFromBech32(sponsor.SponsorAddress)
		require.NoError(t, err, "sponsor_address should be a valid bech32 address")

		// Verify sponsor_address is different from contract_address
		require.NotEqual(t, sponsor.ContractAddress, sponsor.SponsorAddress,
			"sponsor_address should be different from contract_address")
	})

	t.Run("UpdateSponsor preserves sponsor_address", func(t *testing.T) {
		// Get the original sponsor
		originalSponsor, found := keeper.GetSponsor(ctx, contractAddr)
		require.True(t, found)
		originalSponsorAddr := originalSponsor.SponsorAddress

		// Update the sponsor
		newMaxGrant := sdk.NewCoins(sdk.NewCoin("peaka", sdk.NewInt(2000000)))
		pbCoins := make([]*sdk.Coin, len(newMaxGrant))
		for i, coin := range newMaxGrant {
			newCoin := sdk.Coin{
				Denom:  coin.Denom,
				Amount: coin.Amount,
			}
			pbCoins[i] = &newCoin
		}

		msg := &types.MsgUpdateSponsor{
			Creator:         adminAddr,
			ContractAddress: contractAddr,
			IsSponsored:     true,
			MaxGrantPerUser: pbCoins,
		}

		resp, err := msgServer.UpdateSponsor(ctx, msg)
		require.NoError(t, err)
		require.NotNil(t, resp)

		// Verify sponsor_address is preserved after update
		updatedSponsor, found := keeper.GetSponsor(ctx, contractAddr)
		require.True(t, found)
		require.Equal(t, originalSponsorAddr, updatedSponsor.SponsorAddress,
			"sponsor_address should be preserved during updates")
	})
}

// TestMsgServerSponsorAddressConsistency tests sponsor address derivation consistency
func TestMsgServerSponsorAddressConsistency(t *testing.T) {
	keeper, ctx, mockWasmKeeper, authKeeper, bankKeeper := setupKeeperWithDeps(t)
	msgServer := NewMsgServerImplWithDeps(keeper, bankKeeper, authKeeper)

	// Set up multiple contracts with the same admin
	adminAddr := sdk.AccAddress([]byte("test_admin_address_12")).String()
	contracts := []string{
		sdk.AccAddress([]byte("contract_1")).String(),
		sdk.AccAddress([]byte("contract_2")).String(),
		sdk.AccAddress([]byte("contract_3")).String(),
	}

	// Set up mock wasm keeper for all contracts
	for _, contractAddr := range contracts {
		mockWasmKeeper.SetContractInfo(contractAddr, adminAddr)
	}

	sponsorAddresses := make([]string, len(contracts))

	t.Run("Each contract gets unique sponsor_address", func(t *testing.T) {
		// Create sponsors for all contracts
		for i, contractAddr := range contracts {
			maxGrant := sdk.NewCoins(sdk.NewCoin("peaka", sdk.NewInt(1000000)))
			pbCoins := make([]*sdk.Coin, len(maxGrant))
			for j, coin := range maxGrant {
				newCoin := sdk.Coin{
					Denom:  coin.Denom,
					Amount: coin.Amount,
				}
				pbCoins[j] = &newCoin
			}

			msg := &types.MsgSetSponsor{
				Creator:         adminAddr,
				ContractAddress: contractAddr,
				IsSponsored:     true,
				MaxGrantPerUser: pbCoins,
			}

			_, err := msgServer.SetSponsor(ctx, msg)
			require.NoError(t, err)

			// Get the generated sponsor address
			sponsor, found := keeper.GetSponsor(ctx, contractAddr)
			require.True(t, found)
			require.NotEmpty(t, sponsor.SponsorAddress)
			sponsorAddresses[i] = sponsor.SponsorAddress
		}

		// Verify all sponsor addresses are unique
		for i := 0; i < len(sponsorAddresses); i++ {
			for j := i + 1; j < len(sponsorAddresses); j++ {
				require.NotEqual(t, sponsorAddresses[i], sponsorAddresses[j],
					"sponsor addresses should be unique for different contracts")
			}
		}
	})

	t.Run("Sponsor address derivation is deterministic", func(t *testing.T) {
		// Delete and recreate the first sponsor to test deterministic generation
		deleteMsg := &types.MsgDeleteSponsor{
			Creator:         adminAddr,
			ContractAddress: contracts[0],
		}
		_, err := msgServer.DeleteSponsor(ctx, deleteMsg)
		require.NoError(t, err)

		// Recreate the sponsor
		maxGrant := sdk.NewCoins(sdk.NewCoin("peaka", sdk.NewInt(1000000)))
		pbCoins := make([]*sdk.Coin, len(maxGrant))
		for i, coin := range maxGrant {
			newCoin := sdk.Coin{
				Denom:  coin.Denom,
				Amount: coin.Amount,
			}
			pbCoins[i] = &newCoin
		}

		msg := &types.MsgSetSponsor{
			Creator:         adminAddr,
			ContractAddress: contracts[0],
			IsSponsored:     true,
			MaxGrantPerUser: pbCoins,
		}

		_, err = msgServer.SetSponsor(ctx, msg)
		require.NoError(t, err)

		// Verify the sponsor address is the same as before
		sponsor, found := keeper.GetSponsor(ctx, contracts[0])
		require.True(t, found)
		require.Equal(t, sponsorAddresses[0], sponsor.SponsorAddress,
			"sponsor address derivation should be deterministic")
	})
}

// ===== Withdraw sponsor funds tests (moved from withdraw_test.go) =====

func TestWithdrawSponsorFunds_Success(t *testing.T) {
	keeper, ctx, wasmMock, authKeeper, bankKeeper := setupKeeperWithDeps(t)

	// Prepare admin, contract, recipient
	admin := sdk.AccAddress("admin________________")
	contract := sdk.AccAddress("contract____________")
	recipient := sdk.AccAddress("recipient___________")

	// Set contract admin in wasm mock
	wasmMock.SetContractInfo(contract.String(), admin.String())

	// Create msg server with deps
	msgServer := NewMsgServerImplWithDeps(keeper, bankKeeper, authKeeper)

	// Create sponsor via msg to generate sponsor address
	maxGrant := sdk.NewCoins(sdk.NewCoin("peaka", sdk.NewInt(1000000)))
	setMsg := types.NewMsgSetSponsor(admin.String(), contract.String(), true, maxGrant)
	_, err := msgServer.SetSponsor(sdk.WrapSDKContext(ctx), setMsg)
	require.NoError(t, err)

	sponsor, found := keeper.GetSponsor(ctx, contract.String())
	require.True(t, found)
	sponsorAddr, err := sdk.AccAddressFromBech32(sponsor.SponsorAddress)
	require.NoError(t, err)

	// Fund sponsor address
	fund := sdk.NewCoins(sdk.NewCoin("peaka", sdk.NewInt(5000)))
	require.NoError(t, bankKeeper.MintCoins(ctx, types.ModuleName, fund))
	require.NoError(t, bankKeeper.SendCoinsFromModuleToAccount(ctx, types.ModuleName, sponsorAddr, fund))

	// Withdraw
	withdrawAmt := sdk.NewCoins(sdk.NewCoin("peaka", sdk.NewInt(3000)))
	wMsg := types.NewMsgWithdrawSponsorFunds(admin.String(), contract.String(), recipient.String(), withdrawAmt)

	// Add event manager
	ctx = ctx.WithEventManager(sdk.NewEventManager())

	_, err = msgServer.WithdrawSponsorFunds(sdk.WrapSDKContext(ctx), wMsg)
	require.NoError(t, err)

	// Check balances
	balSponsor := bankKeeper.GetBalance(ctx, sponsorAddr, "peaka")
	balRecipient := bankKeeper.GetBalance(ctx, recipient, "peaka")
	require.Equal(t, sdk.NewInt(2000), balSponsor.Amount)   // 5000 - 3000
	require.Equal(t, sdk.NewInt(3000), balRecipient.Amount) // 0 + 3000

	// Verify event emission and attributes
	var withdrawEvent sdk.Event
	eventFound := false
	for _, ev := range ctx.EventManager().Events() {
		if ev.Type == types.EventTypeSponsorWithdrawal {
			withdrawEvent = ev
			eventFound = true
			break
		}
	}
	require.True(t, eventFound, "sponsor_withdraw_funds event should be emitted")

	// Build expected attributes
	expected := map[string]string{
		types.AttributeKeyCreator:         admin.String(),
		types.AttributeKeyContractAddress: contract.String(),
		types.AttributeKeySponsorAddress:  sponsor.SponsorAddress,
		types.AttributeKeyRecipient:       recipient.String(),
		types.AttributeKeySponsorAmount:   withdrawAmt.String(),
	}

	// Check attributes
	got := map[string]string{}
	for _, attr := range withdrawEvent.Attributes {
		got[attr.Key] = attr.Value
	}
	for k, v := range expected {
		require.Equalf(t, v, got[k], "event attribute %s mismatch", k)
	}
}

func TestDeleteSponsorFailsWhenBalanceExists(t *testing.T) {
	keeper, ctx, wasmMock, authKeeper, bankKeeper := setupKeeperWithDeps(t)
	msgServer := NewMsgServerImplWithDeps(keeper, bankKeeper, authKeeper)

	admin := sdk.AccAddress("admin________________")
	contract := sdk.AccAddress("contract____________")

	wasmMock.SetContractInfo(contract.String(), admin.String())

	maxGrant := sdk.NewCoins(sdk.NewCoin("peaka", sdk.NewInt(1000)))
	setMsg := types.NewMsgSetSponsor(admin.String(), contract.String(), true, maxGrant)
	_, err := msgServer.SetSponsor(sdk.WrapSDKContext(ctx), setMsg)
	require.NoError(t, err)

	sponsor, found := keeper.GetSponsor(ctx, contract.String())
	require.True(t, found)

	sponsorAddr, err := sdk.AccAddressFromBech32(sponsor.SponsorAddress)
	require.NoError(t, err)

	fund := sdk.NewCoins(sdk.NewCoin("peaka", sdk.NewInt(500)))
	require.NoError(t, bankKeeper.MintCoins(ctx, types.ModuleName, fund))
	require.NoError(t, bankKeeper.SendCoinsFromModuleToAccount(ctx, types.ModuleName, sponsorAddr, fund))

	deleteMsg := types.NewMsgDeleteSponsor(admin.String(), contract.String())
	_, err = msgServer.DeleteSponsor(sdk.WrapSDKContext(ctx), deleteMsg)
	require.Error(t, err)
	require.Contains(t, err.Error(), "balance")

	withdrawMsg := types.NewMsgWithdrawSponsorFunds(admin.String(), contract.String(), admin.String(), fund)
	_, err = msgServer.WithdrawSponsorFunds(sdk.WrapSDKContext(ctx), withdrawMsg)
	require.NoError(t, err)

	_, err = msgServer.DeleteSponsor(sdk.WrapSDKContext(ctx), deleteMsg)
	require.NoError(t, err)
}

func TestWithdrawSponsorFunds_NotAdmin(t *testing.T) {
	keeper, ctx, wasmMock, authKeeper, bankKeeper := setupKeeperWithDeps(t)
	admin := sdk.AccAddress("admin________________")
	nonAdmin := sdk.AccAddress("user_________________")
	contract := sdk.AccAddress("contract____________")

	wasmMock.SetContractInfo(contract.String(), admin.String())
	msgServer := NewMsgServerImplWithDeps(keeper, bankKeeper, authKeeper)

	maxGrant := sdk.NewCoins(sdk.NewCoin("peaka", sdk.NewInt(1000000)))
	setMsg := types.NewMsgSetSponsor(admin.String(), contract.String(), true, maxGrant)
	_, err := msgServer.SetSponsor(sdk.WrapSDKContext(ctx), setMsg)
	require.NoError(t, err)

	// Try withdraw as non-admin
	wMsg := types.NewMsgWithdrawSponsorFunds(nonAdmin.String(), contract.String(), nonAdmin.String(), sdk.NewCoins(sdk.NewCoin("peaka", sdk.NewInt(1))))
	_, err = msgServer.WithdrawSponsorFunds(sdk.WrapSDKContext(ctx), wMsg)
	require.Error(t, err)
}

func TestWithdrawSponsorFunds_InsufficientFunds(t *testing.T) {
	keeper, ctx, wasmMock, authKeeper, bankKeeper := setupKeeperWithDeps(t)
	admin := sdk.AccAddress("admin________________")
	contract := sdk.AccAddress("contract____________")
	recipient := sdk.AccAddress("recipient___________")

	wasmMock.SetContractInfo(contract.String(), admin.String())
	msgServer := NewMsgServerImplWithDeps(keeper, bankKeeper, authKeeper)

	maxGrant := sdk.NewCoins(sdk.NewCoin("peaka", sdk.NewInt(1000000)))
	setMsg := types.NewMsgSetSponsor(admin.String(), contract.String(), true, maxGrant)
	_, err := msgServer.SetSponsor(sdk.WrapSDKContext(ctx), setMsg)
	require.NoError(t, err)

	sponsor, found := keeper.GetSponsor(ctx, contract.String())
	require.True(t, found)
	sponsorAddr, err := sdk.AccAddressFromBech32(sponsor.SponsorAddress)
	require.NoError(t, err)

	// Fund with small amount
	fund := sdk.NewCoins(sdk.NewCoin("peaka", sdk.NewInt(10)))
	require.NoError(t, bankKeeper.MintCoins(ctx, types.ModuleName, fund))
	require.NoError(t, bankKeeper.SendCoinsFromModuleToAccount(ctx, types.ModuleName, sponsorAddr, fund))

	// Try withdraw larger amount
	wMsg := types.NewMsgWithdrawSponsorFunds(admin.String(), contract.String(), recipient.String(), sdk.NewCoins(sdk.NewCoin("peaka", sdk.NewInt(100))))
	_, err = msgServer.WithdrawSponsorFunds(sdk.WrapSDKContext(ctx), wMsg)
	require.Error(t, err)
}
func TestMsgServer_IssuePolicyTicket_Admin(t *testing.T) {
    keeper, ctx, msgServer, mockWasmKeeper, bankKeeper := setupMsgServerEnv(t)
    _ = bankKeeper
    params := types.DefaultParams()
    require.NoError(t, keeper.SetParams(ctx, params))
    admin := sdk.AccAddress([]byte("admin_addr_issue_m_________"))
    contract := sdk.AccAddress([]byte("contract_addr_issue_m______"))
    mockWasmKeeper.SetContractInfo(contract.String(), admin.String())
    require.NoError(t, keeper.SetSponsor(ctx, types.ContractSponsor{ContractAddress: contract.String(), IsSponsored: true}))
    user := sdk.AccAddress([]byte("user_issue_m________________")).String()
    resp, err := msgServer.IssuePolicyTicket(sdk.WrapSDKContext(ctx), &types.MsgIssuePolicyTicket{
        Creator:         admin.String(),
        ContractAddress: contract.String(),
        UserAddress:     user,
        Method:          "increment",
    })
    require.NoError(t, err)
    require.True(t, resp.Created)
    require.NotNil(t, resp.Ticket)
    // Digest should match method digest
    expect := keeper.ComputeMethodDigest(contract.String(), []string{"increment"})
    require.Equal(t, expect, resp.Ticket.Digest)
}

func TestMsgServer_IssuePolicyTicket_ConflictOnDuplicate(t *testing.T) {
    keeper, ctx, msgServer, mockWasmKeeper, bankKeeper := setupMsgServerEnv(t)
    _ = bankKeeper
    params := types.DefaultParams()
    require.NoError(t, keeper.SetParams(ctx, params))
    admin := sdk.AccAddress([]byte("admin_addr_issue_m_idem____"))
    contract := sdk.AccAddress([]byte("contract_addr_issue_m_idem_"))
    mockWasmKeeper.SetContractInfo(contract.String(), admin.String())
    require.NoError(t, keeper.SetSponsor(ctx, types.ContractSponsor{ContractAddress: contract.String(), IsSponsored: true}))
    user := sdk.AccAddress([]byte("user_issue_m_idem__________")).String()

    // First issue
    resp1, err := msgServer.IssuePolicyTicket(sdk.WrapSDKContext(ctx), &types.MsgIssuePolicyTicket{
        Creator:         admin.String(),
        ContractAddress: contract.String(),
        UserAddress:     user,
        Method:          "increment",
    })
    require.NoError(t, err)
    require.True(t, resp1.Created)
    require.NotNil(t, resp1.Ticket)

    // Second issue with same tuple should now be rejected (conflict)
    ctx = ctx.WithEventManager(sdk.NewEventManager())
    resp2, err := msgServer.IssuePolicyTicket(sdk.WrapSDKContext(ctx), &types.MsgIssuePolicyTicket{
        Creator:         admin.String(),
        ContractAddress: contract.String(),
        UserAddress:     user,
        Method:          "increment",
    })
    require.Error(t, err)
    require.Nil(t, resp2)
    require.Contains(t, err.Error(), "active policy ticket already exists")
    // Event captured
    hasConflict := false
    for _, ev := range ctx.EventManager().Events() {
        if ev.Type == types.EventTypePolicyTicketIssueConflict { hasConflict = true; break }
    }
    require.True(t, hasConflict)
}

func TestIssuePolicyTicket_TtlUsesOverride(t *testing.T) {
    keeper, ctx, msgServer, mockWasmKeeper, _ := setupMsgServerEnv(t)
    // Global default 3, cap 5
    p := types.DefaultParams()
    p.PolicyTicketTtlBlocks = 3
    // removed ttl max param
    require.NoError(t, keeper.SetParams(ctx, p))

    contract := sdk.AccAddress([]byte("contract_ttl_cap________")).String()
    admin := sdk.AccAddress([]byte("admin_ttl_cap___________")).String()
    user := sdk.AccAddress([]byte("user_ttl_cap____________")).String()
    mockWasmKeeper.SetContractInfo(contract, admin)
    require.NoError(t, keeper.SetSponsor(ctx, types.ContractSponsor{ContractAddress: contract, IsSponsored: true}))

    h := uint64(ctx.BlockHeight())
    resp, err := msgServer.IssuePolicyTicket(sdk.WrapSDKContext(ctx), &types.MsgIssuePolicyTicket{
        Creator:         admin,
        ContractAddress: contract,
        UserAddress:     user,
        Method:          "ping",
        Uses:            1,
        TtlBlocks:       10,
    })
    require.NoError(t, err)
    // Expect TTL equals override (10)
    require.Equal(t, h+10, resp.Ticket.ExpiryHeight)
}

func TestIssuePolicyTicket_TtlOverrideZeroUsesGlobal(t *testing.T) {
    keeper, ctx, msgServer, mockWasmKeeper, _ := setupMsgServerEnv(t)
    // Global default 4, overrides disabled (cap=0)
    p := types.DefaultParams()
    p.PolicyTicketTtlBlocks = 4
    // removed ttl max param
    require.NoError(t, keeper.SetParams(ctx, p))

    contract := sdk.AccAddress([]byte("contract_ttl_disabled___")).String()
    admin := sdk.AccAddress([]byte("admin_ttl_disabled_____ ")).String()
    user := sdk.AccAddress([]byte("user_ttl_disabled______ ")).String()
    mockWasmKeeper.SetContractInfo(contract, admin)
    require.NoError(t, keeper.SetSponsor(ctx, types.ContractSponsor{ContractAddress: contract, IsSponsored: true}))

    h := uint64(ctx.BlockHeight())
    resp, err := msgServer.IssuePolicyTicket(sdk.WrapSDKContext(ctx), &types.MsgIssuePolicyTicket{
        Creator:         admin,
        ContractAddress: contract,
        UserAddress:     user,
        Method:          "ping",
        Uses:            1,
    })
    require.NoError(t, err)
    // Expect TTL = global default 4
    require.Equal(t, h+4, resp.Ticket.ExpiryHeight)
}

func TestIssuePolicyTicket_DefaultUsesRemainingOne(t *testing.T) {
    keeper, ctx, msgServer, mockWasmKeeper, _ := setupMsgServerEnv(t)
    p := types.DefaultParams()
    require.NoError(t, keeper.SetParams(ctx, p))
    contract := sdk.AccAddress([]byte("contract_issue_policy___")).String()
    admin := sdk.AccAddress([]byte("admin_issue_policy______")).String()
    user := sdk.AccAddress([]byte("user_issue_policy_______")).String()
    mockWasmKeeper.SetContractInfo(contract, admin)
    require.NoError(t, keeper.SetSponsor(ctx, types.ContractSponsor{ContractAddress: contract, IsSponsored: true}))

    resp, err := msgServer.IssuePolicyTicket(sdk.WrapSDKContext(ctx), &types.MsgIssuePolicyTicket{
        Creator:         admin,
        ContractAddress: contract,
        UserAddress:     user,
        Method:          "noop",
    })
    require.NoError(t, err)
    require.True(t, resp.Created)
    require.NotNil(t, resp.Ticket)
    require.Equal(t, uint32(1), resp.Ticket.UsesRemaining)
}

// ProbeSponsorship tests removed

func TestIssuePolicyTicket_AlreadyHaveTicketConsistent(t *testing.T) {
    keeper, ctx, msgServer, mockWasmKeeper, _ := setupMsgServerEnv(t)
    p := types.DefaultParams()
    p.MaxMethodTicketUsesPerIssue = 5
    require.NoError(t, keeper.SetParams(ctx, p))

    contract := sdk.AccAddress([]byte("contract_already_method__")).String()
    admin := sdk.AccAddress([]byte("admin_already_method____")).String()
    user := sdk.AccAddress([]byte("user_already_method_____ ")).String()
    mockWasmKeeper.SetContractInfo(contract, admin)
    require.NoError(t, keeper.SetSponsor(ctx, types.ContractSponsor{ContractAddress: contract, IsSponsored: true}))

    r1, err := msgServer.IssuePolicyTicket(sdk.WrapSDKContext(ctx), &types.MsgIssuePolicyTicket{
        Creator:         admin,
        ContractAddress: contract,
        UserAddress:     user,
        Method:          "go",
        Uses:            3,
    })
    require.NoError(t, err)
    require.True(t, r1.Created)

    // Reset event manager to capture conflict event cleanly
    ctx = ctx.WithEventManager(sdk.NewEventManager())
    r2, err := msgServer.IssuePolicyTicket(sdk.WrapSDKContext(ctx), &types.MsgIssuePolicyTicket{
        Creator:         admin,
        ContractAddress: contract,
        UserAddress:     user,
        Method:          "go",
        Uses:            4,
    })
    require.Error(t, err)
    require.Nil(t, r2)
    require.Contains(t, err.Error(), "active policy ticket already exists")

    // Verify a conflict event was emitted with ticket info
    evs := ctx.EventManager().Events()
    found := false
    for _, ev := range evs {
        if ev.Type == types.EventTypePolicyTicketIssueConflict {
            found = true
            // Minimal attribute sanity checks
            // contract_address, user, digest should be present
            hasContract := false
            hasUser := false
            hasDigest := false
            for _, a := range ev.Attributes {
                switch string(a.Key) {
                case types.AttributeKeyContractAddress:
                    hasContract = true
                case types.AttributeKeyUser:
                    hasUser = true
                case types.AttributeKeyDigest:
                    hasDigest = true
                }
            }
            require.True(t, hasContract)
            require.True(t, hasUser)
            require.True(t, hasDigest)
            break
        }
    }
    require.True(t, found, "expected policy_ticket_issue_conflict event")
}

// Negative probe cache should be cleared when sponsor settings change for the contract
// Removed negative probe cache tests

// All negative probe caches should be cleared on parameter updates
// Removed negative probe cache tests

// Disabling sponsorship retains stored max_grant_per_user but it becomes unusable (read path errors)
func TestUpdateSponsor_DisableRetainsGrantButUnused(t *testing.T) {
    keeper, ctx, msgServer, mockWasmKeeper, _ := setupMsgServerEnv(t)
    // identities
    admin := sdk.AccAddress([]byte("admin_disable_keep_____ ")).String()
    contract := sdk.AccAddress([]byte("contract_disable_keep___")).String()
    mockWasmKeeper.SetContractInfo(contract, admin)

    // initial enabled sponsor with grant
    grant := []*sdk.Coin{{Denom: "peaka", Amount: sdk.NewInt(100)}}
    require.NoError(t, keeper.SetSponsor(ctx, types.ContractSponsor{ContractAddress: contract, IsSponsored: true, CreatorAddress: admin, MaxGrantPerUser: grant}))

    // disable sponsorship without touching grant
    _, err := msgServer.UpdateSponsor(sdk.WrapSDKContext(ctx), &types.MsgUpdateSponsor{Creator: admin, ContractAddress: contract, IsSponsored: false})
    require.NoError(t, err)

    // state should still have grant stored
    stored, ok := keeper.GetSponsor(ctx, contract)
    require.True(t, ok)
    require.Len(t, stored.MaxGrantPerUser, 1)

    // GetMaxGrantPerUser should error because sponsorship is disabled
    _, err = keeper.GetMaxGrantPerUser(ctx, contract)
    require.Error(t, err)
    require.Contains(t, err.Error(), "sponsorship is disabled")
}

// Enabling sponsorship while omitting grant should reuse existing grant and succeed
func TestUpdateSponsor_EnableUsesExistingGrantWhenOmitted(t *testing.T) {
    keeper, ctx, msgServer, mockWasmKeeper, _ := setupMsgServerEnv(t)
    admin := sdk.AccAddress([]byte("admin_enable_reuse____ ")).String()
    contract := sdk.AccAddress([]byte("contract_enable_reuse__")).String()
    mockWasmKeeper.SetContractInfo(contract, admin)

    // initial enabled sponsor with grant
    grant := []*sdk.Coin{{Denom: "peaka", Amount: sdk.NewInt(200)}}
    require.NoError(t, keeper.SetSponsor(ctx, types.ContractSponsor{ContractAddress: contract, IsSponsored: true, CreatorAddress: admin, MaxGrantPerUser: grant}))

    // partial update: keep enabled and omit grant -> should preserve previous grant
    _, err := msgServer.UpdateSponsor(sdk.WrapSDKContext(ctx), &types.MsgUpdateSponsor{Creator: admin, ContractAddress: contract, IsSponsored: true})
    require.NoError(t, err)

    // Verify grant unchanged
    max, err := keeper.GetMaxGrantPerUser(ctx, contract)
    require.NoError(t, err)
    require.Len(t, max, 1)
    require.Equal(t, "peaka", max[0].Denom)
    require.Equal(t, sdk.NewInt(200), max[0].Amount)
}

func TestGarbageCollect_ExpiredTicketReissue(t *testing.T) {
    keeper, ctx, msgServer, mockWasmKeeper, _ := setupMsgServerEnv(t)
    p := types.DefaultParams()
    p.MaxMethodTicketUsesPerIssue = 3
    require.NoError(t, keeper.SetParams(ctx, p))

    contract := sdk.AccAddress([]byte("contract_gc_reissue_____ ")).String()
    admin := sdk.AccAddress([]byte("admin_gc_reissue________ ")).String()
    user := sdk.AccAddress([]byte("user_gc_reissue_________ ")).String()
    mockWasmKeeper.SetContractInfo(contract, admin)
    require.NoError(t, keeper.SetSponsor(ctx, types.ContractSponsor{ContractAddress: contract, IsSponsored: true}))

    r1, err := msgServer.IssuePolicyTicket(sdk.WrapSDKContext(ctx), &types.MsgIssuePolicyTicket{
        Creator:         admin,
        ContractAddress: contract,
        UserAddress:     user,
        Method:          "go",
        Uses:            2,
        TtlBlocks:       1,
    })
    require.NoError(t, err)
    digest := r1.Ticket.Digest

    // Advance beyond TTL and GC
    ctx = ctx.WithBlockHeight(ctx.BlockHeight() + 2)
    keeper.GarbageCollectByExpiry(ctx, 10)
    _, found := keeper.GetPolicyTicket(ctx, contract, user, digest)
    require.False(t, found)

    // Reissue should be Created=true
    r2, err := msgServer.IssuePolicyTicket(sdk.WrapSDKContext(ctx), &types.MsgIssuePolicyTicket{
        Creator:         admin,
        ContractAddress: contract,
        UserAddress:     user,
        Method:          "go",
        Uses:            2,
    })
    require.NoError(t, err)
    require.True(t, r2.Created)
    require.Equal(t, uint32(2), r2.Ticket.UsesRemaining)
}

func TestRevokePolicyTicket_ReissueCreatesNew(t *testing.T) {
    keeper, ctx, msgServer, mockWasmKeeper, _ := setupMsgServerEnv(t)
    p := types.DefaultParams()
    p.MaxMethodTicketUsesPerIssue = 5
    require.NoError(t, keeper.SetParams(ctx, p))

    contract := sdk.AccAddress([]byte("contract_revoke_reissue__")).String()
    admin := sdk.AccAddress([]byte("admin_revoke_reissue____")).String()
    user := sdk.AccAddress([]byte("user_revoke_reissue_____ ")).String()
    mockWasmKeeper.SetContractInfo(contract, admin)
    require.NoError(t, keeper.SetSponsor(ctx, types.ContractSponsor{ContractAddress: contract, IsSponsored: true}))

    r1, err := msgServer.IssuePolicyTicket(sdk.WrapSDKContext(ctx), &types.MsgIssuePolicyTicket{
        Creator:         admin,
        ContractAddress: contract,
        UserAddress:     user,
        Method:          "go",
        Uses:            4,
    })
    require.NoError(t, err)
    digest := r1.Ticket.Digest

    // Revoke
    _, err = msgServer.RevokePolicyTicket(sdk.WrapSDKContext(ctx), &types.MsgRevokePolicyTicket{
        Creator:         admin,
        ContractAddress: contract,
        UserAddress:     user,
        Digest:          digest,
    })
    require.NoError(t, err)
    _, found := keeper.GetPolicyTicket(ctx, contract, user, digest)
    require.False(t, found)

    // Reissue -> Created=true and uses reset (clamped if needed)
    r2, err := msgServer.IssuePolicyTicket(sdk.WrapSDKContext(ctx), &types.MsgIssuePolicyTicket{
        Creator:         admin,
        ContractAddress: contract,
        UserAddress:     user,
        Method:          "go",
        Uses:            2,
    })
    require.NoError(t, err)
    require.True(t, r2.Created)
    require.Equal(t, uint32(2), r2.Ticket.UsesRemaining)
}

func TestRevokePolicyTicket_PartiallyUsedMultiUse(t *testing.T) {
    keeper, ctx, msgServer, mockWasmKeeper, _ := setupMsgServerEnv(t)
    p := types.DefaultParams()
    p.MaxMethodTicketUsesPerIssue = 5
    require.NoError(t, keeper.SetParams(ctx, p))

    contract := sdk.AccAddress([]byte("contract_revoke_multi____")).String()
    admin := sdk.AccAddress([]byte("admin_revoke_multi______")).String()
    user := sdk.AccAddress([]byte("user_revoke_multi_______")).String()
    mockWasmKeeper.SetContractInfo(contract, admin)
    require.NoError(t, keeper.SetSponsor(ctx, types.ContractSponsor{ContractAddress: contract, IsSponsored: true}))

    // Issue method ticket with uses=3
    resp, err := msgServer.IssuePolicyTicket(sdk.WrapSDKContext(ctx), &types.MsgIssuePolicyTicket{
        Creator:         admin,
        ContractAddress: contract,
        UserAddress:     user,
        Method:          "run",
        Uses:            3,
    })
    require.NoError(t, err)
    digest := resp.Ticket.Digest

    // Consume once (remaining=2)
    require.NoError(t, keeper.ConsumePolicyTicket(ctx, contract, user, digest))
    tkt, ok := keeper.GetPolicyTicket(ctx, contract, user, digest)
    require.True(t, ok)
    require.False(t, tkt.Consumed)
    require.Equal(t, uint32(2), tkt.UsesRemaining)

    // Revoke (should succeed because not consumed)
    _, err = msgServer.RevokePolicyTicket(sdk.WrapSDKContext(ctx), &types.MsgRevokePolicyTicket{
        Creator:         admin,
        ContractAddress: contract,
        UserAddress:     user,
        Digest:          digest,
    })
    require.NoError(t, err)

    // Ticket removed
    _, found := keeper.GetPolicyTicket(ctx, contract, user, digest)
    require.False(t, found)
}

func TestIssuePolicyTicket_ClampToParamUpperBound(t *testing.T) {
    keeper, ctx, msgServer, mockWasmKeeper, _ := setupMsgServerEnv(t)
    // Cap at 100
    p := types.DefaultParams()
    p.MaxMethodTicketUsesPerIssue = 100
    require.NoError(t, keeper.SetParams(ctx, p))

    contract := sdk.AccAddress([]byte("contract_issue_uppercap__")).String()
    admin := sdk.AccAddress([]byte("admin_issue_uppercap____")).String()
    user := sdk.AccAddress([]byte("user_issue_uppercap_____")).String()
    mockWasmKeeper.SetContractInfo(contract, admin)
    require.NoError(t, keeper.SetSponsor(ctx, types.ContractSponsor{ContractAddress: contract, IsSponsored: true}))

    resp, err := msgServer.IssuePolicyTicket(sdk.WrapSDKContext(ctx), &types.MsgIssuePolicyTicket{
        Creator:         admin,
        ContractAddress: contract,
        UserAddress:     user,
        Method:          "op",
        Uses:            1000,
    })
    require.NoError(t, err)
    require.True(t, resp.Created)
    require.Equal(t, uint32(100), resp.Ticket.UsesRemaining)
}

func TestIssuePolicyTicket_ParamZeroFallbackTreatsAsOne(t *testing.T) {
    keeper, ctx, msgServer, mockWasmKeeper, _ := setupMsgServerEnv(t)
    // Force an invalid param using direct SetParams (bypassing governance validation)
    p := types.DefaultParams()
    p.MaxMethodTicketUsesPerIssue = 0
    require.NoError(t, keeper.SetParams(ctx, p))

    contract := sdk.AccAddress([]byte("contract_issue_fallback__")).String()
    admin := sdk.AccAddress([]byte("admin_issue_fallback____")).String()
    user := sdk.AccAddress([]byte("user_issue_fallback_____")).String()
    mockWasmKeeper.SetContractInfo(contract, admin)
    require.NoError(t, keeper.SetSponsor(ctx, types.ContractSponsor{ContractAddress: contract, IsSponsored: true}))

    resp, err := msgServer.IssuePolicyTicket(sdk.WrapSDKContext(ctx), &types.MsgIssuePolicyTicket{
        Creator:         admin,
        ContractAddress: contract,
        UserAddress:     user,
        Method:          "op",
        Uses:            10,
    })
    require.NoError(t, err)
    // Fallback path treats maxPerIssue==0 as 1
    require.Equal(t, uint32(1), resp.Ticket.UsesRemaining)
}

func TestIssuePolicyTicket_ConsumedThenReissueCreatesNew(t *testing.T) {
    keeper, ctx, msgServer, mockWasmKeeper, _ := setupMsgServerEnv(t)
    p := types.DefaultParams()
    p.MaxMethodTicketUsesPerIssue = 2
    require.NoError(t, keeper.SetParams(ctx, p))

    contract := sdk.AccAddress([]byte("contract_issue_reissue___")).String()
    admin := sdk.AccAddress([]byte("admin_issue_reissue_____")).String()
    user := sdk.AccAddress([]byte("user_issue_reissue______")).String()
    mockWasmKeeper.SetContractInfo(contract, admin)
    require.NoError(t, keeper.SetSponsor(ctx, types.ContractSponsor{ContractAddress: contract, IsSponsored: true}))

    // First issue uses=2
    resp, err := msgServer.IssuePolicyTicket(sdk.WrapSDKContext(ctx), &types.MsgIssuePolicyTicket{
        Creator:         admin,
        ContractAddress: contract,
        UserAddress:     user,
        Method:          "go",
        Uses:            2,
    })
    require.NoError(t, err)
    require.True(t, resp.Created)
    digest := resp.Ticket.Digest

    // Consume twice to exhaust
    require.NoError(t, keeper.ConsumePolicyTicket(ctx, contract, user, digest))
    require.NoError(t, keeper.ConsumePolicyTicket(ctx, contract, user, digest))
    tkt, ok := keeper.GetPolicyTicket(ctx, contract, user, digest)
    require.True(t, ok)
    require.True(t, tkt.Consumed)
    require.Equal(t, uint32(0), tkt.UsesRemaining)

    // Re-issue with same tuple should create a fresh ticket
    resp2, err := msgServer.IssuePolicyTicket(sdk.WrapSDKContext(ctx), &types.MsgIssuePolicyTicket{
        Creator:         admin,
        ContractAddress: contract,
        UserAddress:     user,
        Method:          "go",
        Uses:            2,
    })
    require.NoError(t, err)
    require.True(t, resp2.Created)
    // Same digest key overwritten with fresh ticket
    require.Equal(t, digest, resp2.Ticket.Digest)
    require.False(t, resp2.Ticket.Consumed)
    require.Equal(t, uint32(2), resp2.Ticket.UsesRemaining)
}

func TestIssuePolicyTicket_ExpiredThenReissueCreatesNew(t *testing.T) {
    keeper, ctx, msgServer, mockWasmKeeper, _ := setupMsgServerEnv(t)
    p := types.DefaultParams()
    p.MaxMethodTicketUsesPerIssue = 3
    // Allow overrides: default cap 120 is fine
    require.NoError(t, keeper.SetParams(ctx, p))

    contract := sdk.AccAddress([]byte("contract_issue_expire____")).String()
    admin := sdk.AccAddress([]byte("admin_issue_expire______")).String()
    user := sdk.AccAddress([]byte("user_issue_expire_______")).String()
    mockWasmKeeper.SetContractInfo(contract, admin)
    // Sponsor with TTL override = 1
    require.NoError(t, keeper.SetSponsor(ctx, types.ContractSponsor{ContractAddress: contract, IsSponsored: true}))

    resp, err := msgServer.IssuePolicyTicket(sdk.WrapSDKContext(ctx), &types.MsgIssuePolicyTicket{
        Creator:         admin,
        ContractAddress: contract,
        UserAddress:     user,
        Method:          "ping",
        Uses:            3,
        TtlBlocks:       1,
    })
    require.NoError(t, err)
    require.True(t, resp.Created)
    digest := resp.Ticket.Digest

    // Advance height beyond TTL
    ctx = ctx.WithBlockHeight(ctx.BlockHeight() + 2)

    resp2, err := msgServer.IssuePolicyTicket(sdk.WrapSDKContext(ctx), &types.MsgIssuePolicyTicket{
        Creator:         admin,
        ContractAddress: contract,
        UserAddress:     user,
        Method:          "ping",
        Uses:            2,
    })
    require.NoError(t, err)
    require.True(t, resp2.Created)
    // Same digest reused; ticket refreshed
    require.Equal(t, digest, resp2.Ticket.Digest)
    require.False(t, resp2.Ticket.Consumed)
}

// multi-method issuance no longer supported at proto level (single method only)

// Capacity: max tickets per user per contract enforced
// Capacity limits removed: whitelist-based issuance provides sufficient control.


func TestConsumePolicyTicket_IdempotentAfterConsumed(t *testing.T) {
    keeper, ctx, msgServer, mockWasmKeeper, _ := setupMsgServerEnv(t)
    _ = msgServer; _ = mockWasmKeeper
    p := types.DefaultParams()
    p.MaxMethodTicketUsesPerIssue = 1
    require.NoError(t, keeper.SetParams(ctx, p))

    contract := sdk.AccAddress([]byte("contract_consume_idem___")).String()
    admin := sdk.AccAddress([]byte("admin_consume_idem______")).String()
    user := sdk.AccAddress([]byte("user_consume_idem_______")).String()
    mockWasmKeeper.SetContractInfo(contract, admin)
    require.NoError(t, keeper.SetSponsor(ctx, types.ContractSponsor{ContractAddress: contract, IsSponsored: true}))

    resp, err := msgServer.IssuePolicyTicket(sdk.WrapSDKContext(ctx), &types.MsgIssuePolicyTicket{
        Creator:         admin,
        ContractAddress: contract,
        UserAddress:     user,
        Method:          "do",
        Uses:            5, // clamped to 1 due to param
    })
    require.NoError(t, err)
    require.Equal(t, uint32(1), resp.Ticket.UsesRemaining)

    // First consume -> consumed
    require.NoError(t, keeper.ConsumePolicyTicket(ctx, contract, user, resp.Ticket.Digest))
    tkt, ok := keeper.GetPolicyTicket(ctx, contract, user, resp.Ticket.Digest)
    require.True(t, ok)
    require.True(t, tkt.Consumed)
    require.Equal(t, uint32(0), tkt.UsesRemaining)

    // Second consume -> no-op
    require.NoError(t, keeper.ConsumePolicyTicket(ctx, contract, user, resp.Ticket.Digest))
    tkt2, ok := keeper.GetPolicyTicket(ctx, contract, user, resp.Ticket.Digest)
    require.True(t, ok)
    require.True(t, tkt2.Consumed)
    require.Equal(t, uint32(0), tkt2.UsesRemaining)
}
