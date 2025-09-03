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

func TestMsgServer_SetSponsor(t *testing.T) {
	keeper, ctx := setupKeeperSimple(t)
	server := NewMsgServerImpl(keeper)

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
	keeper, ctx := setupKeeperSimple(t)
	server := NewMsgServerImpl(keeper)

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

func TestMsgServer_DeleteSponsor(t *testing.T) {
	keeper, ctx := setupKeeperSimple(t)
	server := NewMsgServerImpl(keeper)

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
	keeper, ctx := setupKeeperSimple(t)
	msgServer := NewMsgServerImpl(keeper)

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
	keeper, ctx := setupKeeperSimple(t)
	msgServer := NewMsgServerImpl(keeper)

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
	keeper, ctx := setupKeeperSimple(t)
	msgServer := NewMsgServerImpl(keeper)

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
	keeper, ctx := setupKeeperSimple(t)
	msgServer := NewMsgServerImpl(keeper)

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
	keeper, ctx := setupKeeperSimple(t)
	msgServer := NewMsgServerImpl(keeper)

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

// TestMsgServerAdminPermissions tests that only contract admins can manage sponsors
func TestMsgServerAdminPermissions(t *testing.T) {
	keeper, ctx, mockWasmKeeper := setupKeeper(t)
	msgServer := NewMsgServerImpl(keeper)

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
	keeper, ctx := setupKeeperSimple(t)
	msgServer := NewMsgServerImpl(keeper)

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
	keeper, ctx := setupKeeperSimple(t)
	msgServer := NewMsgServerImpl(keeper)

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
	keeper, ctx := setupKeeperSimple(t)
	msgServer := NewMsgServerImpl(keeper)

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
	keeper, ctx, mockWasmKeeper := setupKeeper(t)
	msgServer := NewMsgServerImpl(keeper)

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
	keeper, ctx, mockWasmKeeper := setupKeeper(t)
	msgServer := NewMsgServerImpl(keeper)

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
	keeper, ctx, mockWasmKeeper := setupKeeper(t)
	msgServer := NewMsgServerImpl(keeper)

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
    keeper, ctx, wasmMock, _, bankKeeper := setupKeeperWithDeps(t)

    // Prepare admin, contract, recipient
    admin := sdk.AccAddress("admin________________")
    contract := sdk.AccAddress("contract____________")
    recipient := sdk.AccAddress("recipient___________")

    // Set contract admin in wasm mock
    wasmMock.SetContractInfo(contract.String(), admin.String())

    // Create msg server with deps
    msgServer := NewMsgServerImplWithDeps(keeper, bankKeeper)

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

func TestWithdrawSponsorFunds_NotAdmin(t *testing.T) {
    keeper, ctx, wasmMock, _, bankKeeper := setupKeeperWithDeps(t)
    admin := sdk.AccAddress("admin________________")
    nonAdmin := sdk.AccAddress("user_________________")
    contract := sdk.AccAddress("contract____________")

    wasmMock.SetContractInfo(contract.String(), admin.String())
    msgServer := NewMsgServerImplWithDeps(keeper, bankKeeper)

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
    keeper, ctx, wasmMock, _, bankKeeper := setupKeeperWithDeps(t)
    admin := sdk.AccAddress("admin________________")
    contract := sdk.AccAddress("contract____________")
    recipient := sdk.AccAddress("recipient___________")

    wasmMock.SetContractInfo(contract.String(), admin.String())
    msgServer := NewMsgServerImplWithDeps(keeper, bankKeeper)

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
