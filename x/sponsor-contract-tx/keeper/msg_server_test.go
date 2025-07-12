package keeper

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	sdk "github.com/cosmos/cosmos-sdk/types"

	"github.com/DoraFactory/doravota/x/sponsor-contract-tx/types"
)

func TestMsgServer_SetSponsor(t *testing.T) {
	keeper, ctx := setupKeeper(t)
	server := NewMsgServerImpl(keeper)

	msg := &types.MsgSetSponsor{
		Creator:          "dora1signer123",
		ContractAddress: "dora1contract123",
		IsSponsored:     true,
	}

	resp, err := server.SetSponsor(sdk.WrapSDKContext(ctx), msg)
	require.NoError(t, err)
	require.NotNil(t, resp)

	// Verify the sponsor was set
	sponsor, found := keeper.GetSponsor(ctx, "dora1contract123")
	require.True(t, found)
	assert.Equal(t, "dora1contract123", sponsor.ContractAddress)
	assert.True(t, sponsor.IsSponsored)
}

func TestMsgServer_UpdateSponsor(t *testing.T) {
	keeper, ctx := setupKeeper(t)
	server := NewMsgServerImpl(keeper)

	// First set a sponsor
	sponsor := types.ContractSponsor{
		ContractAddress: "dora1contract123",
		IsSponsored:     true,
	}
	keeper.SetSponsor(ctx, sponsor)

	// Update the sponsor
	msg := &types.MsgUpdateSponsor{
		Creator:          "dora1signer123",
		ContractAddress: "dora1contract123",
		IsSponsored:     false,
	}

	resp, err := server.UpdateSponsor(sdk.WrapSDKContext(ctx), msg)
	require.NoError(t, err)
	require.NotNil(t, resp)

	// Verify the sponsor was updated
	updatedSponsor, found := keeper.GetSponsor(ctx, "dora1contract123")
	require.True(t, found)
	assert.Equal(t, "dora1contract123", updatedSponsor.ContractAddress)
	assert.False(t, updatedSponsor.IsSponsored)
}

func TestMsgServer_DeleteSponsor(t *testing.T) {
	keeper, ctx := setupKeeper(t)
	server := NewMsgServerImpl(keeper)

	// First set a sponsor
	sponsor := types.ContractSponsor{
		ContractAddress: "dora1contract123",
		IsSponsored:     true,
	}
	keeper.SetSponsor(ctx, sponsor)

	// Delete the sponsor
	msg := &types.MsgDeleteSponsor{
		Creator:          "dora1signer123",
		ContractAddress: "dora1contract123",
	}

	resp, err := server.DeleteSponsor(sdk.WrapSDKContext(ctx), msg)
	require.NoError(t, err)
	require.NotNil(t, resp)

	// Verify the sponsor was deleted
	_, found := keeper.GetSponsor(ctx, "dora1contract123")
	require.False(t, found)
}

func TestMsgServerEventEmission(t *testing.T) {
	keeper, ctx := setupKeeper(t)
	msgServer := NewMsgServerImpl(keeper)

	// Create event manager for testing
	eventManager := sdk.NewEventManager()
	ctx = ctx.WithEventManager(eventManager)

	// Test SetSponsor event
	msg := &types.MsgSetSponsor{
		Creator:          "dora1signer123",
		ContractAddress: "dora1contract123",
		IsSponsored:     true,
	}

	res, err := msgServer.SetSponsor(sdk.WrapSDKContext(ctx), msg)
	require.NoError(t, err)
	require.NotNil(t, res)

	// Verify event was emitted
	events := eventManager.Events()
	require.Len(t, events, 1)
	event := events[0]
	assert.Equal(t, "set_sponsor", event.Type)

	// Check event attributes
	attributes := event.Attributes
	require.Len(t, attributes, 3)
	assert.Equal(t, "creator", string(attributes[0].Key))
	assert.Equal(t, "dora1signer123", string(attributes[0].Value))
	assert.Equal(t, "contract_address", string(attributes[1].Key))
	assert.Equal(t, "dora1contract123", string(attributes[1].Value))
	assert.Equal(t, "is_sponsored", string(attributes[2].Key))
	assert.Equal(t, "true", string(attributes[2].Value))
}

func TestMsgServerUpdateEventEmission(t *testing.T) {
	keeper, ctx := setupKeeper(t)
	msgServer := NewMsgServerImpl(keeper)

	// First set a sponsor
	contractAddr := "dora1contract123"
	sponsor := types.ContractSponsor{
		ContractAddress: contractAddr,
		IsSponsored:     true,
	}
	keeper.SetSponsor(ctx, sponsor)

	// Create event manager for testing
	eventManager := sdk.NewEventManager()
	ctx = ctx.WithEventManager(eventManager)

	// Test UpdateSponsor event
	msg := &types.MsgUpdateSponsor{
		Creator:          "dora1signer123",
		ContractAddress: contractAddr,
		IsSponsored:     false,
	}

	res, err := msgServer.UpdateSponsor(sdk.WrapSDKContext(ctx), msg)
	require.NoError(t, err)
	require.NotNil(t, res)

	// Verify event was emitted
	events := eventManager.Events()
	require.Len(t, events, 1)
	event := events[0]
	assert.Equal(t, "update_sponsor", event.Type)

	// Check event attributes
	attributes := event.Attributes
	require.Len(t, attributes, 3)
	assert.Equal(t, "creator", string(attributes[0].Key))
	assert.Equal(t, "dora1signer123", string(attributes[0].Value))
	assert.Equal(t, "contract_address", string(attributes[1].Key))
	assert.Equal(t, contractAddr, string(attributes[1].Value))
	assert.Equal(t, "is_sponsored", string(attributes[2].Key))
	assert.Equal(t, "false", string(attributes[2].Value))
}

func TestMsgServerDeleteEventEmission(t *testing.T) {
	keeper, ctx := setupKeeper(t)
	msgServer := NewMsgServerImpl(keeper)

	// First set a sponsor
	contractAddr := "dora1contract123"
	sponsor := types.ContractSponsor{
		ContractAddress: contractAddr,
		IsSponsored:     true,
	}
	keeper.SetSponsor(ctx, sponsor)

	// Create event manager for testing
	eventManager := sdk.NewEventManager()
	ctx = ctx.WithEventManager(eventManager)

	// Test DeleteSponsor event
	msg := &types.MsgDeleteSponsor{
		Creator:          "dora1signer123",
		ContractAddress: contractAddr,
	}

	res, err := msgServer.DeleteSponsor(sdk.WrapSDKContext(ctx), msg)
	require.NoError(t, err)
	require.NotNil(t, res)

	// Verify event was emitted
	events := eventManager.Events()
	require.Len(t, events, 1)
	event := events[0]
	assert.Equal(t, "delete_sponsor", event.Type)

	// Check event attributes
	attributes := event.Attributes
	require.Len(t, attributes, 2)
	assert.Equal(t, "creator", string(attributes[0].Key))
	assert.Equal(t, "dora1signer123", string(attributes[0].Value))
	assert.Equal(t, "contract_address", string(attributes[1].Key))
	assert.Equal(t, contractAddr, string(attributes[1].Value))
}

func TestMsgServerWorkflow(t *testing.T) {
	keeper, ctx := setupKeeper(t)
	msgServer := NewMsgServerImpl(keeper)

	contractAddr := "dora1contract123"
	signer := "dora1signer123"

	// 1. Set sponsor
	setMsg := &types.MsgSetSponsor{
		Creator:          signer,
		ContractAddress: contractAddr,
		IsSponsored:     true,
	}

	res, err := msgServer.SetSponsor(sdk.WrapSDKContext(ctx), setMsg)
	require.NoError(t, err)
	require.NotNil(t, res)

	// Verify sponsor is set and sponsored
	assert.True(t, keeper.IsSponsored(ctx, contractAddr))

	// Verify sponsor is set correctly
	sponsor, found := keeper.GetSponsor(ctx, contractAddr)
	require.True(t, found)
	assert.Equal(t, contractAddr, sponsor.ContractAddress)

	// 2. Update sponsor to not sponsored
	updateMsg := &types.MsgUpdateSponsor{
		Creator:          signer,
		ContractAddress: contractAddr,
		IsSponsored:     false,
	}

	updateRes, err := msgServer.UpdateSponsor(sdk.WrapSDKContext(ctx), updateMsg)
	require.NoError(t, err)
	require.NotNil(t, updateRes)

	// Verify sponsor is not sponsored
	assert.False(t, keeper.IsSponsored(ctx, contractAddr))

	// 3. Update sponsor back to sponsored
	updateMsg2 := &types.MsgUpdateSponsor{
		Creator:          signer,
		ContractAddress: contractAddr,
		IsSponsored:     true,
	}

	updateRes2, err := msgServer.UpdateSponsor(sdk.WrapSDKContext(ctx), updateMsg2)
	require.NoError(t, err)
	require.NotNil(t, updateRes2)

	// Verify sponsor is sponsored again
	assert.True(t, keeper.IsSponsored(ctx, contractAddr))

	// 4. Delete sponsor
	deleteMsg := &types.MsgDeleteSponsor{
		Creator:          signer,
		ContractAddress: contractAddr,
	}

	deleteRes, err := msgServer.DeleteSponsor(sdk.WrapSDKContext(ctx), deleteMsg)
	require.NoError(t, err)
	require.NotNil(t, deleteRes)

	// Verify sponsor is deleted
	assert.False(t, keeper.HasSponsor(ctx, contractAddr))
	assert.False(t, keeper.IsSponsored(ctx, contractAddr))
}

func TestMsgServerMultipleSponsors(t *testing.T) {
	keeper, ctx := setupKeeper(t)
	msgServer := NewMsgServerImpl(keeper)

	signer := "dora1signer123"
	contracts := []string{"dora1contract1", "dora1contract2", "dora1contract3"}

	// Set multiple sponsors
	for i, contractAddr := range contracts {
		msg := &types.MsgSetSponsor{
			Creator:          signer,
			ContractAddress: contractAddr,
			IsSponsored:     i%2 == 0, // alternate between true and false
		}

		res, err := msgServer.SetSponsor(sdk.WrapSDKContext(ctx), msg)
		require.NoError(t, err)
		require.NotNil(t, res)
	}

	// Verify all sponsors are set correctly
	allSponsors := keeper.GetAllSponsors(ctx)
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

	// Update one sponsor
	updateMsg := &types.MsgUpdateSponsor{
		Creator:          signer,
		ContractAddress: contracts[1],
		IsSponsored:     true,
	}

	res, err := msgServer.UpdateSponsor(sdk.WrapSDKContext(ctx), updateMsg)
	require.NoError(t, err)
	require.NotNil(t, res)

	// Verify the update
	assert.True(t, keeper.IsSponsored(ctx, contracts[1]))

	// Delete one sponsor
	deleteMsg := &types.MsgDeleteSponsor{
		Creator:          signer,
		ContractAddress: contracts[0],
	}

	deleteRes, err := msgServer.DeleteSponsor(sdk.WrapSDKContext(ctx), deleteMsg)
	require.NoError(t, err)
	require.NotNil(t, deleteRes)

	// Verify the deletion
	assert.False(t, keeper.HasSponsor(ctx, contracts[0]))
	assert.False(t, keeper.IsSponsored(ctx, contracts[0]))

	// Check final state
	allSponsors = keeper.GetAllSponsors(ctx)
	require.Len(t, allSponsors, 2)
}
