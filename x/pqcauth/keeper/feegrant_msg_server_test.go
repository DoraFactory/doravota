package keeper

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	sdkaddress "github.com/cosmos/cosmos-sdk/codec/address"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/cosmos/cosmos-sdk/x/feegrant"
	"github.com/stretchr/testify/require"
)

type feegrantMsgServerStub struct {
	grantErr  error
	revokeErr error
	pruneErr  error
}

func (stub feegrantMsgServerStub) GrantAllowance(
	context.Context,
	*feegrant.MsgGrantAllowance,
) (*feegrant.MsgGrantAllowanceResponse, error) {
	if stub.grantErr != nil {
		return nil, stub.grantErr
	}
	return &feegrant.MsgGrantAllowanceResponse{}, nil
}

func (stub feegrantMsgServerStub) RevokeAllowance(
	context.Context,
	*feegrant.MsgRevokeAllowance,
) (*feegrant.MsgRevokeAllowanceResponse, error) {
	if stub.revokeErr != nil {
		return nil, stub.revokeErr
	}
	return &feegrant.MsgRevokeAllowanceResponse{}, nil
}

func (stub feegrantMsgServerStub) PruneAllowances(
	context.Context,
	*feegrant.MsgPruneAllowances,
) (*feegrant.MsgPruneAllowancesResponse, error) {
	if stub.pruneErr != nil {
		return nil, stub.pruneErr
	}
	return &feegrant.MsgPruneAllowancesResponse{}, nil
}

func TestFeegrantMsgServerMaintainsOutgoingIndex(t *testing.T) {
	moduleKeeper, ctx := setupKeeper(t, 10)
	ctx = ctx.WithBlockTime(time.Unix(2_000_000_000, 0).UTC())
	granter := sdk.AccAddress(bytes.Repeat([]byte{0x21}, 20))
	grantee := sdk.AccAddress(bytes.Repeat([]byte{0x22}, 20))
	server := NewFeegrantMsgServer(
		feegrantMsgServerStub{},
		moduleKeeper,
		sdkaddress.NewBech32Codec(sdk.GetConfig().GetBech32AccountAddrPrefix()),
	)
	grant, err := feegrant.NewMsgGrantAllowance(
		&feegrant.BasicAllowance{},
		granter,
		grantee,
	)
	require.NoError(t, err)

	_, err = server.GrantAllowance(sdk.WrapSDKContext(ctx), grant)
	require.NoError(t, err)
	found, err := moduleKeeper.HasOutgoingFeegrant(ctx, granter)
	require.NoError(t, err)
	require.True(t, found)

	revoke := feegrant.NewMsgRevokeAllowance(granter, grantee)
	_, err = server.RevokeAllowance(sdk.WrapSDKContext(ctx), &revoke)
	require.NoError(t, err)
	found, err = moduleKeeper.HasOutgoingFeegrant(ctx, granter)
	require.NoError(t, err)
	require.False(t, found)
}

func TestFeegrantMsgServerIndexesOnlySuccessfulMutations(t *testing.T) {
	moduleKeeper, ctx := setupKeeper(t, 10)
	granter := sdk.AccAddress(bytes.Repeat([]byte{0x31}, 20))
	grantee := sdk.AccAddress(bytes.Repeat([]byte{0x32}, 20))
	expected := errors.New("canonical feegrant mutation failed")
	server := NewFeegrantMsgServer(
		feegrantMsgServerStub{grantErr: expected},
		moduleKeeper,
		sdkaddress.NewBech32Codec(sdk.GetConfig().GetBech32AccountAddrPrefix()),
	)
	grant, err := feegrant.NewMsgGrantAllowance(
		&feegrant.BasicAllowance{},
		granter,
		grantee,
	)
	require.NoError(t, err)

	_, err = server.GrantAllowance(sdk.WrapSDKContext(ctx), grant)
	require.ErrorIs(t, err, expected)
	found, err := moduleKeeper.HasOutgoingFeegrant(ctx, granter)
	require.NoError(t, err)
	require.False(t, found)
}

func TestFeegrantMsgServerPrunesMatchingDerivedEntries(t *testing.T) {
	moduleKeeper, ctx := setupKeeper(t, 10)
	now := time.Unix(2_000_000_000, 0).UTC()
	ctx = ctx.WithBlockTime(now)
	granter := sdk.AccAddress(bytes.Repeat([]byte{0x41}, 20))
	grantee := sdk.AccAddress(bytes.Repeat([]byte{0x42}, 20))
	expiration := now.Add(-time.Second)
	require.NoError(t, moduleKeeper.SetOutgoingFeegrant(
		ctx,
		granter,
		grantee,
		&feegrant.BasicAllowance{Expiration: &expiration},
	))
	server := NewFeegrantMsgServer(
		feegrantMsgServerStub{},
		moduleKeeper,
		sdkaddress.NewBech32Codec(sdk.GetConfig().GetBech32AccountAddrPrefix()),
	)

	_, err := server.PruneAllowances(
		sdk.WrapSDKContext(ctx),
		&feegrant.MsgPruneAllowances{Pruner: granter.String()},
	)
	require.NoError(t, err)
	found, err := moduleKeeper.HasOutgoingFeegrant(ctx, granter)
	require.NoError(t, err)
	require.False(t, found)
}

var _ feegrant.MsgServer = feegrantMsgServerStub{}
