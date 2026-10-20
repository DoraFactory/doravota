package keeper

import (
	"context"
	"errors"

	"cosmossdk.io/core/address"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/cosmos/cosmos-sdk/x/feegrant"
)

// FeegrantMsgServer keeps the pqcauth granter index in the same cached state
// transition as the canonical x/feegrant store. Wrapping the MsgServer, rather
// than relying only on top-level Ante inspection, also covers executions routed
// through authz, group, governance, or Wasm.
type FeegrantMsgServer struct {
	inner        feegrant.MsgServer
	keeper       Keeper
	addressCodec address.Codec
}

func NewFeegrantMsgServer(
	inner feegrant.MsgServer,
	moduleKeeper Keeper,
	addressCodec address.Codec,
) FeegrantMsgServer {
	if inner == nil {
		panic("pqcauth feegrant message server is required")
	}
	if addressCodec == nil {
		panic("pqcauth feegrant address codec is required")
	}
	return FeegrantMsgServer{
		inner:        inner,
		keeper:       moduleKeeper,
		addressCodec: addressCodec,
	}
}

func (s FeegrantMsgServer) GrantAllowance(
	ctx context.Context,
	message *feegrant.MsgGrantAllowance,
) (*feegrant.MsgGrantAllowanceResponse, error) {
	response, err := s.inner.GrantAllowance(ctx, message)
	if err != nil {
		return nil, err
	}
	granter, grantee, err := s.allowanceAddresses(message.Granter, message.Grantee)
	if err != nil {
		return nil, err
	}
	allowance, err := message.GetFeeAllowanceI()
	if err != nil {
		return nil, err
	}
	if err := s.keeper.SetOutgoingFeegrant(sdk.UnwrapSDKContext(ctx), granter, grantee, allowance); err != nil {
		return nil, err
	}
	return response, nil
}

func (s FeegrantMsgServer) RevokeAllowance(
	ctx context.Context,
	message *feegrant.MsgRevokeAllowance,
) (*feegrant.MsgRevokeAllowanceResponse, error) {
	response, err := s.inner.RevokeAllowance(ctx, message)
	if err != nil {
		return nil, err
	}
	granter, grantee, err := s.allowanceAddresses(message.Granter, message.Grantee)
	if err != nil {
		return nil, err
	}
	if err := s.keeper.DeleteOutgoingFeegrant(sdk.UnwrapSDKContext(ctx), granter, grantee); err != nil {
		return nil, err
	}
	return response, nil
}

func (s FeegrantMsgServer) PruneAllowances(
	ctx context.Context,
	message *feegrant.MsgPruneAllowances,
) (*feegrant.MsgPruneAllowancesResponse, error) {
	response, err := s.inner.PruneAllowances(ctx, message)
	if err != nil {
		return nil, err
	}
	if err := s.keeper.PruneExpiredFeegrantIndexForMessage(sdk.UnwrapSDKContext(ctx)); err != nil {
		return nil, err
	}
	return response, nil
}

func (s FeegrantMsgServer) allowanceAddresses(
	encodedGranter, encodedGrantee string,
) (sdk.AccAddress, sdk.AccAddress, error) {
	granter, err := s.addressCodec.StringToBytes(encodedGranter)
	if err != nil {
		return nil, nil, err
	}
	grantee, err := s.addressCodec.StringToBytes(encodedGrantee)
	if err != nil {
		return nil, nil, err
	}
	if len(granter) == 0 || len(grantee) == 0 {
		return nil, nil, errors.New("feegrant addresses must not be empty")
	}
	return sdk.AccAddress(granter), sdk.AccAddress(grantee), nil
}

var _ feegrant.MsgServer = FeegrantMsgServer{}
