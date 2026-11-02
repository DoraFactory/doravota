package keeper

import (
	"context"

	errorsmod "cosmossdk.io/errors"
	sdk "github.com/cosmos/cosmos-sdk/types"
	sdkerrors "github.com/cosmos/cosmos-sdk/types/errors"

	"github.com/DoraFactory/doravota/x/pqcauth/types"
)

type QueryServer struct {
	types.UnimplementedQueryServer
	Keeper
}

var _ types.QueryServer = QueryServer{}

func NewQueryServer(keeper Keeper) types.QueryServer {
	return QueryServer{Keeper: keeper}
}

func (q QueryServer) Params(
	goCtx context.Context,
	req *types.QueryParamsRequest,
) (*types.QueryParamsResponse, error) {
	if req == nil {
		return nil, errorsmod.Wrap(sdkerrors.ErrInvalidRequest, "nil request")
	}
	ctx := sdk.UnwrapSDKContext(goCtx)
	params := q.GetParams(ctx).Effective(ctx.BlockHeight())
	return &types.QueryParamsResponse{
		Params:                   params,
		EffectiveEnforcementMode: params.EnforcementMode,
		EffectiveEmergencyMode:   params.EmergencyMode,
	}, nil
}

func (q QueryServer) Account(
	goCtx context.Context,
	req *types.QueryAccountRequest,
) (*types.QueryAccountResponse, error) {
	if req == nil {
		return nil, errorsmod.Wrap(sdkerrors.ErrInvalidRequest, "nil request")
	}
	owner, err := sdk.AccAddressFromBech32(req.Owner)
	if err != nil || owner.String() != req.Owner {
		return nil, errorsmod.Wrap(sdkerrors.ErrInvalidAddress, "invalid owner")
	}
	ctx := sdk.UnwrapSDKContext(goCtx)
	policy, found := q.GetEffectiveAccountPolicy(ctx, owner)
	if !found {
		return nil, types.ErrPolicyNotFound
	}
	response := &types.QueryAccountResponse{Policy: policy}
	if key, _, active := q.GetActiveSigningKey(ctx, owner); active {
		response.ActiveSigningKey = &key
	}
	for _, role := range []types.KeyRole{
		types.KeyRole_KEY_ROLE_SIGNING,
		types.KeyRole_KEY_ROLE_RECOVERY,
	} {
		if history, exists := q.GetKeyHistory(ctx, owner, role); exists {
			response.KeyHistories = append(response.KeyHistories, history)
		}
	}
	return response, nil
}

func (q QueryServer) Key(
	goCtx context.Context,
	req *types.QueryKeyRequest,
) (*types.QueryKeyResponse, error) {
	if req == nil {
		return nil, errorsmod.Wrap(sdkerrors.ErrInvalidRequest, "nil request")
	}
	owner, err := sdk.AccAddressFromBech32(req.Owner)
	if err != nil || owner.String() != req.Owner || req.KeyId == 0 {
		return nil, errorsmod.Wrap(sdkerrors.ErrInvalidRequest, "invalid owner or key id")
	}
	ctx := sdk.UnwrapSDKContext(goCtx)
	key, found := q.GetKey(ctx, owner, req.KeyId)
	if !found {
		return nil, types.ErrKeyNotFound
	}
	return &types.QueryKeyResponse{Key: key}, nil
}

func (q QueryServer) Keys(
	goCtx context.Context,
	req *types.QueryKeysRequest,
) (*types.QueryKeysResponse, error) {
	if req == nil {
		return nil, errorsmod.Wrap(sdkerrors.ErrInvalidRequest, "nil request")
	}
	owner, err := sdk.AccAddressFromBech32(req.Owner)
	if err != nil || owner.String() != req.Owner {
		return nil, errorsmod.Wrap(sdkerrors.ErrInvalidAddress, "invalid owner")
	}
	ctx := sdk.UnwrapSDKContext(goCtx)
	keys, pagination, err := q.GetKeysPaginated(ctx, owner, req.Pagination)
	if err != nil {
		return nil, err
	}
	return &types.QueryKeysResponse{Keys: keys, Pagination: pagination}, nil
}
