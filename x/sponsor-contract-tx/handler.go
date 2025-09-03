package sponsor

import (
    sdk "github.com/cosmos/cosmos-sdk/types"
    sdkerrors "github.com/cosmos/cosmos-sdk/types/errors"

    "github.com/DoraFactory/doravota/x/sponsor-contract-tx/keeper"
    "github.com/DoraFactory/doravota/x/sponsor-contract-tx/types"
)

// NewHandler creates a new handler for sponsor messages
func NewHandler(k keeper.Keeper) sdk.Handler {
    msgServer := keeper.NewMsgServerImpl(k)

	return func(ctx sdk.Context, msg sdk.Msg) (*sdk.Result, error) {
		ctx = ctx.WithEventManager(sdk.NewEventManager())

		switch msg := msg.(type) {
		case *types.MsgSetSponsor:
			res, err := msgServer.SetSponsor(sdk.WrapSDKContext(ctx), msg)
			return sdk.WrapServiceResult(ctx, res, err)
		case *types.MsgUpdateSponsor:
			res, err := msgServer.UpdateSponsor(sdk.WrapSDKContext(ctx), msg)
			return sdk.WrapServiceResult(ctx, res, err)
		case *types.MsgDeleteSponsor:
			res, err := msgServer.DeleteSponsor(sdk.WrapSDKContext(ctx), msg)
			return sdk.WrapServiceResult(ctx, res, err)
		case *types.MsgWithdrawSponsorFunds:
			res, err := msgServer.WithdrawSponsorFunds(sdk.WrapSDKContext(ctx), msg)
			return sdk.WrapServiceResult(ctx, res, err)
		default:
			return nil, sdkerrors.Wrapf(sdkerrors.ErrUnknownRequest, "unrecognized %s message type: %T", types.ModuleName, msg)
		}
	}
}

// NewHandlerWithDeps creates a new handler and injects dependencies for full functionality
// Prefer using gRPC Msg service path; this is provided for legacy router usage.
func NewHandlerWithDeps(k keeper.Keeper, bk types.BankKeeper) sdk.Handler {
    msgServer := keeper.NewMsgServerImplWithDeps(k, bk)

    return func(ctx sdk.Context, msg sdk.Msg) (*sdk.Result, error) {
        ctx = ctx.WithEventManager(sdk.NewEventManager())

        switch msg := msg.(type) {
        case *types.MsgSetSponsor:
            res, err := msgServer.SetSponsor(sdk.WrapSDKContext(ctx), msg)
            return sdk.WrapServiceResult(ctx, res, err)
        case *types.MsgUpdateSponsor:
            res, err := msgServer.UpdateSponsor(sdk.WrapSDKContext(ctx), msg)
            return sdk.WrapServiceResult(ctx, res, err)
        case *types.MsgDeleteSponsor:
            res, err := msgServer.DeleteSponsor(sdk.WrapSDKContext(ctx), msg)
            return sdk.WrapServiceResult(ctx, res, err)
        case *types.MsgWithdrawSponsorFunds:
            res, err := msgServer.WithdrawSponsorFunds(sdk.WrapSDKContext(ctx), msg)
            return sdk.WrapServiceResult(ctx, res, err)
        default:
            return nil, sdkerrors.Wrapf(sdkerrors.ErrUnknownRequest, "unrecognized %s message type: %T", types.ModuleName, msg)
        }
    }
}
