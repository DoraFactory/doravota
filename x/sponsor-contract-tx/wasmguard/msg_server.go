package wasmguard

import (
	"context"

	wasmtypes "github.com/CosmWasm/wasmd/x/wasm/types"
	sdk "github.com/cosmos/cosmos-sdk/types"

	sponsortypes "github.com/DoraFactory/doravota/x/sponsor-contract-tx/types"
)

// SponsorStateReader is the minimal Sponsor state required to protect the
// Wasm contract-admin lifecycle.
type SponsorStateReader interface {
	HasSponsor(ctx sdk.Context, contractAddr string) bool
}

// MsgServer wraps the upstream Wasm MsgServer and protects ClearAdmin without
// changing any other Wasm message behavior.
type MsgServer struct {
	wasmtypes.MsgServer
	sponsorState SponsorStateReader
}

var _ wasmtypes.MsgServer = MsgServer{}

// NewMsgServer returns a Wasm MsgServer that rejects ClearAdmin while the
// contract still has Sponsor state.
func NewMsgServer(next wasmtypes.MsgServer, sponsorState SponsorStateReader) wasmtypes.MsgServer {
	return MsgServer{
		MsgServer:    next,
		sponsorState: sponsorState,
	}
}

// ClearAdmin requires the current admin to withdraw Sponsor funds and delete
// the Sponsor before permanently clearing the Wasm admin. The check is in the
// message execution path, so authz and governance-dispatched messages are
// covered as well as ordinary transactions.
func (m MsgServer) ClearAdmin(goCtx context.Context, msg *wasmtypes.MsgClearAdmin) (*wasmtypes.MsgClearAdminResponse, error) {
	if msg == nil {
		return m.MsgServer.ClearAdmin(goCtx, msg)
	}
	if err := msg.ValidateBasic(); err != nil {
		return nil, err
	}

	ctx := sdk.UnwrapSDKContext(goCtx)
	if m.sponsorState.HasSponsor(ctx, msg.Contract) {
		return nil, sponsortypes.ErrSponsorMustBeRemoved.Wrap(
			"withdraw all sponsor funds and delete the sponsor before clearing contract admin",
		)
	}

	return m.MsgServer.ClearAdmin(goCtx, msg)
}
