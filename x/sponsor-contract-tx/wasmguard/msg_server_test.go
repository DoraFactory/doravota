package wasmguard

import (
	"bytes"
	"context"
	"testing"

	wasmtypes "github.com/CosmWasm/wasmd/x/wasm/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/stretchr/testify/require"

	sponsortypes "github.com/DoraFactory/doravota/x/sponsor-contract-tx/types"
)

type recordingWasmMsgServer struct {
	wasmtypes.UnimplementedMsgServer
	clearAdminCalls int
}

func (m *recordingWasmMsgServer) ClearAdmin(context.Context, *wasmtypes.MsgClearAdmin) (*wasmtypes.MsgClearAdminResponse, error) {
	m.clearAdminCalls++
	return &wasmtypes.MsgClearAdminResponse{}, nil
}

type stubSponsorState struct {
	hasSponsor bool
}

func (s stubSponsorState) HasSponsor(sdk.Context, string) bool {
	return s.hasSponsor
}

func TestClearAdminRejectsActiveSponsor(t *testing.T) {
	next := &recordingWasmMsgServer{}
	server := NewMsgServer(next, stubSponsorState{hasSponsor: true})
	msg := &wasmtypes.MsgClearAdmin{
		Sender:   sdk.AccAddress(bytes.Repeat([]byte{0x01}, 20)).String(),
		Contract: sdk.AccAddress(bytes.Repeat([]byte{0x02}, 20)).String(),
	}

	resp, err := server.ClearAdmin(sdk.WrapSDKContext(sdk.Context{}), msg)

	require.Nil(t, resp)
	require.ErrorIs(t, err, sponsortypes.ErrSponsorMustBeRemoved)
	require.Zero(t, next.clearAdminCalls)
}

func TestClearAdminDelegatesAfterSponsorRemoval(t *testing.T) {
	next := &recordingWasmMsgServer{}
	server := NewMsgServer(next, stubSponsorState{})
	msg := &wasmtypes.MsgClearAdmin{
		Sender:   sdk.AccAddress(bytes.Repeat([]byte{0x03}, 20)).String(),
		Contract: sdk.AccAddress(bytes.Repeat([]byte{0x04}, 20)).String(),
	}

	resp, err := server.ClearAdmin(sdk.WrapSDKContext(sdk.Context{}), msg)

	require.NoError(t, err)
	require.NotNil(t, resp)
	require.Equal(t, 1, next.clearAdminCalls)
}
