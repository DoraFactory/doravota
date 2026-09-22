package legacyics29

import (
	"encoding/json"
	"fmt"
	"testing"

	sdk "github.com/cosmos/cosmos-sdk/types"
	channeltypes "github.com/cosmos/ibc-go/v10/modules/core/04-channel/types"
	porttypes "github.com/cosmos/ibc-go/v10/modules/core/05-port/types"
	"github.com/cosmos/ibc-go/v10/modules/core/exported"
	"github.com/stretchr/testify/require"
)

type callbackApp struct {
	porttypes.IBCModule
	version string
	ack     []byte
	async   bool
}

func (a *callbackApp) OnRecvPacket(_ sdk.Context, v string, _ channeltypes.Packet, _ sdk.AccAddress) exported.Acknowledgement {
	a.version = v
	if a.async {
		return nil
	}
	return channeltypes.NewResultAcknowledgement([]byte{1})
}
func (a *callbackApp) OnAcknowledgementPacket(_ sdk.Context, v string, _ channeltypes.Packet, ack []byte, _ sdk.AccAddress) error {
	a.version = v
	a.ack = ack
	return nil
}
func (a *callbackApp) OnChanOpenInit(_ sdk.Context, _ channeltypes.Order, _ []string, _, _ string, _ channeltypes.Counterparty, v string) (string, error) {
	return v, nil
}
func (a *callbackApp) OnChanOpenAck(_ sdk.Context, _, _, _, v string) error {
	a.version = v
	return nil
}

type wire struct {
	porttypes.ICS4Wrapper
	ack  exported.Acknowledgement
	fail bool
}

func (w *wire) WriteAcknowledgement(_ sdk.Context, _ exported.PacketI, a exported.Acknowledgement) error {
	if w.fail {
		return fmt.Errorf("injected write failure")
	}
	w.ack = a
	return nil
}

func TestLegacyWireAcknowledgements(t *testing.T) {
	ctx, key, _ := fixture(t)
	rawVersion := `{"fee_version":"ics29-1","app_version":"ics721-1"}`
	relayer := sdk.AccAddress(make([]byte, 20))
	packet := channeltypes.Packet{SourcePort: "transfer", SourceChannel: "channel-0", DestinationPort: "transfer", DestinationChannel: "channel-0", Sequence: 1}
	store := ctx.KVStore(key)
	store.Set(feeKey("transfer", "channel-0"), []byte{1})
	store.Set([]byte("counterpartyPayee/"+relayer.String()+"/channel-0"), []byte("remote-payee"))
	base := &callbackApp{}
	ics4 := &wire{}
	k := Keeper{ICS4Wrapper: ics4, Key: key}
	m := Middleware{IBCModule: base, Keeper: k}
	ack := m.OnRecvPacket(ctx, rawVersion, packet, relayer)
	require.Equal(t, "ics721-1", base.version)
	var wrapped acknowledgement
	require.NoError(t, json.Unmarshal(ack.Acknowledgement(), &wrapped))
	require.Equal(t, "remote-payee", wrapped.ForwardRelayerAddress)
	require.JSONEq(t, `{"result":"AQ=="}`, string(wrapped.AppAcknowledgement))
	require.NoError(t, m.OnAcknowledgementPacket(ctx, rawVersion, packet, ack.Acknowledgement(), relayer))
	require.Equal(t, wrapped.AppAcknowledgement, base.ack)
	require.Error(t, m.OnAcknowledgementPacket(ctx, rawVersion, packet, []byte(`{"result":"AQ=="}`), relayer))
	require.NoError(t, m.OnChanOpenAck(ctx, "transfer", "channel-0", "channel-1", rawVersion))
	require.Equal(t, "ics721-1", base.version)
	base.async = true
	require.Nil(t, m.OnRecvPacket(ctx, rawVersion, packet, relayer))
	require.True(t, store.Has(forwardKey(packet)))
	ics4.fail = true
	require.Error(t, k.WriteAcknowledgement(ctx, packet, channeltypes.NewResultAcknowledgement([]byte{1})))
	require.True(t, store.Has(forwardKey(packet)))
	ics4.fail = false
	require.NoError(t, k.WriteAcknowledgement(ctx, packet, channeltypes.NewResultAcknowledgement([]byte{1})))
	require.False(t, store.Has(forwardKey(packet)))
	require.NoError(t, json.Unmarshal(ics4.ack.Acknowledgement(), &wrapped))
	require.Equal(t, "remote-payee", wrapped.ForwardRelayerAddress)
}
func TestNewChannelsCannotEnableFees(t *testing.T) {
	ctx, key, _ := fixture(t)
	m := Middleware{IBCModule: &callbackApp{}, Keeper: Keeper{Key: key}}
	_, err := m.OnChanOpenInit(ctx, channeltypes.UNORDERED, nil, "transfer", "channel-1", channeltypes.Counterparty{}, `{"fee_version":"ics29-1","app_version":"ics20-1"}`)
	require.Error(t, err)
	version, err := m.OnChanOpenInit(ctx, channeltypes.UNORDERED, nil, "transfer", "channel-1", channeltypes.Counterparty{}, "ics20-1")
	require.NoError(t, err)
	require.Equal(t, "ics20-1", version)
}
