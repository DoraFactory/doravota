package legacyics29

import (
	"encoding/json"
	"fmt"

	storetypes "cosmossdk.io/store/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
	channeltypes "github.com/cosmos/ibc-go/v10/modules/core/04-channel/types"
	porttypes "github.com/cosmos/ibc-go/v10/modules/core/05-port/types"
	"github.com/cosmos/ibc-go/v10/modules/core/exported"
)

type metadata struct {
	FeeVersion string `json:"fee_version"`
	AppVersion string `json:"app_version"`
}

func appVersion(version string) (string, error) {
	var m metadata
	if err := json.Unmarshal([]byte(version), &m); err != nil {
		return "", err
	}
	if m.FeeVersion != "ics29-1" {
		return "", fmt.Errorf("invalid ICS-29 channel version")
	}
	return m.AppVersion, nil
}
func containsFeeVersion(version string) bool {
	var fields map[string]json.RawMessage
	if json.Unmarshal([]byte(version), &fields) != nil {
		return false
	}
	_, ok := fields["fee_version"]
	return ok
}
func feeKey(port, channel string) []byte { return []byte("feeEnabled/" + port + "/" + channel) }
func forwardKey(packet exported.PacketI) []byte {
	return []byte(fmt.Sprintf("forwardRelayer/%s/%s/%d", packet.GetDestPort(), packet.GetDestChannel(), packet.GetSequence()))
}

type acknowledgement struct {
	AppAcknowledgement    []byte `json:"app_acknowledgement"`
	ForwardRelayerAddress string `json:"forward_relayer_address"`
	UnderlyingAppSuccess  bool   `json:"underlying_app_success"`
}

func (a acknowledgement) Success() bool { return a.UnderlyingAppSuccess }
func (a acknowledgement) Acknowledgement() []byte {
	b, err := json.Marshal(a)
	if err != nil {
		panic(err)
	}
	return sdk.MustSortJSON(b)
}

// Keeper wraps only the wire protocol of migrated channels. SendPacket passes
// through unchanged. Counterparty payee mappings remain frozen at upgrade;
// unregistered relayers get the standard ICS-29 empty-payee refund behavior on
// the other chain. There are deliberately no new fee registration messages.
type Keeper struct {
	porttypes.ICS4Wrapper
	Key *storetypes.KVStoreKey
}

func (k Keeper) enabled(ctx sdk.Context, port, channel string) bool {
	return ctx.KVStore(k.Key).Has(feeKey(port, channel))
}
func (k Keeper) wrap(ctx sdk.Context, channel, relayer string, ack exported.Acknowledgement) exported.Acknowledgement {
	payee := ctx.KVStore(k.Key).Get([]byte("counterpartyPayee/" + relayer + "/" + channel))
	return acknowledgement{ack.Acknowledgement(), string(payee), ack.Success()}
}
func (k Keeper) GetAppVersion(ctx sdk.Context, port, channel string) (string, bool) {
	version, found := k.ICS4Wrapper.GetAppVersion(ctx, port, channel)
	if !found || !k.enabled(ctx, port, channel) {
		return version, found
	}
	underlying, err := appVersion(version)
	if err != nil {
		return "", false
	}
	return underlying, true
}
func (k Keeper) WriteAcknowledgement(ctx sdk.Context, packet exported.PacketI, ack exported.Acknowledgement) error {
	if !k.enabled(ctx, packet.GetDestPort(), packet.GetDestChannel()) {
		return k.ICS4Wrapper.WriteAcknowledgement(ctx, packet, ack)
	}
	cache, write := ctx.CacheContext()
	store := cache.KVStore(k.Key)
	key := forwardKey(packet)
	relayer := store.Get(key)
	if len(relayer) == 0 {
		return fmt.Errorf("missing legacy async acknowledgement relayer")
	}
	if err := k.ICS4Wrapper.WriteAcknowledgement(cache, packet, k.wrap(cache, packet.GetDestChannel(), string(relayer), ack)); err != nil {
		return err
	}
	store.Delete(key)
	write()
	return nil
}

type Middleware struct {
	porttypes.IBCModule
	Keeper Keeper
}

var _ porttypes.IBCModule = Middleware{}
var _ porttypes.ICS4Wrapper = Keeper{}

// Fresh channels use the underlying application protocol; no new ICS-29
// channels can be negotiated. Existing INIT/TRYOPEN channels may finish.
func (m Middleware) OnChanOpenInit(ctx sdk.Context, order channeltypes.Order, hops []string, port, channel string, counterparty channeltypes.Counterparty, version string) (string, error) {
	if containsFeeVersion(version) {
		return "", fmt.Errorf("new ICS-29 channels are disabled")
	}
	selected, err := m.IBCModule.OnChanOpenInit(ctx, order, hops, port, channel, counterparty, version)
	if err == nil && containsFeeVersion(selected) {
		return "", fmt.Errorf("application cannot enable a new ICS-29 channel")
	}
	return selected, err
}
func (m Middleware) OnChanOpenTry(ctx sdk.Context, order channeltypes.Order, hops []string, port, channel string, counterparty channeltypes.Counterparty, version string) (string, error) {
	if containsFeeVersion(version) {
		return "", fmt.Errorf("new ICS-29 channels are disabled")
	}
	selected, err := m.IBCModule.OnChanOpenTry(ctx, order, hops, port, channel, counterparty, version)
	if err == nil && containsFeeVersion(selected) {
		return "", fmt.Errorf("application cannot enable a new ICS-29 channel")
	}
	return selected, err
}
func (m Middleware) OnChanOpenAck(ctx sdk.Context, port, channel, counterpartyChannel, version string) error {
	if m.Keeper.enabled(ctx, port, channel) {
		v, err := appVersion(version)
		if err != nil {
			return err
		}
		version = v
	} else if containsFeeVersion(version) {
		return fmt.Errorf("new ICS-29 channels are disabled")
	}
	return m.IBCModule.OnChanOpenAck(ctx, port, channel, counterpartyChannel, version)
}
func (m Middleware) OnRecvPacket(ctx sdk.Context, version string, packet channeltypes.Packet, relayer sdk.AccAddress) exported.Acknowledgement {
	if !m.Keeper.enabled(ctx, packet.DestinationPort, packet.DestinationChannel) {
		return m.IBCModule.OnRecvPacket(ctx, version, packet, relayer)
	}
	v, err := appVersion(version)
	if err != nil {
		return m.Keeper.wrap(ctx, packet.DestinationChannel, relayer.String(), channeltypes.NewErrorAcknowledgement(err))
	}
	ack := m.IBCModule.OnRecvPacket(ctx, v, packet, relayer)
	if ack == nil {
		ctx.KVStore(m.Keeper.Key).Set(forwardKey(packet), []byte(relayer.String()))
		return nil
	}
	return m.Keeper.wrap(ctx, packet.DestinationChannel, relayer.String(), ack)
}
func (m Middleware) OnAcknowledgementPacket(ctx sdk.Context, version string, packet channeltypes.Packet, ack []byte, relayer sdk.AccAddress) error {
	if m.Keeper.enabled(ctx, packet.SourcePort, packet.SourceChannel) {
		v, err := appVersion(version)
		if err != nil {
			return err
		}
		version = v
		var wrapped acknowledgement
		if err := json.Unmarshal(ack, &wrapped); err != nil {
			return fmt.Errorf("decode ICS-29 acknowledgement: %w", err)
		}
		if len(wrapped.AppAcknowledgement) == 0 {
			return fmt.Errorf("missing ICS-29 application acknowledgement")
		}
		ack = wrapped.AppAcknowledgement
	}
	return m.IBCModule.OnAcknowledgementPacket(ctx, version, packet, ack, relayer)
}
func (m Middleware) OnTimeoutPacket(ctx sdk.Context, version string, packet channeltypes.Packet, relayer sdk.AccAddress) error {
	if m.Keeper.enabled(ctx, packet.SourcePort, packet.SourceChannel) {
		v, err := appVersion(version)
		if err != nil {
			return err
		}
		version = v
	}
	return m.IBCModule.OnTimeoutPacket(ctx, version, packet, relayer)
}

// Preserve the optional packet-decoding interface used by IBC tooling.
func (m Middleware) UnmarshalPacketData(ctx sdk.Context, port, channel string, raw []byte) (any, string, error) {
	if decoder, ok := m.IBCModule.(porttypes.PacketDataUnmarshaler); ok {
		return decoder.UnmarshalPacketData(ctx, port, channel, raw)
	}
	return nil, "", fmt.Errorf("underlying application does not support packet decoding")
}
