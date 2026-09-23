package legacyics29

import (
	"encoding/json"
	"testing"

	sdk "github.com/cosmos/cosmos-sdk/types"
	authtypes "github.com/cosmos/cosmos-sdk/x/auth/types"
	channeltypes "github.com/cosmos/ibc-go/v10/modules/core/04-channel/types"
	"github.com/stretchr/testify/require"
)

func TestHistoricalCounterpartyPayeeBytes(t *testing.T) {
	for _, tc := range []struct {
		name string
		raw  []byte
	}{
		{"ascii", []byte("remote-payee")}, {"unicode", []byte("收款地址")},
		{"invalid byte", []byte{0xff}}, {"overlong", []byte{0xc0, 0xaf}},
		{"surrogate", []byte{0xed, 0xa0, 0x80}}, {"truncated", []byte{0xe4, 0xb8}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, key, bank := fixture(t)
			store := ctx.KVStore(key)
			relayer := sdk.AccAddress(make([]byte, 20))
			source := authtypes.NewModuleAddress("feeibc")
			meta := []byte("counterpartyPayee/" + relayer.String() + "/channel-0")
			packetKey := []byte("feesInEscrow/transfer/channel-0/1")
			store.Set(feeKey("transfer", "channel-0"), []byte{1})
			store.Set(meta, tc.raw)
			store.Set(packetKey, packetFee(t, relayer))
			bank.set(ctx, source, sdk.NewCoins(sdk.NewInt64Coin("peaka", 12)))
			require.NoError(t, RefundAndRetire(ctx, key, bank, testChannels{}))
			require.Equal(t, "12peaka", bank.GetAllBalances(ctx, relayer).String())
			require.True(t, bank.GetAllBalances(ctx, source).IsZero())
			require.False(t, store.Has(packetKey))
			require.Equal(t, tc.raw, store.Get(meta))
			require.NoError(t, RefundAndRetire(ctx, key, bank, testChannels{}))
			require.Equal(t, "12peaka", bank.GetAllBalances(ctx, relayer).String())

			// Genesis encodes []byte as base64, preserving even invalid text exactly.
			raw := (Module{Key: key}).ExportGenesis(ctx, nil)
			require.NoError(t, (Basic{}).ValidateGenesis(nil, nil, raw))
			restored, restoredKey, _ := fixture(t)
			(Module{Key: restoredKey}).InitGenesis(restored, nil, raw)
			require.Equal(t, tc.raw, restored.KVStore(restoredKey).Get(meta))

			// The legacy JSON acknowledgement replaces invalid UTF-8 on the wire,
			// as v7.3.0 did, without rewriting the stored mapping.
			w := &wire{}
			app := &callbackApp{}
			keeper := Keeper{ICS4Wrapper: w, Key: key}
			m := Middleware{IBCModule: app, Keeper: keeper}
			packet := channeltypes.Packet{SourcePort: "transfer", SourceChannel: "channel-0", DestinationPort: "transfer", DestinationChannel: "channel-0", Sequence: 1}
			version := `{"fee_version":"ics29-1","app_version":"ics721-1"}`
			ack := m.OnRecvPacket(ctx, version, packet, relayer)
			var decoded acknowledgement
			require.NoError(t, json.Unmarshal(ack.Acknowledgement(), &decoded))
			require.Equal(t, string([]rune(string(tc.raw))), decoded.ForwardRelayerAddress)
			require.JSONEq(t, `{"result":"AQ=="}`, string(decoded.AppAcknowledgement))
			require.NoError(t, m.OnAcknowledgementPacket(ctx, version, packet, ack.Acknowledgement(), relayer))
			require.Equal(t, decoded.AppAcknowledgement, app.ack)
			app.async = true
			require.Nil(t, m.OnRecvPacket(ctx, version, packet, relayer))
			require.NoError(t, keeper.WriteAcknowledgement(ctx, packet, channeltypes.NewResultAcknowledgement([]byte{1})))
			require.Equal(t, ack.Acknowledgement(), w.ack.Acknowledgement())
			require.Equal(t, tc.raw, store.Get(meta))
		})
	}
}

func TestHistoricalPayeeValidationStillRejectsInvalidFinancialState(t *testing.T) {
	a := sdk.AccAddress(make([]byte, 20))
	for _, tc := range []struct {
		name       string
		key, value []byte
	}{
		{"empty counterparty", []byte("counterpartyPayee/" + a.String() + "/channel-0"), nil},
		{"invalid local payee", []byte("payee/" + a.String() + "/channel-0"), []byte{0xff}},
		{"invalid relayer", []byte("counterpartyPayee/not-an-address/channel-0"), []byte{0xff}},
	} {
		t.Run(tc.name, func(t *testing.T) { require.Error(t, validateKey(tc.key, tc.value, true)) })
	}
	ctx, key, bank := fixture(t)
	store := ctx.KVStore(key)
	store.Set(feeKey("transfer", "channel-0"), []byte{1})
	store.Set([]byte("counterpartyPayee/"+a.String()+"/channel-0"), []byte{0xff})
	packet := []byte("feesInEscrow/transfer/channel-0/1")
	// A valid coin record with an invalid refund destination must still stop.
	amount := sdk.NewInt64Coin("peaka", 12)
	coin, err := amount.Marshal()
	require.NoError(t, err)
	store.Set(packet, field(1, append(field(1, field(1, coin)), field(2, []byte("not-an-address"))...)))
	source := authtypes.NewModuleAddress("feeibc")
	bank.set(ctx, source, sdk.NewCoins(sdk.NewInt64Coin("peaka", 12)))
	before := append([]byte(nil), store.Get(packet)...)
	require.Error(t, RefundAndRetire(ctx, key, bank, testChannels{}))
	require.Equal(t, before, store.Get(packet))
	require.Equal(t, "12peaka", bank.GetAllBalances(ctx, source).String())
	require.True(t, bank.GetAllBalances(ctx, a).IsZero())
}
