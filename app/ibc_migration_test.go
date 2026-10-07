package app_test

import (
	"encoding/binary"
	"testing"

	"github.com/DoraFactory/doravota/app/upgrades/sdk055"
	tmproto "github.com/cometbft/cometbft/proto/tendermint/types"
	ibc "github.com/cosmos/ibc-go/v11/modules/core"
	connectiontypes "github.com/cosmos/ibc-go/v11/modules/core/03-connection/types"
	channelv11 "github.com/cosmos/ibc-go/v11/modules/core/04-channel/migrations/v11"
	channeltypes "github.com/cosmos/ibc-go/v11/modules/core/04-channel/types"
	"github.com/stretchr/testify/require"
)

func TestPinnedIBCCoreMigrationVersion(t *testing.T) {
	require.EqualValues(t, 8, (ibc.AppModule{}).ConsensusVersion(), "Review automatic v11 channel migration before changing the pinned IBC dependency; never blindly skip an entire module migration")
}

func TestIBCChannelMigrationPreservesSequencesAndRejectsRepeat(t *testing.T) {
	a := policyTestApp(t)
	ctx := a.NewNextBlockContext(tmproto.Header{})
	key := a.GetKey("ibc")
	store := ctx.KVStore(key)
	a.IBCKeeper.ConnectionKeeper.SetConnection(ctx, "connection-0", connectiontypes.ConnectionEnd{ClientId: "07-tendermint-0", Counterparty: connectiontypes.Counterparty{ClientId: "07-tendermint-1"}, State: connectiontypes.OPEN})
	for i, tc := range []struct {
		state channeltypes.State
		order channeltypes.Order
	}{{channeltypes.OPEN, channeltypes.UNORDERED}, {channeltypes.OPEN, channeltypes.ORDERED}, {channeltypes.CLOSED, channeltypes.UNORDERED}, {channeltypes.INIT, channeltypes.UNORDERED}} {
		id := channeltypes.FormatChannelIdentifier(uint64(i))
		a.IBCKeeper.ChannelKeeper.SetChannel(ctx, "transfer", id, channeltypes.Channel{State: tc.state, Ordering: tc.order, ConnectionHops: []string{"connection-0"}, Counterparty: channeltypes.Counterparty{PortId: "transfer", ChannelId: id}, Version: "ics20-1"})
		b := make([]byte, 8)
		binary.BigEndian.PutUint64(b, uint64(31000+i))
		store.Set(channelv11.NextSequenceSendV1Key("transfer", id), b)
		a.IBCKeeper.ChannelKeeper.SetNextSequenceRecv(ctx, "transfer", id, uint64(100+i))
		a.IBCKeeper.ChannelKeeper.SetNextSequenceAck(ctx, "transfer", id, uint64(200+i))
		a.IBCKeeper.ChannelKeeper.SetPacketCommitment(ctx, "transfer", id, 7, []byte("pending-packet"))
	}
	require.NoError(t, sdk055.MigrateIBCChannels(ctx, key, a.AppCodec(), a.IBCKeeper))
	require.ErrorContains(t, sdk055.MigrateIBCChannels(ctx, key, a.AppCodec(), a.IBCKeeper), "may already have run")
	for i := 0; i < 4; i++ {
		id := channeltypes.FormatChannelIdentifier(uint64(i))
		send, found := a.IBCKeeper.ChannelKeeper.GetNextSequenceSend(ctx, "transfer", id)
		require.True(t, found)
		require.EqualValues(t, 31000+i, send)
		recv, found := a.IBCKeeper.ChannelKeeper.GetNextSequenceRecv(ctx, "transfer", id)
		require.True(t, found)
		require.EqualValues(t, 100+i, recv)
		ack, found := a.IBCKeeper.ChannelKeeper.GetNextSequenceAck(ctx, "transfer", id)
		require.True(t, found)
		require.EqualValues(t, 200+i, ack)
		require.Equal(t, []byte("pending-packet"), a.IBCKeeper.ChannelKeeper.GetPacketCommitment(ctx, "transfer", id, 7))
		require.False(t, store.Has(channelv11.NextSequenceSendV1Key("transfer", id)))
	}
}

func TestIBCChannelMigrationRejectsBadSourceWithoutWrites(t *testing.T) {
	for _, tc := range []struct {
		name        string
		value       []byte
		destination bool
	}{{"missing", nil, false}, {"short", []byte{1}, false}, {"zero", make([]byte, 8), false}, {"mixed", []byte{0, 0, 0, 0, 0, 0, 0, 9}, true}} {
		t.Run(tc.name, func(t *testing.T) {
			a := policyTestApp(t)
			ctx := a.NewNextBlockContext(tmproto.Header{})
			key := a.GetKey("ibc")
			store := ctx.KVStore(key)
			a.IBCKeeper.ChannelKeeper.SetChannel(ctx, "transfer", "channel-0", channeltypes.Channel{State: channeltypes.INIT})
			if tc.value != nil {
				store.Set(channelv11.NextSequenceSendV1Key("transfer", "channel-0"), tc.value)
			}
			if tc.destination {
				a.IBCKeeper.ChannelKeeperV2.SetNextSequenceSend(ctx, "channel-0", 99)
			}
			snapshot := func() map[string]string {
				m := map[string]string{}
				it := store.Iterator(nil, nil)
				defer it.Close()
				for ; it.Valid(); it.Next() {
					m[string(it.Key())] = string(it.Value())
				}
				return m
			}
			before := snapshot()
			require.Error(t, sdk055.MigrateIBCChannels(ctx, key, a.AppCodec(), a.IBCKeeper))
			require.Equal(t, before, snapshot())
		})
	}
}
