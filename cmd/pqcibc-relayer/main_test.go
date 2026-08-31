package main

import (
	"encoding/hex"
	"flag"
	"io"
	"testing"

	abci "github.com/cometbft/cometbft/abci/types"
	"github.com/stretchr/testify/require"

	clienttypes "github.com/cosmos/ibc-go/v11/modules/core/02-client/types"
	channeltypes "github.com/cosmos/ibc-go/v11/modules/core/04-channel/types"
)

func TestAddChainFlagsUpdatesReturnedConfig(t *testing.T) {
	set := flag.NewFlagSet("chain", flag.ContinueOnError)
	set.SetOutput(io.Discard)
	config := addChainFlags(set, "source", true)

	err := set.Parse([]string{
		"--source-chain-id", "dora-pqc-1",
		"--source-rpc", "http://127.0.0.1:26657",
		"--source-home", "/tmp/source",
		"--source-key", "relayer",
		"--source-client-id", "07-tendermint-0",
	})
	require.NoError(t, err)
	require.Equal(t, "dora-pqc-1", config.ChainID)
	require.Equal(t, "http://127.0.0.1:26657", config.RPC)
	require.Equal(t, "/tmp/source", config.Home)
	require.Equal(t, "relayer", config.Key)
	require.Equal(t, "07-tendermint-0", config.Client)
}

func TestPacketFromEvents(t *testing.T) {
	data := []byte(`{"denom":"stake","amount":"7"}`)
	events := []abci.Event{{
		Type: channeltypes.EventTypeSendPacket,
		Attributes: []abci.EventAttribute{
			{Key: channeltypes.AttributeKeySequence, Value: "3"},
			{Key: channeltypes.AttributeKeySrcPort, Value: "transfer"},
			{Key: channeltypes.AttributeKeySrcChannel, Value: "channel-0"},
			{Key: channeltypes.AttributeKeyDstPort, Value: "transfer"},
			{Key: channeltypes.AttributeKeyDstChannel, Value: "channel-1"},
			{Key: channeltypes.AttributeKeyDataHex, Value: hex.EncodeToString(data)},
			{Key: channeltypes.AttributeKeyTimeoutHeight, Value: "1-99"},
			{Key: channeltypes.AttributeKeyTimeoutTimestamp, Value: "1234"},
		},
	}}

	packet, err := packetFromEvents(events)
	require.NoError(t, err)
	require.Equal(t, uint64(3), packet.Sequence)
	require.Equal(t, data, packet.Data)
	require.Equal(t, clienttypes.NewHeight(1, 99), packet.TimeoutHeight)
	require.Equal(t, uint64(1234), packet.TimeoutTimestamp)
}

func TestAcknowledgementFromEvents(t *testing.T) {
	want := []byte(`{"result":"AQ=="}`)
	events := []abci.Event{{
		Type: channeltypes.EventTypeWriteAck,
		Attributes: []abci.EventAttribute{{
			Key:   channeltypes.AttributeKeyAckHex,
			Value: hex.EncodeToString(want),
		}},
	}}

	got, err := acknowledgementFromEvents(events)
	require.NoError(t, err)
	require.Equal(t, want, got)
}

func TestPacketFromEventsRejectsMissingSendEvent(t *testing.T) {
	_, err := packetFromEvents(nil)
	require.ErrorContains(t, err, channeltypes.EventTypeSendPacket)
}
