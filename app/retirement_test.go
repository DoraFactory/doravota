package app_test

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/DoraFactory/doravota/app/wasmarchive"
	"github.com/cometbft/cometbft/crypto/ed25519"
	tmtypes "github.com/cometbft/cometbft/types"
	codectypes "github.com/cosmos/cosmos-sdk/codec/types"
	simtestutil "github.com/cosmos/cosmos-sdk/testutil/sims"
	sdk "github.com/cosmos/cosmos-sdk/types"
	txtypes "github.com/cosmos/cosmos-sdk/types/tx"
	"google.golang.org/protobuf/proto"
	"testing"
	"time"

	"github.com/DoraFactory/doravota/app"
	abci "github.com/cometbft/cometbft/abci/types"
	tmproto "github.com/cometbft/cometbft/proto/tendermint/types"
	"github.com/cosmos/cosmos-sdk/types/module"
	authtypes "github.com/cosmos/cosmos-sdk/x/auth/types"
	channeltypes "github.com/cosmos/ibc-go/v11/modules/core/04-channel/types"
	"github.com/stretchr/testify/require"
)

func TestRetiredModulesAbsent(t *testing.T) {
	a := policyTestApp(t)
	require.NotContains(t, a.ModuleManager().Modules, "wasm")
	require.NotNil(t, a.GetKey("wasm"))
	require.NotContains(t, app.GetMaccPerms(), "wasm")
	require.True(t, a.BlockedModuleAccountAddrs()[authtypes.NewModuleAddress("wasm").String()])
	for _, name := range []string{"ibc", "transfer", "interchainaccounts"} {
		require.Contains(t, a.ModuleManager().Modules, name)
	}
	for _, url := range []string{"/cosmwasm.wasm.v1.MsgExecuteContract", "/cosmwasm.wasm.v1.MsgStoreCode", "/cosmwasm.wasm.v1.MsgMigrateContract"} {
		require.Nil(t, a.MsgServiceRouter().HandlerByTypeURL(url))
	}
	for _, url := range []string{"/ibc.applications.transfer.v1.MsgTransfer", "/ibc.core.channel.v1.MsgRecvPacket"} {
		require.NotNil(t, a.MsgServiceRouter().HandlerByTypeURL(url))
	}
}

func TestOldGenesisCannotSilentlyDiscardRetiredState(t *testing.T) {
	a := policyTestApp(t)
	state := app.NewDefaultGenesisState(a.AppCodec())
	state["wasm"] = json.RawMessage(`{"contracts":[{}]}`)
	raw, err := json.Marshal(state)
	require.NoError(t, err)
	_, err = a.InitChain(&abci.RequestInitChain{ChainId: "policy-test", AppStateBytes: raw})
	require.ErrorContains(t, err, "live wasm genesis is unsupported")
}

// Old clients may keep broadcasting retired messages. They must fail as
// transactions without aborting consensus or blocking unrelated blocks.
func TestRetiredTransactionsDoNotHaltBlocks(t *testing.T) {
	a := policyTestApp(t)
	pub := ed25519.GenPrivKey().PubKey()
	genesis, err := simtestutil.GenesisStateWithValSet(a.AppCodec(), app.NewDefaultGenesisState(a.AppCodec()),
		tmtypes.NewValidatorSet([]*tmtypes.Validator{tmtypes.NewValidator(pub, 1)}),
		[]authtypes.GenesisAccount{authtypes.NewBaseAccountWithAddress(sdk.AccAddress(pub.Address()))})
	require.NoError(t, err)
	genesis[wasmarchive.GenesisKey] = json.RawMessage(`{"entries":[{"key":"AwAB","value":"bGVnYWN5"}]}`)
	raw, err := json.Marshal(genesis)
	require.NoError(t, err)
	cp := tmtypes.DefaultConsensusParams().ToProto()
	stamp := time.Unix(1700000000, 0)
	_, err = a.InitChain(&abci.RequestInitChain{ChainId: "policy-test", InitialHeight: 1, Time: stamp, ConsensusParams: &cp, AppStateBytes: raw})
	require.NoError(t, err)
	var transactions [][]byte
	for _, url := range []string{"/cosmwasm.wasm.v1.MsgExecuteContract", "/cosmwasm.wasm.v1.MsgInstantiateContract", "/cosmos.group.v1.MsgCreateGroup"} {
		body, err := (&txtypes.TxBody{Messages: []*codectypes.Any{{TypeUrl: url, Value: []byte{}}}}).Marshal()
		require.NoError(t, err)
		tx, err := (&txtypes.TxRaw{BodyBytes: body, AuthInfoBytes: []byte{}}).Marshal()
		require.NoError(t, err)
		transactions = append(transactions, tx)
	}
	block, err := a.FinalizeBlock(&abci.RequestFinalizeBlock{Height: 1, Time: stamp.Add(time.Second), Txs: transactions})
	require.NoError(t, err)
	require.Len(t, block.TxResults, 3)
	for _, result := range block.TxResults {
		require.NotZero(t, result.Code)
	}
	_, err = a.Commit()
	require.NoError(t, err)
	_, err = a.FinalizeBlock(&abci.RequestFinalizeBlock{Height: 2, Time: stamp.Add(2 * time.Second)})
	require.NoError(t, err)
	_, err = a.Commit()
	require.NoError(t, err)
	for _, height := range []int64{1, 2} {
		request, err := proto.Marshal(&wasmarchive.GetRequest{Key: []byte{3, 0, 1}})
		require.NoError(t, err)
		response, err := a.Query(context.Background(), &abci.RequestQuery{Path: "/doravota.wasmarchive.v1.Query/Get", Data: request, Height: height})
		require.NoError(t, err)
		require.Zero(t, response.Code, response.Log)
		var decoded wasmarchive.GetResponse
		require.NoError(t, proto.Unmarshal(response.Value, &decoded))
		require.Equal(t, []byte("legacy"), decoded.Value)
		require.Equal(t, height, decoded.Height)
	}
	exported, err := a.ExportAppStateAndValidators(false, nil, nil)
	require.NoError(t, err)
	var state map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(exported.AppState, &state))
	require.JSONEq(t, string(genesis[wasmarchive.GenesisKey]), string(state[wasmarchive.GenesisKey]))
}

// A restored pre-retirement state must not execute blocks with the new rules.
func TestPreBlockRejectsUnactivatedRestoredState(t *testing.T) {
	a := policyTestApp(t)
	ctx := a.NewContextLegacy(true, tmproto.Header{Height: 12})
	require.NoError(t, a.UpgradeKeeper.SetModuleVersionMap(ctx, module.VersionMap{"wasm": 4}))
	_, err := a.PreBlocker(ctx, &abci.RequestFinalizeBlock{Height: 12})
	require.ErrorContains(t, err, "archive activation is required")
}

func TestRetirementClosesOnlyWasmChannelsAndPreservesPackets(t *testing.T) {
	a := policyTestApp(t)
	ctx := a.NewContextLegacy(true, tmproto.Header{Height: 12})
	k := a.IBCKeeper.ChannelKeeper
	store := ctx.KVStore(a.GetKey("ibc"))
	states := []channeltypes.State{channeltypes.INIT, channeltypes.TRYOPEN, channeltypes.OPEN, channeltypes.CLOSED}
	for i, state := range states {
		id := fmt.Sprintf("channel-%d", i)
		ch := channeltypes.Channel{State: state, Ordering: channeltypes.UNORDERED,
			Counterparty: channeltypes.Counterparty{PortId: "wasm.peer", ChannelId: "channel-7"}, ConnectionHops: []string{"connection-0"}, Version: "archive-test"}
		k.SetChannel(ctx, "wasm.contract", id, ch)
		for _, prefix := range []string{"commitments", "receipts", "acks"} {
			store.Set([]byte(prefix+"/ports/wasm.contract/channels/"+id+"/sequences/1"), []byte{1, 2, 3})
		}
	}
	for _, port := range []string{"transfer", "icahost", "icacontroller-owner"} {
		k.SetChannel(ctx, port, "channel-9", channeltypes.Channel{State: channeltypes.OPEN, Ordering: channeltypes.ORDERED, Version: "unchanged"})
	}
	wasmarchive.RetireChannels(ctx, k)
	for i := range states {
		id := fmt.Sprintf("channel-%d", i)
		ch, found := k.GetChannel(ctx, "wasm.contract", id)
		require.True(t, found)
		require.Equal(t, channeltypes.CLOSED, ch.State)
		require.Equal(t, "archive-test", ch.Version)
		require.Equal(t, []string{"connection-0"}, ch.ConnectionHops)
		require.Equal(t, "channel-7", ch.Counterparty.ChannelId)
		for _, prefix := range []string{"commitments", "receipts", "acks"} {
			require.Equal(t, []byte{1, 2, 3}, store.Get([]byte(prefix+"/ports/wasm.contract/channels/"+id+"/sequences/1")))
		}
	}
	for _, port := range []string{"transfer", "icahost", "icacontroller-owner"} {
		ch, _ := k.GetChannel(ctx, port, "channel-9")
		require.Equal(t, channeltypes.OPEN, ch.State)
		require.Equal(t, "unchanged", ch.Version)
	}
	require.Len(t, ctx.EventManager().Events(), 3)
	wasmarchive.RetireChannels(ctx, k)
	require.Len(t, ctx.EventManager().Events(), 3, "repeated retirement does not duplicate events")
}
