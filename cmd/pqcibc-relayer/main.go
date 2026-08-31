package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	sdkmath "cosmossdk.io/math"
	abci "github.com/cometbft/cometbft/abci/types"
	cmthttp "github.com/cometbft/cometbft/light/provider/http"
	rpchttp "github.com/cometbft/cometbft/rpc/client/http"
	coretypes "github.com/cometbft/cometbft/rpc/core/types"
	"github.com/cosmos/cosmos-sdk/client"
	"github.com/cosmos/cosmos-sdk/client/flags"
	clienttx "github.com/cosmos/cosmos-sdk/client/tx"
	"github.com/cosmos/cosmos-sdk/crypto/keyring"
	sdk "github.com/cosmos/cosmos-sdk/types"
	authtypes "github.com/cosmos/cosmos-sdk/x/auth/types"

	clienttypes "github.com/cosmos/ibc-go/v11/modules/core/02-client/types"
	channeltypes "github.com/cosmos/ibc-go/v11/modules/core/04-channel/types"
	commitmenttypes "github.com/cosmos/ibc-go/v11/modules/core/23-commitment/types"
	ibchost "github.com/cosmos/ibc-go/v11/modules/core/24-host"
	ibcclient "github.com/cosmos/ibc-go/v11/modules/core/client"
	ibctm "github.com/cosmos/ibc-go/v11/modules/light-clients/07-tendermint"

	"github.com/DoraFactory/doravota/app"
	"github.com/DoraFactory/doravota/pkg/pqcibc"
)

const defaultTxTimeout = 45 * time.Second

type chainConfig struct {
	ChainID string
	RPC     string
	Home    string
	Key     string
	Client  string
}

type runtime struct {
	config    chainConfig
	clientCtx client.Context
	rpc       *rpchttp.HTTP
}

type txRecord struct {
	ChainID string `json:"chain_id"`
	Hash    string `json:"hash"`
	Height  int64  `json:"height"`
	Code    uint32 `json:"code"`
	GasUsed int64  `json:"gas_used"`
}

type updateRecord struct {
	Skipped bool               `json:"skipped"`
	Client  string             `json:"client_id"`
	Target  int64              `json:"target_height"`
	Stats   pqcibc.HeaderStats `json:"header_stats"`
	Tx      *txRecord          `json:"tx,omitempty"`
}

type relayRecord struct {
	Packet                channeltypes.Packet `json:"packet"`
	DestinationUpdate     updateRecord        `json:"destination_client_update"`
	Receive               txRecord            `json:"receive"`
	SourceUpdate          updateRecord        `json:"source_client_update"`
	Acknowledgement       txRecord            `json:"acknowledgement"`
	AcknowledgementLength int                 `json:"acknowledgement_length"`
}

func main() {
	configureSDK()
	if len(os.Args) < 2 {
		fatalf("usage: pqcibc-relayer <update-client|relay-transfer> [flags]")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	var result any
	var err error
	switch os.Args[1] {
	case "update-client":
		result, err = runUpdateClient(ctx, os.Args[2:])
	case "relay-transfer":
		result, err = runRelayTransfer(ctx, os.Args[2:])
	default:
		err = fmt.Errorf("unknown command %q", os.Args[1])
	}
	if err != nil {
		fatalf("%v", err)
	}
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(result); err != nil {
		fatalf("encode result: %v", err)
	}
}

func runUpdateClient(ctx context.Context, args []string) (updateRecord, error) {
	set := flag.NewFlagSet("update-client", flag.ContinueOnError)
	set.SetOutput(io.Discard)
	source := addChainFlags(set, "source", false)
	destination := addChainFlags(set, "destination", true)
	targetHeight := set.Int64("target-height", 0, "source height to submit; zero uses latest")
	gas := set.Uint64("gas", 2_000_000, "transaction gas limit")
	fees := set.String("fees", "0stake", "transaction fees")
	if err := set.Parse(args); err != nil {
		return updateRecord{}, err
	}
	if err := source.validate(false); err != nil {
		return updateRecord{}, fmt.Errorf("source: %w", err)
	}
	if err := destination.validate(true); err != nil {
		return updateRecord{}, fmt.Errorf("destination: %w", err)
	}
	destinationRuntime, err := newRuntime(*destination)
	if err != nil {
		return updateRecord{}, err
	}
	return updateClient(ctx, *source, destinationRuntime, *targetHeight, *gas, *fees)
}

func runRelayTransfer(ctx context.Context, args []string) (relayRecord, error) {
	set := flag.NewFlagSet("relay-transfer", flag.ContinueOnError)
	set.SetOutput(io.Discard)
	source := addChainFlags(set, "source", true)
	destination := addChainFlags(set, "destination", true)
	txHash := set.String("tx-hash", "", "source MsgTransfer transaction hash")
	gas := set.Uint64("gas", 2_000_000, "transaction gas limit")
	fees := set.String("fees", "0stake", "transaction fees")
	if err := set.Parse(args); err != nil {
		return relayRecord{}, err
	}
	if err := source.validate(true); err != nil {
		return relayRecord{}, fmt.Errorf("source: %w", err)
	}
	if err := destination.validate(true); err != nil {
		return relayRecord{}, fmt.Errorf("destination: %w", err)
	}
	if *txHash == "" {
		return relayRecord{}, errors.New("tx-hash is required")
	}
	sourceRuntime, err := newRuntime(*source)
	if err != nil {
		return relayRecord{}, err
	}
	destinationRuntime, err := newRuntime(*destination)
	if err != nil {
		return relayRecord{}, err
	}

	sendResult, err := queryTx(ctx, sourceRuntime.rpc, *txHash)
	if err != nil {
		return relayRecord{}, fmt.Errorf("query source transfer: %w", err)
	}
	packet, err := packetFromEvents(sendResult.TxResult.Events)
	if err != nil {
		return relayRecord{}, err
	}

	sourceProofHeight, err := waitForHeight(ctx, sourceRuntime.rpc, sendResult.Height+1, defaultTxTimeout)
	if err != nil {
		return relayRecord{}, err
	}
	destinationUpdate, err := updateClient(ctx, *source, destinationRuntime, sourceProofHeight, *gas, *fees)
	if err != nil {
		return relayRecord{}, fmt.Errorf("update destination client: %w", err)
	}
	commitment, proof, proofHeight, err := queryProof(
		sourceRuntime,
		sourceProofHeight,
		ibchost.PacketCommitmentKey(packet.SourcePort, packet.SourceChannel, packet.Sequence),
	)
	if err != nil {
		return relayRecord{}, fmt.Errorf("packet commitment proof: %w", err)
	}
	if len(commitment) == 0 {
		return relayRecord{}, errors.New("packet commitment does not exist")
	}
	receiveMessage := channeltypes.NewMsgRecvPacket(packet, proof, proofHeight, destinationRuntime.clientCtx.FromAddress.String())
	receiveResult, err := destinationRuntime.broadcast(ctx, *gas, *fees, receiveMessage)
	if err != nil {
		return relayRecord{}, fmt.Errorf("broadcast receive packet: %w", err)
	}
	acknowledgement, err := acknowledgementFromEvents(receiveResult.TxResult.Events)
	if err != nil {
		return relayRecord{}, err
	}

	destinationProofHeight, err := waitForHeight(ctx, destinationRuntime.rpc, receiveResult.Height+1, defaultTxTimeout)
	if err != nil {
		return relayRecord{}, err
	}
	sourceUpdate, err := updateClient(ctx, *destination, sourceRuntime, destinationProofHeight, *gas, *fees)
	if err != nil {
		return relayRecord{}, fmt.Errorf("update source client: %w", err)
	}
	ackValue, ackProof, ackProofHeight, err := queryProof(
		destinationRuntime,
		destinationProofHeight,
		ibchost.PacketAcknowledgementKey(packet.DestinationPort, packet.DestinationChannel, packet.Sequence),
	)
	if err != nil {
		return relayRecord{}, fmt.Errorf("acknowledgement proof: %w", err)
	}
	if len(ackValue) == 0 {
		return relayRecord{}, errors.New("acknowledgement commitment does not exist")
	}
	ackMessage := channeltypes.NewMsgAcknowledgement(
		packet,
		acknowledgement,
		ackProof,
		ackProofHeight,
		sourceRuntime.clientCtx.FromAddress.String(),
	)
	ackResult, err := sourceRuntime.broadcast(ctx, *gas, *fees, ackMessage)
	if err != nil {
		return relayRecord{}, fmt.Errorf("broadcast acknowledgement: %w", err)
	}

	return relayRecord{
		Packet:                packet,
		DestinationUpdate:     destinationUpdate,
		Receive:               txRecordFromResult(destination.ChainID, receiveResult),
		SourceUpdate:          sourceUpdate,
		Acknowledgement:       txRecordFromResult(source.ChainID, ackResult),
		AcknowledgementLength: len(acknowledgement),
	}, nil
}

func addChainFlags(set *flag.FlagSet, prefix string, includeSigner bool) *chainConfig {
	config := &chainConfig{}
	set.StringVar(&config.ChainID, prefix+"-chain-id", "", prefix+" chain ID")
	set.StringVar(&config.RPC, prefix+"-rpc", "", prefix+" CometBFT RPC URL")
	set.StringVar(&config.Client, prefix+"-client-id", "", "client on "+prefix+" tracking its counterparty")
	if includeSigner {
		set.StringVar(&config.Home, prefix+"-home", "", prefix+" keyring directory")
		set.StringVar(&config.Key, prefix+"-key", "", prefix+" native ML-DSA relayer key")
	}
	return config
}

func (config chainConfig) validate(requireSigner bool) error {
	if config.ChainID == "" || config.RPC == "" {
		return errors.New("chain-id and rpc are required")
	}
	if requireSigner && (config.Home == "" || config.Key == "" || config.Client == "") {
		return errors.New("home, key and client-id are required")
	}
	return nil
}

func newRuntime(config chainConfig) (*runtime, error) {
	encoding := app.MakeEncodingConfig()
	rpcClient, err := rpchttp.New(config.RPC, "/websocket")
	if err != nil {
		return nil, fmt.Errorf("create RPC client for %s: %w", config.ChainID, err)
	}
	keybase, err := keyring.New(
		sdk.KeyringServiceName(),
		keyring.BackendTest,
		config.Home,
		nil,
		encoding.Marshaler,
		pqcibc.KeyringOption(nil, nil),
	)
	if err != nil {
		return nil, fmt.Errorf("open keyring for %s: %w", config.ChainID, err)
	}
	record, err := keybase.Key(config.Key)
	if err != nil {
		return nil, fmt.Errorf("load relayer key %q: %w", config.Key, err)
	}
	publicKey, err := record.GetPubKey()
	if err != nil {
		return nil, err
	}
	if publicKey.Type() != "ml_dsa_65" {
		return nil, fmt.Errorf("relayer key %q uses %q, expected ml_dsa_65", config.Key, publicKey.Type())
	}
	address, err := record.GetAddress()
	if err != nil {
		return nil, err
	}
	clientCtx := client.Context{}.
		WithCodec(encoding.Marshaler).
		WithInterfaceRegistry(encoding.InterfaceRegistry).
		WithTxConfig(encoding.TxConfig).
		WithLegacyAmino(encoding.Amino).
		WithAccountRetriever(authtypes.AccountRetriever{}).
		WithKeyring(keybase).
		WithKeyringDir(config.Home).
		WithFromName(config.Key).
		WithFromAddress(address).
		WithChainID(config.ChainID).
		WithNodeURI(config.RPC).
		WithClient(rpcClient).
		WithBroadcastMode(flags.BroadcastSync).
		WithSkipConfirmation(true).
		WithOutputFormat("json")
	return &runtime{config: config, clientCtx: clientCtx, rpc: rpcClient}, nil
}

func updateClient(
	ctx context.Context,
	source chainConfig,
	destination *runtime,
	targetHeight int64,
	gas uint64,
	fees string,
) (updateRecord, error) {
	clientStateResponse, err := clienttypes.NewQueryClient(destination.clientCtx).ClientState(
		ctx,
		&clienttypes.QueryClientStateRequest{ClientId: destination.config.Client},
	)
	if err != nil {
		return updateRecord{}, fmt.Errorf("query client %s: %w", destination.config.Client, err)
	}
	unpacked, err := clienttypes.UnpackClientState(clientStateResponse.ClientState)
	if err != nil {
		return updateRecord{}, err
	}
	tendermintState, ok := unpacked.(*ibctm.ClientState)
	if !ok {
		return updateRecord{}, fmt.Errorf("client %s is not a 07-tendermint client", destination.config.Client)
	}
	trustedHeight := tendermintState.LatestHeight
	if targetHeight == 0 {
		rpcClient, err := rpchttp.New(source.RPC, "/websocket")
		if err != nil {
			return updateRecord{}, err
		}
		targetHeight, err = latestHeight(ctx, rpcClient)
		if err != nil {
			return updateRecord{}, err
		}
	}
	record := updateRecord{Client: destination.config.Client, Target: targetHeight}
	if trustedHeight.RevisionHeight >= uint64(targetHeight) {
		record.Skipped = true
		return record, nil
	}
	provider, err := cmthttp.New(source.ChainID, source.RPC)
	if err != nil {
		return updateRecord{}, fmt.Errorf("create source light provider: %w", err)
	}
	header, stats, err := pqcibc.BuildUpdateHeaderFromSource(
		ctx,
		provider,
		targetHeight,
		trustedHeight,
		pqcibc.DefaultHeaderLimits(),
	)
	if err != nil {
		return updateRecord{}, err
	}
	message, err := clienttypes.NewMsgUpdateClient(
		destination.config.Client,
		header,
		destination.clientCtx.FromAddress.String(),
	)
	if err != nil {
		return updateRecord{}, err
	}
	result, err := destination.broadcast(ctx, gas, fees, message)
	if err != nil {
		return updateRecord{}, err
	}
	tx := txRecordFromResult(destination.config.ChainID, result)
	record.Stats = stats
	record.Tx = &tx
	return record, nil
}

func (runtime *runtime) broadcast(ctx context.Context, gas uint64, fees string, messages ...sdk.Msg) (*coretypes.ResultTx, error) {
	factory := clienttx.Factory{}.
		WithTxConfig(runtime.clientCtx.TxConfig).
		WithAccountRetriever(runtime.clientCtx.AccountRetriever).
		WithKeybase(runtime.clientCtx.Keyring).
		WithChainID(runtime.config.ChainID).
		WithFromName(runtime.config.Key).
		WithGas(gas).
		WithFees(fees)
	prepared, err := factory.Prepare(runtime.clientCtx)
	if err != nil {
		return nil, err
	}
	builder, err := prepared.BuildUnsignedTx(messages...)
	if err != nil {
		return nil, err
	}
	if err := clienttx.Sign(ctx, prepared, runtime.config.Key, builder, true); err != nil {
		return nil, err
	}
	txBytes, err := runtime.clientCtx.TxConfig.TxEncoder()(builder.GetTx())
	if err != nil {
		return nil, err
	}
	response, err := runtime.clientCtx.BroadcastTx(txBytes)
	if err != nil {
		return nil, err
	}
	if response.Code != 0 {
		return nil, fmt.Errorf("CheckTx rejected transaction code=%d codespace=%s raw_log=%s", response.Code, response.Codespace, response.RawLog)
	}
	return waitForTx(ctx, runtime.rpc, response.TxHash, defaultTxTimeout)
}

func queryProof(runtime *runtime, height int64, key []byte) ([]byte, []byte, clienttypes.Height, error) {
	queryContext := runtime.clientCtx.WithHeight(height)
	value, proof, proofHeight, err := ibcclient.QueryTendermintProof(queryContext, key)
	if err != nil {
		return nil, nil, clienttypes.Height{}, err
	}
	var merkleProof commitmenttypes.MerkleProof
	if err := queryContext.Codec.Unmarshal(proof, &merkleProof); err != nil {
		return nil, nil, clienttypes.Height{}, fmt.Errorf("decode generated proof: %w", err)
	}
	return value, proof, proofHeight, nil
}

func queryTx(ctx context.Context, rpc *rpchttp.HTTP, hash string) (*coretypes.ResultTx, error) {
	decoded, err := hex.DecodeString(strings.TrimPrefix(hash, "0x"))
	if err != nil {
		return nil, err
	}
	return rpc.Tx(ctx, decoded, false)
}

func waitForTx(ctx context.Context, rpc *rpchttp.HTTP, hash string, timeout time.Duration) (*coretypes.ResultTx, error) {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		result, err := queryTx(ctx, rpc, hash)
		if err == nil {
			if result.TxResult.Code != 0 {
				return nil, fmt.Errorf("DeliverTx failed code=%d codespace=%s log=%s", result.TxResult.Code, result.TxResult.Codespace, result.TxResult.Log)
			}
			return result, nil
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(300 * time.Millisecond):
		}
	}
	return nil, fmt.Errorf("transaction %s was not committed within %s", hash, timeout)
}

func latestHeight(ctx context.Context, rpc *rpchttp.HTTP) (int64, error) {
	status, err := rpc.Status(ctx)
	if err != nil {
		return 0, err
	}
	if status.SyncInfo.LatestBlockHeight <= 0 {
		return 0, errors.New("chain has no committed blocks")
	}
	return status.SyncInfo.LatestBlockHeight, nil
}

// waitForHeight waits for the block after a state-changing transaction. IBC
// proof queries at Tendermint height H read the application state at H-1, so a
// packet committed in block H must be proven against a header at H+1 or later.
func waitForHeight(ctx context.Context, rpc *rpchttp.HTTP, minimum int64, timeout time.Duration) (int64, error) {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		height, err := latestHeight(ctx, rpc)
		if err == nil && height >= minimum {
			return height, nil
		}
		select {
		case <-ctx.Done():
			return 0, ctx.Err()
		case <-time.After(300 * time.Millisecond):
		}
	}
	return 0, fmt.Errorf("chain did not reach proof height %d within %s", minimum, timeout)
}

func packetFromEvents(events []abci.Event) (channeltypes.Packet, error) {
	attributes, err := eventAttributes(events, channeltypes.EventTypeSendPacket)
	if err != nil {
		return channeltypes.Packet{}, err
	}
	sequence, err := strconv.ParseUint(attributes[channeltypes.AttributeKeySequence], 10, 64)
	if err != nil {
		return channeltypes.Packet{}, fmt.Errorf("parse packet sequence: %w", err)
	}
	data, err := hex.DecodeString(attributes[channeltypes.AttributeKeyDataHex])
	if err != nil {
		return channeltypes.Packet{}, fmt.Errorf("decode packet data: %w", err)
	}
	timeoutHeight, err := clienttypes.ParseHeight(attributes[channeltypes.AttributeKeyTimeoutHeight])
	if err != nil {
		return channeltypes.Packet{}, fmt.Errorf("parse timeout height: %w", err)
	}
	timeoutTimestamp, err := strconv.ParseUint(attributes[channeltypes.AttributeKeyTimeoutTimestamp], 10, 64)
	if err != nil {
		return channeltypes.Packet{}, fmt.Errorf("parse timeout timestamp: %w", err)
	}
	packet := channeltypes.NewPacket(
		data,
		sequence,
		attributes[channeltypes.AttributeKeySrcPort],
		attributes[channeltypes.AttributeKeySrcChannel],
		attributes[channeltypes.AttributeKeyDstPort],
		attributes[channeltypes.AttributeKeyDstChannel],
		timeoutHeight,
		timeoutTimestamp,
	)
	if err := packet.ValidateBasic(); err != nil {
		return channeltypes.Packet{}, err
	}
	return packet, nil
}

func acknowledgementFromEvents(events []abci.Event) ([]byte, error) {
	attributes, err := eventAttributes(events, channeltypes.EventTypeWriteAck)
	if err != nil {
		return nil, err
	}
	acknowledgement, err := hex.DecodeString(attributes[channeltypes.AttributeKeyAckHex])
	if err != nil {
		return nil, fmt.Errorf("decode acknowledgement: %w", err)
	}
	if len(acknowledgement) == 0 {
		return nil, errors.New("empty acknowledgement")
	}
	return acknowledgement, nil
}

func eventAttributes(events []abci.Event, eventType string) (map[string]string, error) {
	for _, event := range events {
		if event.Type != eventType {
			continue
		}
		attributes := make(map[string]string, len(event.Attributes))
		for _, attribute := range event.Attributes {
			attributes[attribute.Key] = attribute.Value
		}
		return attributes, nil
	}
	return nil, fmt.Errorf("transaction contains no %s event", eventType)
}

func txRecordFromResult(chainID string, result *coretypes.ResultTx) txRecord {
	return txRecord{
		ChainID: chainID,
		Hash:    strings.ToUpper(hex.EncodeToString(result.Hash)),
		Height:  result.Height,
		Code:    result.TxResult.Code,
		GasUsed: result.TxResult.GasUsed,
	}
}

func configureSDK() {
	config := sdk.GetConfig()
	config.SetBech32PrefixForAccount(app.Bech32PrefixAccAddr, app.Bech32PrefixAccPub)
	config.SetBech32PrefixForValidator(app.Bech32PrefixValAddr, app.Bech32PrefixValPub)
	config.SetBech32PrefixForConsensusNode(app.Bech32PrefixConsAddr, app.Bech32PrefixConsPub)
	if err := sdk.RegisterDenom("DORA", sdkmath.LegacyOneDec()); err != nil {
		panic(err)
	}
	if err := sdk.RegisterDenom("peaka", sdkmath.LegacyNewDecWithPrec(1, 18)); err != nil {
		panic(err)
	}
	sdk.DefaultBondDenom = "peaka"
	config.Seal()
}

func fatalf(format string, arguments ...any) {
	fmt.Fprintf(os.Stderr, "pqcibc-relayer: "+format+"\n", arguments...)
	os.Exit(1)
}
