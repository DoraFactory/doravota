//go:build pqcibc_e2e

package app_test

import (
	"encoding/json"
	"strings"
	"testing"

	"cosmossdk.io/log/v2"
	sdkmath "cosmossdk.io/math"
	"github.com/CosmWasm/wasmd/x/wasm"
	cmtmldsa65 "github.com/cometbft/cometbft/crypto/mldsa65"
	cmttypes "github.com/cometbft/cometbft/types"
	dbm "github.com/cosmos/cosmos-db"
	"github.com/cosmos/cosmos-sdk/client/flags"
	sdkmldsa65 "github.com/cosmos/cosmos-sdk/crypto/keys/mldsa65"
	"github.com/cosmos/cosmos-sdk/server"
	servertypes "github.com/cosmos/cosmos-sdk/server/types"
	simtestutil "github.com/cosmos/cosmos-sdk/testutil/sims"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/stretchr/testify/require"

	transfertypes "github.com/cosmos/ibc-go/v11/modules/apps/transfer/types"
	clienttypes "github.com/cosmos/ibc-go/v11/modules/core/02-client/types"
	ibctesting "github.com/cosmos/ibc-go/v11/testing"

	"github.com/DoraFactory/doravota/app"
)

// TestPQCIBCTwoChainCompatibility is the deterministic P0 compatibility gate:
// it runs two real Dora applications, creates a 07-tendermint client pair, an
// IBC connection and an ICS-20 channel, then keeps the original clients alive
// while each source validator set rotates from Ed25519 to ML-DSA-65.
func TestPQCIBCTwoChainCompatibility(t *testing.T) {
	coordinator := ibctesting.NewCustomAppCoordinator(t, 2, doraIBCAppCreator(t))
	chainA := coordinator.GetChain(ibctesting.GetChainID(1))
	chainB := coordinator.GetChain(ibctesting.GetChainID(2))
	useNativeMLDSA65RelayerAccount(t, coordinator, chainA)
	useNativeMLDSA65RelayerAccount(t, coordinator, chainB)
	path := ibctesting.NewTransferPath(chainA, chainB)
	path.Setup()

	relayTransfer(t, path, chainA, chainB, sdk.NewInt64Coin(sdk.DefaultBondDenom, 111))

	rotateTestChainToMLDSA65(t, coordinator, chainA, path.EndpointB)
	require.NoError(t, path.EndpointB.UpdateClient(), "existing chain-B client must cross chain-A validator-key rotation")
	assertMLDSA65ValidatorSet(t, chainA)
	relayTransfer(t, path, chainA, chainB, sdk.NewInt64Coin(sdk.DefaultBondDenom, 222))

	rotateTestChainToMLDSA65(t, coordinator, chainB, path.EndpointA)
	require.NoError(t, path.EndpointA.UpdateClient(), "existing chain-A client must cross chain-B validator-key rotation")
	assertMLDSA65ValidatorSet(t, chainB)

	chainBApp, ok := chainB.App.(*app.App)
	require.True(t, ok)
	chainBBalances := chainBApp.BankKeeper.GetAllBalances(chainB.GetContext(), chainB.SenderAccount.GetAddress())
	var voucherDenom string
	for _, balance := range chainBBalances {
		if strings.HasPrefix(balance.Denom, "ibc/") && balance.Amount.GTE(sdkmath.NewInt(100)) {
			voucherDenom = balance.Denom
			break
		}
	}
	require.NotEmpty(t, voucherDenom, "chain B must hold the voucher minted by the A-to-B transfers")
	chainBVoucher := sdk.NewCoin(voucherDenom, sdkmath.NewInt(100))
	relayTransfer(t, path.Reversed(), chainB, chainA, chainBVoucher)

	latestA, ok := path.EndpointA.GetClientLatestHeight().(clienttypes.Height)
	require.True(t, ok)
	latestB, ok := path.EndpointB.GetClientLatestHeight().(clienttypes.Height)
	require.True(t, ok)
	require.Greater(t, latestA.RevisionHeight, uint64(1))
	require.Greater(t, latestB.RevisionHeight, uint64(1))
}

// useNativeMLDSA65RelayerAccount replaces the harness' classic sender with a
// funded native ML-DSA-65 account. Consequently every create/update client,
// connection/channel handshake, recv-packet and acknowledgement transaction
// in this test passes through Dora Ante with an actual PQC account signature.
func useNativeMLDSA65RelayerAccount(
	t *testing.T,
	coordinator *ibctesting.Coordinator,
	chain *ibctesting.TestChain,
) {
	t.Helper()
	chainApp, ok := chain.App.(*app.App)
	require.True(t, ok)
	privateKey, err := sdkmldsa65.GenPrivKey()
	require.NoError(t, err)
	address := sdk.AccAddress(privateKey.PubKey().Address())
	context := chain.GetContext()
	account := chainApp.AccountKeeper.NewAccountWithAddress(context, address)
	require.NoError(t, account.SetPubKey(privateKey.PubKey()))
	chainApp.AccountKeeper.SetAccount(context, account)
	require.NoError(t, chainApp.BankKeeper.SendCoins(
		context,
		chain.SenderAccount.GetAddress(),
		address,
		sdk.NewCoins(sdk.NewInt64Coin(sdk.DefaultBondDenom, 1_000_000_000)),
	))
	chain.SenderPrivKey = &privateKey
	chain.SenderAccount = account
	coordinator.CommitBlock(chain)
}

func doraIBCAppCreator(t *testing.T) ibctesting.AppCreator {
	t.Helper()
	return func() (ibctesting.TestingApp, map[string]json.RawMessage) {
		database := dbm.NewMemDB()
		t.Cleanup(func() { require.NoError(t, database.Close()) })
		home := t.TempDir()
		appOptions := make(simtestutil.AppOptionsMap)
		appOptions[flags.FlagHome] = home
		appOptions[server.FlagInvCheckPeriod] = uint(0)
		chainApp := app.New(
			log.NewNopLogger(),
			database,
			nil,
			true,
			map[int64]bool{},
			home,
			0,
			app.MakeEncodingConfig(),
			servertypes.AppOptions(appOptions),
			[]wasm.Option{},
		)
		return chainApp, app.NewDefaultGenesisState(chainApp.AppCodec())
	}
}

func rotateTestChainToMLDSA65(
	t *testing.T,
	coordinator *ibctesting.Coordinator,
	chain *ibctesting.TestChain,
	counterpartyEndpoint *ibctesting.Endpoint,
) {
	t.Helper()
	validators := make([]*cmttypes.Validator, 0, len(chain.Vals.Validators))
	for range len(chain.Vals.Validators) {
		privateKey, err := cmtmldsa65.GenPrivKey()
		require.NoError(t, err)
		privateValidator := cmttypes.NewMockPVWithParams(privateKey, false, false)
		publicKey, err := privateValidator.GetPubKey()
		require.NoError(t, err)
		validators = append(validators, cmttypes.NewValidator(publicKey, 1))
		chain.Signers[publicKey.Address().String()] = privateValidator
	}

	// CometBFT applies validator updates returned at H to H+2. The transition
	// block is signed by the old set and commits the new NextValidatorsHash;
	// the following block is the first one signed by ML-DSA-65.
	newSet := cmttypes.NewValidatorSet(validators)
	chain.NextVals = newSet
	chain.ProposedHeader.NextValidatorsHash = newSet.Hash()
	coordinator.CommitBlock(chain)
	updateClientFromLatestCommittedHeader(t, counterpartyEndpoint)
	coordinator.CommitBlock(chain)
}

// updateClientFromLatestCommittedHeader relays the transition header before
// the first all-ML-DSA commit. This is a production requirement when the old
// and new validator sets have no overlap: skipping the transition would leave
// the light client without one-third trusted voting power in the new set.
func updateClientFromLatestCommittedHeader(t *testing.T, endpoint *ibctesting.Endpoint) {
	t.Helper()
	trustedHeight, ok := endpoint.GetClientLatestHeight().(clienttypes.Height)
	require.True(t, ok)
	header, err := endpoint.Counterparty.Chain.IBCClientHeader(
		endpoint.Counterparty.Chain.LatestCommittedHeader,
		trustedHeight,
	)
	require.NoError(t, err)
	message, err := clienttypes.NewMsgUpdateClient(
		endpoint.ClientID,
		header,
		endpoint.Chain.SenderAccount.GetAddress().String(),
	)
	require.NoError(t, err)
	_, err = endpoint.Chain.SendMsgs(message)
	require.NoError(t, err, "relayer must submit the old-signed transition header before all validators use ML-DSA-65")
}

func relayTransfer(
	t *testing.T,
	path *ibctesting.Path,
	source *ibctesting.TestChain,
	destination *ibctesting.TestChain,
	coin sdk.Coin,
) {
	t.Helper()
	destinationApp, ok := destination.App.(*app.App)
	require.True(t, ok)
	receiver := destination.SenderAccount.GetAddress()
	before := destinationApp.BankKeeper.GetAllBalances(destination.GetContext(), receiver)

	message := transfertypes.NewMsgTransfer(
		path.EndpointA.ChannelConfig.PortID,
		path.EndpointA.ChannelID,
		coin,
		source.SenderAccount.GetAddress().String(),
		receiver.String(),
		destination.GetTimeoutHeight(),
		destination.GetTimeoutTimestamp(),
		"",
	)
	result, err := source.SendMsgs(message)
	require.NoError(t, err)
	packet, err := ibctesting.ParsePacketFromEvents(result.Events)
	require.NoError(t, err)
	require.NoError(t, path.RelayPacket(packet))

	after := destinationApp.BankKeeper.GetAllBalances(destination.GetContext(), receiver)
	require.False(t, after.Equal(before), "successful ICS-20 relay must change destination balance")
}

func assertMLDSA65ValidatorSet(t *testing.T, chain *ibctesting.TestChain) {
	t.Helper()
	require.NotEmpty(t, chain.Vals.Validators)
	for _, validator := range chain.Vals.Validators {
		require.Equal(t, cmtmldsa65.KeyType, validator.PubKey.Type())
	}
	require.NotNil(t, chain.LatestCommittedHeader)
	require.Len(t, chain.LatestCommittedHeader.Commit.Signatures, len(chain.Vals.Validators))
}
