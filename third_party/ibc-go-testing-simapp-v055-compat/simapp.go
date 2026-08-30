// Package simapp is a narrow SDK v0.55 compatibility adapter for the IBC-Go
// v11 deterministic testing harness.
//
// IBC-Go v11.2's bundled SimApp still calls pre-v0.55 module constructors.
// The harness itself is compatible, so this package supplies only the three
// symbols it consumes and backs them with the real Dora application.
package simapp

import (
	"encoding/json"
	"io"
	"math/rand"
	"os"
	"testing"
	"time"

	"cosmossdk.io/log/v2"
	"github.com/CosmWasm/wasmd/x/wasm"
	abci "github.com/cometbft/cometbft/abci/types"
	dbm "github.com/cosmos/cosmos-db"
	"github.com/cosmos/cosmos-sdk/baseapp"
	"github.com/cosmos/cosmos-sdk/client"
	"github.com/cosmos/cosmos-sdk/client/flags"
	cryptotypes "github.com/cosmos/cosmos-sdk/crypto/types"
	servertypes "github.com/cosmos/cosmos-sdk/server/types"
	simtestutil "github.com/cosmos/cosmos-sdk/testutil/sims"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/stretchr/testify/require"

	"github.com/DoraFactory/doravota/app"
)

// SimApp embeds the production Dora app so the upstream testing package keeps
// its expected concrete type without introducing a second module graph.
type SimApp struct {
	*app.App
}

// NewSimApp preserves the constructor used by IBC-Go's fallback app creator.
// Dora-specific tests normally provide their own creator, but keeping this
// path functional avoids a compile-only shim.
func NewSimApp(
	logger log.Logger,
	database dbm.DB,
	traceStore io.Writer,
	loadLatest bool,
	appOpts servertypes.AppOptions,
) *SimApp {
	home, _ := appOpts.Get(flags.FlagHome).(string)
	if home == "" {
		var err error
		home, err = os.MkdirTemp("", "dora-ibc-simapp-")
		if err != nil {
			panic(err)
		}
	}
	chainApp := app.New(
		logger,
		database,
		traceStore,
		loadLatest,
		map[int64]bool{},
		home,
		0,
		app.MakeEncodingConfig(),
		appOpts,
		[]wasm.Option{},
	)
	return &SimApp{App: chainApp}
}

// DefaultGenesis returns the production module genesis used by Dora.
func (simApp *SimApp) DefaultGenesis() map[string]json.RawMessage {
	return app.NewDefaultGenesisState(simApp.App.AppCodec())
}

// SignAndDeliver is equivalent to the IBC-Go helper, but compiles against SDK
// v0.55. It signs the relayer message, encodes it through the Dora TxConfig and
// executes a real FinalizeBlock.
func SignAndDeliver(
	tb testing.TB,
	txConfig client.TxConfig,
	application *baseapp.BaseApp,
	messages []sdk.Msg,
	chainID string,
	accountNumbers, accountSequences []uint64,
	expectPass bool,
	blockTime time.Time,
	nextValidatorsHash []byte,
	privateKeys ...cryptotypes.PrivKey,
) (*abci.ResponseFinalizeBlock, error) {
	tb.Helper()
	transaction, err := simtestutil.GenSignedMockTx(
		rand.New(rand.NewSource(time.Now().UnixNano())),
		txConfig,
		messages,
		sdk.Coins{sdk.NewInt64Coin(sdk.DefaultBondDenom, 0)},
		simtestutil.DefaultGenTxGas,
		chainID,
		accountNumbers,
		accountSequences,
		privateKeys...,
	)
	require.NoError(tb, err)
	transactionBytes, err := txConfig.TxEncoder()(transaction)
	require.NoError(tb, err)
	_ = expectPass
	return application.FinalizeBlock(&abci.RequestFinalizeBlock{
		Height:             application.LastBlockHeight() + 1,
		Time:               blockTime,
		NextValidatorsHash: nextValidatorsHash,
		Txs:                [][]byte{transactionBytes},
	})
}
