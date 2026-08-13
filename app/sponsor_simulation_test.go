package app_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"cosmossdk.io/log/v2"
	tmproto "github.com/cometbft/cometbft/proto/tendermint/types"
	dbm "github.com/cosmos/cosmos-db"
	"github.com/cosmos/cosmos-sdk/baseapp"
	"github.com/cosmos/cosmos-sdk/client/flags"
	"github.com/cosmos/cosmos-sdk/server"
	simtestutil "github.com/cosmos/cosmos-sdk/testutil/sims"
	simtypes "github.com/cosmos/cosmos-sdk/types/simulation"
	"github.com/cosmos/cosmos-sdk/x/simulation"
	"github.com/stretchr/testify/require"

	"github.com/DoraFactory/doravota/app"
)

func TestSponsorSimulationExecutesStateTransitions(t *testing.T) {
	params := map[string]interface{}{
		"stake_per_account":                  "2000000000000000000",
		"initially_bonded_validators":        10,
		"op_weight_msg_store_code":           500,
		"op_weight_msg_instantiate_contract": 500,
		"op_weight_msg_update_admin":         0,
		"op_weight_msg_clear_admin":          0,
		"op_weight_msg_migrate_contract":     0,
		"op_weight_msg_set_sponsor":          1000,
		"op_weight_msg_update_sponsor":       0,
		"op_weight_msg_delete_sponsor":       0,
		"op_weight_sponsored_tx":             0,
		"op_weight_policy_check":             0,
		"op_weight_user_grant_usage":         0,
	}
	paramsJSON, err := json.Marshal(params)
	require.NoError(t, err)
	paramsPath := filepath.Join(t.TempDir(), "params.json")
	require.NoError(t, os.WriteFile(paramsPath, paramsJSON, 0o600))

	config := simtypes.Config{
		ParamsFile:         paramsPath,
		Seed:               7,
		GenesisTime:        1_700_000_000,
		InitialBlockHeight: 1,
		NumBlocks:          12,
		BlockSize:          12,
		ChainID:            "sponsor-transition-sim",
		Lean:               true,
		Commit:             true,
		AllInvariants:      true,
		BlockMaxGas:        -1,
	}

	db := dbm.NewMemDB()
	t.Cleanup(func() {
		require.NoError(t, db.Close())
	})
	appOptions := make(simtestutil.AppOptionsMap)
	appOptions[flags.FlagHome] = t.TempDir()
	appOptions[server.FlagInvCheckPeriod] = uint(1)
	chainApp := app.New(
		log.NewNopLogger(),
		db,
		nil,
		true,
		map[int64]bool{},
		t.TempDir(),
		1,
		app.MakeEncodingConfig(),
		appOptions,
		emptyWasmOpts,
		fauxMerkleModeOpt,
		baseapp.SetChainID(config.ChainID),
	)

	stopEarly, _, simErr := simulation.SimulateFromSeed(
		t,
		os.Stdout,
		chainApp.BaseApp,
		simtestutil.AppStateFn(
			chainApp.AppCodec(),
			chainApp.SimulationManager(),
			app.NewDefaultGenesisState(chainApp.AppCodec()),
		),
		simtypes.RandomAccounts,
		simtestutil.SimulationOperations(chainApp, chainApp.AppCodec(), config),
		chainApp.ModuleAccountAddrs(),
		config,
		chainApp.AppCodec(),
	)
	require.NoError(t, simErr)
	require.False(t, stopEarly)

	ctx := chainApp.NewUncachedContext(
		false,
		tmproto.Header{Height: chainApp.LastBlockHeight()},
	)
	sponsors := chainApp.SponsorKeeper.GetAllSponsors(ctx)
	require.NotEmpty(t, sponsors, "MsgSetSponsor simulation must mutate application state")
	for _, sponsor := range sponsors {
		require.NotZero(t, sponsor.Generation)
		require.NotEmpty(t, sponsor.SponsorAddress)
	}
}
