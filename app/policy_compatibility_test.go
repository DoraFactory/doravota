package app_test

import (
	"encoding/json"
	"testing"
	"time"

	"cosmossdk.io/log"
	sdkmath "cosmossdk.io/math"
	wasmkeeper "github.com/CosmWasm/wasmd/x/wasm/keeper"
	abci "github.com/cometbft/cometbft/abci/types"
	"github.com/cometbft/cometbft/crypto/ed25519"
	tmproto "github.com/cometbft/cometbft/proto/tendermint/types"
	tmtypes "github.com/cometbft/cometbft/types"
	dbm "github.com/cosmos/cosmos-db"
	"github.com/cosmos/cosmos-sdk/baseapp"
	simtestutil "github.com/cosmos/cosmos-sdk/testutil/sims"
	sdk "github.com/cosmos/cosmos-sdk/types"
	authtypes "github.com/cosmos/cosmos-sdk/x/auth/types"
	govkeeper "github.com/cosmos/cosmos-sdk/x/gov/keeper"
	govv1 "github.com/cosmos/cosmos-sdk/x/gov/types/v1"
	paramproposal "github.com/cosmos/cosmos-sdk/x/params/types/proposal"
	"github.com/cosmos/ibc-go/v10/modules/apps/transfer"
	clienttypes "github.com/cosmos/ibc-go/v10/modules/core/02-client/types"
	solomachine "github.com/cosmos/ibc-go/v10/modules/light-clients/06-solomachine"
	"github.com/stretchr/testify/require"

	"github.com/DoraFactory/doravota/app"
	"github.com/DoraFactory/doravota/app/legacyics29"
	upgrade "github.com/DoraFactory/doravota/app/upgrades/v0_5_0"
)

func policyTestApp(t *testing.T) *app.App {
	t.Helper()
	opts := simtestutil.AppOptionsMap{}
	db := dbm.NewMemDB()
	t.Cleanup(func() { require.NoError(t, db.Close()) })
	return app.New(log.NewNopLogger(), db, nil, true, map[int64]bool{},
		simulationHome(t, opts), 0, app.MakeEncodingConfig(), opts,
		simulationWasmOpts(t), baseapp.SetChainID("policy-test"))
}

// Exercise the real registered BaseApp handlers, not a copy of their logic.
func TestSDKProposalPolicyWithoutBridgeOverrides(t *testing.T) {
	for _, tc := range []struct {
		name string
		gas  *int64
		want int
	}{
		{"empty destination before migration", nil, 2},
		{"governed 600 million", int64Ptr(600_000_000), 1},
		{"legacy unlimited", int64Ptr(-1), 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := policyTestApp(t)
			ctx := a.NewUncachedContext(true, tmproto.Header{})
			if tc.gas != nil {
				cp := tmtypes.DefaultConsensusParams().ToProto()
				cp.Block.MaxGas = *tc.gas
				require.NoError(t, a.StoreConsensusParams(ctx, cp))
			}
			var txs [][]byte
			for _, gas := range []uint64{150_000_000, 500_000_000} {
				tx := a.TxConfig().NewTxBuilder()
				tx.SetGasLimit(gas)
				raw, err := a.TxConfig().TxEncoder()(tx.GetTx())
				require.NoError(t, err)
				txs = append(txs, raw)
			}
			response, err := a.PrepareProposal(&abci.RequestPrepareProposal{Height: 2, MaxTxBytes: 1_000_000, Txs: txs})
			require.NoError(t, err)
			require.Len(t, response.Txs, tc.want)
			// No 100M bridge ceiling; the first 150M transaction is included.
			require.Equal(t, txs[0], response.Txs[0])
			processed, err := a.ProcessProposal(&abci.RequestProcessProposal{Height: 2, Txs: response.Txs})
			require.NoError(t, err)
			require.Equal(t, abci.ResponseProcessProposal_ACCEPT, processed.Status)
			if tc.gas != nil {
				require.Equal(t, *tc.gas, a.GetConsensusParams(ctx).Block.MaxGas)
			}
		})
	}
}

func int64Ptr(n int64) *int64 { return &n }

func TestInitChainPreservesConsensusGas(t *testing.T) {
	for _, gas := range []int64{-1, 0, 600_000_000} {
		t.Run(sdkmath.NewInt(gas).String(), func(t *testing.T) {
			a := policyTestApp(t)
			pub := ed25519.GenPrivKey().PubKey()
			valSet := tmtypes.NewValidatorSet([]*tmtypes.Validator{tmtypes.NewValidator(pub, 1)})
			genesis, err := simtestutil.GenesisStateWithValSet(a.AppCodec(), app.NewDefaultGenesisState(a.AppCodec()), valSet,
				[]authtypes.GenesisAccount{authtypes.NewBaseAccountWithAddress(sdk.AccAddress(pub.Address()))})
			require.NoError(t, err)
			raw, err := json.Marshal(genesis)
			require.NoError(t, err)
			cp := tmtypes.DefaultConsensusParams().ToProto()
			cp.Block.MaxGas = gas
			response, err := a.InitChain(&abci.RequestInitChain{
				ChainId: "policy-test", InitialHeight: 1, Time: time.Unix(1_700_000_000, 0),
				ConsensusParams: &cp, AppStateBytes: raw,
			})
			require.NoError(t, err)
			require.Nil(t, response.ConsensusParams, "no application override of the supplied genesis consensus parameters")
			require.Equal(t, cp, a.GetConsensusParams(a.NewContext(false)))
		})
	}
}

// This invokes the pinned SDK's actual v4 -> v5 governance migration, then
// applies our approved choices. It is not a full mainnet-store upgrade drill.
func TestGovernanceSDKMigrationPreservesAllLegacyFields(t *testing.T) {
	a := policyTestApp(t)
	ctx := a.NewUncachedContext(false, tmproto.Header{})
	voting, deposit := 24*time.Hour, 24*time.Hour
	old := govv1.Params{
		MinDeposit:       sdk.NewCoins(sdk.NewCoin("peaka", sdkmath.NewInt(100_000).Mul(sdkmath.NewInt(1_000_000_000_000_000_000)))),
		MaxDepositPeriod: &deposit, VotingPeriod: &voting,
		Quorum: "0.334000000000000000", Threshold: "0.500000000000000000",
		VetoThreshold: "0.334000000000000000", MinInitialDepositRatio: "0.000000000000000000",
		BurnVoteQuorum: true, BurnProposalDepositPrevote: true, BurnVoteVeto: false,
	}
	require.NoError(t, a.GovKeeper.Params.Set(ctx, old))
	require.NoError(t, govkeeper.NewMigrator(&a.GovKeeper, a.GetSubspace("gov")).Migrate4to5(ctx))
	migrated, err := a.GovKeeper.Params.Get(ctx)
	require.NoError(t, err)
	require.Equal(t, "0.010000000000000000", migrated.MinDepositRatio)
	require.Equal(t, "0.500000000000000000", migrated.ProposalCancelRatio)
	approved, err := upgrade.ApprovedGovernanceParams(migrated)
	require.NoError(t, err)
	require.NoError(t, a.GovKeeper.Params.Set(ctx, approved))
	got, err := a.GovKeeper.Params.Get(ctx)
	require.NoError(t, err)
	require.NoError(t, got.ValidateBasic())
	require.Equal(t, "0.000000000000000000", got.MinDepositRatio)
	require.Equal(t, "0.000000000000000000", got.ProposalCancelRatio)
	require.Equal(t, "110000000000000000000000peaka", sdk.Coins(got.ExpeditedMinDeposit).String())
	require.Equal(t, 23*time.Hour, *got.ExpeditedVotingPeriod)
	require.Equal(t, "0.667000000000000000", got.ExpeditedThreshold)
	require.Empty(t, got.ProposalCancelDest)
	// Remove only the SDK-added fields; every old parameter must still match.
	got.ExpeditedMinDeposit = nil
	got.ExpeditedVotingPeriod = nil
	got.ExpeditedThreshold = ""
	got.ProposalCancelRatio = ""
	got.ProposalCancelDest = ""
	got.MinDepositRatio = ""
	require.Equal(t, old, got)
}

func TestBaselineIBCWiring(t *testing.T) {
	a := policyTestApp(t)
	ctx := a.NewUncachedContext(false, tmproto.Header{})
	a.IBCKeeper.ClientKeeper.SetParams(ctx, clienttypes.DefaultParams())
	route, err := a.IBCKeeper.ClientKeeper.Route(ctx, "06-solomachine-0")
	require.NoError(t, err)
	require.IsType(t, &solomachine.LightClientModule{}, route)
	transferRoute, found := a.IBCKeeper.PortKeeper.Router.Route("transfer")
	require.True(t, found)
	require.IsType(t, legacyics29.Middleware{}, transferRoute)
	require.IsType(t, transfer.IBCModule{}, transferRoute.(legacyics29.Middleware).IBCModule)
	require.True(t, a.IBCKeeper.PortKeeper.Router.HasRoute("wasm"))
	require.True(t, a.IBCKeeper.PortKeeper.Router.HasRoute("icahost"))
	require.True(t, a.IBCKeeper.PortKeeper.Router.HasRoute("icacontroller"))
	require.False(t, a.IBCKeeper.ChannelKeeperV2.Router.HasRoute("transfer"))
	require.False(t, a.IBCKeeper.ChannelKeeperV2.Router.HasRoute(wasmkeeper.PortIDPrefixV2+"contract"))
	require.NotContains(t, app.AllCapabilities(), "ibc2")
	require.Contains(t, app.AllCapabilities(), "cosmwasm_1_4")
	require.Equal(t, []string{"iterator", "staking", "stargate", "cosmwasm_1_1", "cosmwasm_1_2", "cosmwasm_1_3", "cosmwasm_1_4"}, app.AllCapabilities())
	feeAddr := authtypes.NewModuleAddress("feeibc")
	require.True(t, a.BankKeeper.BlockedAddr(feeAddr))
	require.NotContains(t, app.GetMaccPerms(), "feeibc")
}

func TestLegacyParameterProposalRouteRetained(t *testing.T) {
	a := policyTestApp(t)
	ctx := a.NewUncachedContext(true, tmproto.Header{})
	router := a.GovKeeper.LegacyRouter()
	require.True(t, router.HasRoute(paramproposal.RouterKey))
	proposal := paramproposal.NewParameterChangeProposal("legacy", "unsupported subspace returns the module error", []paramproposal.ParamChange{
		{Subspace: "missing-subspace", Key: "MissingKey", Value: "1"},
	})
	err := router.GetRoute(paramproposal.RouterKey)(ctx, proposal)
	require.ErrorIs(t, err, paramproposal.ErrUnknownSubspace)
}
