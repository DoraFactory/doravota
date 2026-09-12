package cmd

import (
	"encoding/json"
	"fmt"
	"math"
	"testing"
	"time"

	"cosmossdk.io/log"
	"github.com/DoraFactory/doravota/app"
	abci "github.com/cometbft/cometbft/abci/types"
	"github.com/cometbft/cometbft/crypto/ed25519"
	tmtypes "github.com/cometbft/cometbft/types"
	dbm "github.com/cosmos/cosmos-db"
	"github.com/cosmos/cosmos-sdk/client/flags"
	"github.com/cosmos/cosmos-sdk/server"
	simtestutil "github.com/cosmos/cosmos-sdk/testutil/sims"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/cosmos/cosmos-sdk/types/mempool"
	authtypes "github.com/cosmos/cosmos-sdk/x/auth/types"
	"github.com/stretchr/testify/require"
)

// Use the daemon's real creator: app.New by itself bypasses config wiring.
func TestDaemonQueryGasLimitConfiguration(t *testing.T) {
	initSDKConfig()
	for _, limit := range []uint64{0, 12345} {
		t.Run(fmt.Sprint(limit), func(t *testing.T) {
			opts := simtestutil.AppOptionsMap{
				flags.FlagHome: t.TempDir(), flags.FlagChainID: "config-audit",
				server.FlagPruning: "default", server.FlagQueryGasLimit: limit,
				server.FlagMempoolMaxTxs: 5000,
			}
			creator := appCreator{encodingConfig: app.MakeEncodingConfig()}
			a := creator.newApp(log.NewNopLogger(), dbm.NewMemDB(), nil, opts).(*app.App)
			t.Cleanup(func() { require.NoError(t, a.Close()) })
			require.IsType(t, mempool.NoOpMempool{}, a.Mempool())
			pub := ed25519.GenPrivKey().PubKey()
			vals := tmtypes.NewValidatorSet([]*tmtypes.Validator{tmtypes.NewValidator(pub, 1)})
			gen, err := simtestutil.GenesisStateWithValSet(a.AppCodec(), app.NewDefaultGenesisState(a.AppCodec()), vals,
				[]authtypes.GenesisAccount{authtypes.NewBaseAccountWithAddress(sdk.AccAddress(pub.Address()))})
			require.NoError(t, err)
			raw, err := json.Marshal(gen)
			require.NoError(t, err)
			cp := tmtypes.DefaultConsensusParams().ToProto()
			stamp := time.Unix(1700000000, 0)
			_, err = a.InitChain(&abci.RequestInitChain{ChainId: "config-audit", InitialHeight: 1, Time: stamp, ConsensusParams: &cp, AppStateBytes: raw})
			require.NoError(t, err)
			_, err = a.FinalizeBlock(&abci.RequestFinalizeBlock{Height: 1, Time: stamp.Add(time.Second)})
			require.NoError(t, err)
			_, err = a.Commit()
			require.NoError(t, err)
			queryCtx, err := a.CreateQueryContext(1, false)
			require.NoError(t, err)
			want := limit
			if limit == 0 {
				want = math.MaxUint64
			}
			require.Equal(t, want, queryCtx.GasMeter().Limit())
			if limit > 0 {
				require.Panics(t, func() { queryCtx.GasMeter().ConsumeGas(limit+1, "query limit regression") })
			} else {
				require.NotPanics(t, func() { queryCtx.GasMeter().ConsumeGas(12346, "unlimited default") })
			}
		})
	}
}
