package app_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/DoraFactory/doravota/app"
	pqctypes "github.com/DoraFactory/doravota/x/pqcauth/types"
	abci "github.com/cometbft/cometbft/abci/types"
	"github.com/cometbft/cometbft/crypto/ed25519"
	tmtypes "github.com/cometbft/cometbft/types"
	"github.com/cosmos/cosmos-sdk/baseapp"
	cryptotypes "github.com/cosmos/cosmos-sdk/crypto/types"
	simtestutil "github.com/cosmos/cosmos-sdk/testutil/sims"
	sdk "github.com/cosmos/cosmos-sdk/types"
	authtypes "github.com/cosmos/cosmos-sdk/x/auth/types"
	banktypes "github.com/cosmos/cosmos-sdk/x/bank/types"
	"github.com/stretchr/testify/require"
)

// Exercise the opt-in generator's actual output through real InitChain, not
// merely the PQC-only ValidateGenesis (which cannot inspect SDK accounts).
func TestPQCAuthNetworkLoadGenesis(t *testing.T) {
	for _, kind := range []string{"classic", "hybrid", "native", "hybrid-missing-public-keys"} {
		t.Run(kind, func(t *testing.T) {
			dir := t.TempDir()
			a := policyTestApp(t)
			baseapp.SetChainID("pqc-isolated-fixture-regression")(a.BaseApp)
			params := pqctypes.DefaultParams()
			loadKind := kind
			if kind == "hybrid-missing-public-keys" {
				loadKind = "hybrid"
			}
			config, err := json.Marshal(map[string]any{
				"chain_id": "pqc-isolated-fixture-regression", "kind": loadKind,
				"phase": "prepare", "count": 1,
				"params": json.RawMessage(a.AppCodec().MustMarshalJSON(&params)),
			})
			require.NoError(t, err)
			require.NoError(t, os.WriteFile(filepath.Join(dir, "load-config.json"), config, 0600))
			generatePQCNetworkLoad(t, dir)
			encoded, err := os.ReadFile(filepath.Join(dir, "load-genesis.json"))
			require.NoError(t, err)
			var fixture struct {
				Addresses  []string                   `json:"addresses"`
				PQC        json.RawMessage            `json:"pqcauth"`
				PublicKeys map[string]json.RawMessage `json:"account_public_keys"`
			}
			require.NoError(t, json.Unmarshal(encoded, &fixture))
			require.Len(t, fixture.Addresses, 7)
			require.Len(t, fixture.PublicKeys, 7)
			accounts := make([]authtypes.GenesisAccount, 0, 7)
			balances := make([]banktypes.Balance, 0, 7)
			for _, owner := range fixture.Addresses {
				address := sdk.MustAccAddressFromBech32(owner)
				var pub cryptotypes.PubKey
				require.NoError(t, a.AppCodec().UnmarshalInterfaceJSON(fixture.PublicKeys[owner], &pub))
				require.Equal(t, address.Bytes(), pub.Address().Bytes())
				account := authtypes.NewBaseAccountWithAddress(address)
				// Match the harness: only pre-enrolled hybrid accounts need
				// their pubkey installed before InitChain.
				if kind == "hybrid" {
					require.NoError(t, account.SetPubKey(pub))
				}
				accounts = append(accounts, account)
				balances = append(balances, banktypes.Balance{Address: owner, Coins: sdk.NewCoins(sdk.NewInt64Coin(sdk.DefaultBondDenom, 100000000))})
			}
			genesis, err := simtestutil.GenesisStateWithValSet(a.AppCodec(), app.NewDefaultGenesisState(a.AppCodec()),
				tmtypes.NewValidatorSet([]*tmtypes.Validator{tmtypes.NewValidator(ed25519.GenPrivKey().PubKey(), 1)}), accounts, balances...)
			require.NoError(t, err)
			genesis[pqctypes.ModuleName] = fixture.PQC
			raw, err := json.Marshal(genesis)
			require.NoError(t, err)
			cp := tmtypes.DefaultConsensusParams().ToProto()
			request := &abci.RequestInitChain{ChainId: "pqc-isolated-fixture-regression", InitialHeight: 1,
				Time: time.Unix(1700000000, 0), ConsensusParams: &cp, AppStateBytes: raw}
			if kind == "hybrid-missing-public-keys" {
				require.Panics(t, func() { _, _ = a.InitChain(request) }, "retain production rejection of malformed genesis")
				return
			}
			_, err = a.InitChain(request)
			require.NoError(t, err)
			_, err = a.FinalizeBlock(&abci.RequestFinalizeBlock{Height: 1, Time: request.Time.Add(time.Second)})
			require.NoError(t, err)
			_, err = a.Commit()
			require.NoError(t, err)
			if kind == "hybrid" {
				report := a.PQCAuthKeeper.AuditState(a.NewContext(true).WithBlockHeight(1), 100)
				require.True(t, report.Consistent, "%+v", report.Issues)
			}
		})
	}
}
