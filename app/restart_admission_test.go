package app_test

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"cosmossdk.io/log/v2"
	"github.com/DoraFactory/doravota/app"
	pqcclient "github.com/DoraFactory/doravota/x/pqcauth/client"
	abci "github.com/cometbft/cometbft/abci/types"
	"github.com/cometbft/cometbft/crypto/ed25519"
	tmtypes "github.com/cometbft/cometbft/types"
	dbm "github.com/cosmos/cosmos-db"
	"github.com/cosmos/cosmos-sdk/baseapp"
	sdktx "github.com/cosmos/cosmos-sdk/client/tx"
	"github.com/cosmos/cosmos-sdk/crypto/keys/mldsa65"
	"github.com/cosmos/cosmos-sdk/crypto/keys/secp256k1"
	cryptotypes "github.com/cosmos/cosmos-sdk/crypto/types"
	simtestutil "github.com/cosmos/cosmos-sdk/testutil/sims"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/cosmos/cosmos-sdk/types/tx/signing"
	authsigning "github.com/cosmos/cosmos-sdk/x/auth/signing"
	authtypes "github.com/cosmos/cosmos-sdk/x/auth/types"
	banktypes "github.com/cosmos/cosmos-sdk/x/bank/types"
	"github.com/stretchr/testify/require"
)

// Restart admission must use the loaded height/time before any new block.
// Each restart closes and reopens a real on-disk application database. No
// invented context/header, signature verifier, or SDK logic is substituted.
func TestRestartAdmissionUsesCommittedContext(t *testing.T) {
	for _, name := range []string{"classic", "hybrid", "native"} {
		t.Run(name, func(t *testing.T) {
			hybrid := name == "hybrid"
			dir := t.TempDir()
			opts := simtestutil.AppOptionsMap{}
			home := simulationHome(t, opts)
			var observedHeight int64
			var observedTime time.Time
			var loadHeight int64
			open := func() *app.App {
				db, err := dbm.NewDB("restart", dbm.GoLevelDBBackend, dir)
				require.NoError(t, err)
				a := app.New(log.NewNopLogger(), db, nil, false, map[int64]bool{}, home, 0, app.MakeEncodingConfig(), opts, baseapp.SetChainID("policy-test"))
				original := a.AnteHandler()
				a.SetAnteHandler(func(ctx sdk.Context, tx sdk.Tx, simulate bool) (sdk.Context, error) {
					updated, err := original(ctx, tx, simulate)
					observedHeight = updated.BlockHeight()
					observedTime = updated.BlockTime()
					require.Equal(t, updated.BlockHeight(), updated.HeaderInfo().Height)
					require.True(t, updated.BlockTime().Equal(updated.HeaderInfo().Time))
					return updated, err
				})
				if loadHeight == 0 {
					require.NoError(t, a.LoadLatestVersion())
				} else {
					require.NoError(t, a.LoadHeight(loadHeight))
				}
				return a
			}
			a := open()
			key, other := secp256k1.GenPrivKey(), secp256k1.GenPrivKey()
			var signingKey cryptotypes.PrivKey = key
			if name == "native" {
				native, err := mldsa65.GenPrivKey()
				require.NoError(t, err)
				signingKey = &native
			}
			owner, second := sdk.AccAddress(signingKey.PubKey().Address()), sdk.AccAddress(other.PubKey().Address())
			cp := tmtypes.DefaultConsensusParams().ToProto()
			genesis, err := simtestutil.GenesisStateWithValSet(a.AppCodec(), app.NewDefaultGenesisState(a.AppCodec()), tmtypes.NewValidatorSet([]*tmtypes.Validator{tmtypes.NewValidator(ed25519.GenPrivKey().PubKey(), 1)}), []authtypes.GenesisAccount{authtypes.NewBaseAccount(owner, nil, 20, 0), authtypes.NewBaseAccount(second, nil, 21, 0)}, banktypes.Balance{Address: owner.String(), Coins: sdk.NewCoins(sdk.NewInt64Coin(sdk.DefaultBondDenom, 100000000))}, banktypes.Balance{Address: second.String(), Coins: sdk.NewCoins(sdk.NewInt64Coin(sdk.DefaultBondDenom, 1000000))})
			require.NoError(t, err)
			rawGenesis, err := json.Marshal(genesis)
			require.NoError(t, err)
			stamp := time.Unix(1700000000, 0)
			_, err = a.InitChain(&abci.RequestInitChain{ChainId: "policy-test", InitialHeight: 1, Time: stamp, ConsensusParams: &cp, AppStateBytes: rawGenesis})
			require.NoError(t, err)
			c := &pqcChain{a, key, other, 0, stamp}
			c.block(t, nil)
			c.block(t, nil)
			c.block(t, nil)
			var factor pqcclient.PQCSigner
			if hybrid {
				factor, _ = reviewEnroll(t, c)
			}
			account := a.AccountKeeper.GetAccount(a.NewContext(true), owner)
			var raw []byte
			if name == "native" {
				b := a.TxConfig().NewTxBuilder()
				require.NoError(t, b.SetMsgs(banktypes.NewMsgSend(owner, second, sdk.NewCoins(sdk.NewInt64Coin(sdk.DefaultBondDenom, 1)))))
				b.SetGasLimit(3000000)
				b.SetFeeAmount(sdk.NewCoins(sdk.NewInt64Coin(sdk.DefaultBondDenom, 10)))
				require.NoError(t, b.SetSignatures(signing.SignatureV2{PubKey: signingKey.PubKey(), Sequence: account.GetSequence(), Data: &signing.SingleSignatureData{SignMode: signing.SignMode_SIGN_MODE_DIRECT}}))
				sig, err := sdktx.SignWithPrivKey(context.Background(), signing.SignMode_SIGN_MODE_DIRECT, authsigning.SignerData{Address: owner.String(), ChainID: "policy-test", AccountNumber: account.GetAccountNumber(), Sequence: account.GetSequence(), PubKey: signingKey.PubKey()}, b, signingKey, a.TxConfig(), account.GetSequence())
				require.NoError(t, err)
				require.NoError(t, b.SetSignatures(sig))
				raw, err = a.TxConfig().TxEncoder()(b.GetTx())
				require.NoError(t, err)
			} else {
				raw = c.tx(t, key, factor, selectionSend(key, other))
			}
			require.NotZero(t, account.GetAccountNumber())
			seq := account.GetSequence()
			balance := a.BankKeeper.GetBalance(a.NewContext(true), owner, sdk.DefaultBondDenom)
			before := recheckResult(t, c, raw, abci.CheckTxType_New)
			require.Zero(t, before.Code, before.Log)
			t.Logf("before restart: store=%d ante=%d account=%d code=%d", a.LastBlockHeight(), observedHeight, account.GetAccountNumber(), before.Code)
			committed := a.LastCommitID()
			require.NoError(t, a.Close())
			c.app = open()
			defer func() { require.NoError(t, c.app.Close()) }()
			require.Equal(t, c.height, c.app.LastBlockHeight())
			require.Equal(t, account.GetAccountNumber(), c.app.AccountKeeper.GetAccount(c.app.NewContext(true), owner).GetAccountNumber())
			if hybrid {
				badFactor := c.tx(t, key, capacityFactor(t, c), selectionSend(key, other))
				r := recheckResult(t, c, badFactor, abci.CheckTxType_New)
				require.NotZero(t, r.Code, "startup must not bypass PQC authentication")
				require.Equal(t, seq, c.app.AccountKeeper.GetAccount(c.app.NewContext(true), owner).GetSequence())
				require.Equal(t, balance, c.app.BankKeeper.GetBalance(c.app.NewContext(true), owner, sdk.DefaultBondDenom))
			}
			// An already-expired transaction must not appear valid at height zero.
			expired, err := c.app.TxConfig().TxDecoder()(raw)
			require.NoError(t, err)
			expiredBuilder, err := c.app.TxConfig().WrapTxBuilder(expired)
			require.NoError(t, err)
			expiredBuilder.SetTimeoutHeight(uint64(c.height - 1))
			expiredRaw, err := c.app.TxConfig().TxEncoder()(expiredBuilder.GetTx())
			require.NoError(t, err)
			expiredResult := recheckResult(t, c, expiredRaw, abci.CheckTxType_New)
			require.NotZero(t, expiredResult.Code)
			require.Contains(t, expiredResult.Log, "timeout height")
			_, _, err = c.app.Simulate(raw)
			require.NoError(t, err)
			require.Equal(t, c.height, observedHeight)
			require.True(t, observedTime.Equal(stamp.Add(time.Duration(c.height)*time.Second)))
			require.Equal(t, seq, c.app.AccountKeeper.GetAccount(c.app.NewContext(true), owner).GetSequence())
			after := recheckResult(t, c, raw, abci.CheckTxType_New)
			require.Zero(t, after.Code, after.Log)
			require.Equal(t, c.height, observedHeight)
			require.True(t, observedTime.Equal(stamp.Add(time.Duration(c.height)*time.Second)))
			require.Equal(t, before.GasUsed, after.GasUsed)
			require.Equal(t, committed, c.app.LastCommitID())
			t.Logf("after disk reopen: store=%d ante=%d account=%d code=%d log=%s", c.app.LastBlockHeight(), observedHeight, account.GetAccountNumber(), after.Code, after.Log)
			// Successful CheckTx changes only the admission cache, not committed state.

			c.block(t, nil)
			afterEmpty := recheckResult(t, c, raw, abci.CheckTxType_New)
			require.Zero(t, afterEmpty.Code, afterEmpty.Log)
			require.Equal(t, c.height, observedHeight)
			t.Logf("after empty block: store=%d ante=%d valid-code=%d", c.app.LastBlockHeight(), observedHeight, afterEmpty.Code)
			require.NoError(t, c.app.Close())
			loadHeight = c.height // Also cover App.LoadHeight -> App.LoadVersion.
			c.app = open()

			// Re-sign only the classical layer with the WRONG account number. This
			// is a diagnostic negative control, NEVER a workaround for wallet users.
			decoded, err := c.app.TxConfig().TxDecoder()(raw)
			require.NoError(t, err)
			builder, err := c.app.TxConfig().WrapTxBuilder(decoded)
			require.NoError(t, err)
			wrongSig, err := sdktx.SignWithPrivKey(context.Background(), signing.SignMode_SIGN_MODE_DIRECT, authsigning.SignerData{Address: owner.String(), ChainID: "policy-test", AccountNumber: 0, Sequence: seq, PubKey: signingKey.PubKey()}, builder, signingKey, c.app.TxConfig(), seq)
			require.NoError(t, err)
			require.NoError(t, builder.SetSignatures(wrongSig))
			wrongRaw, err := c.app.TxConfig().TxEncoder()(builder.GetTx())
			require.NoError(t, err)
			wrongAdmission := recheckResult(t, c, wrongRaw, abci.CheckTxType_New)
			t.Logf("wrong-account-number admission: code=%d log=%s", wrongAdmission.Code, wrongAdmission.Log)
			require.NotZero(t, wrongAdmission.Code)
			require.Contains(t, wrongAdmission.Log, "signature verification failed")
			delivered := c.block(t, wrongRaw)
			require.NotZero(t, delivered.Code)
			require.Contains(t, delivered.Log, "signature verification failed")
			require.Equal(t, seq, c.app.AccountKeeper.GetAccount(c.app.NewContext(true), owner).GetSequence())
			require.Equal(t, balance, c.app.BankKeeper.GetBalance(c.app.NewContext(true), owner, sdk.DefaultBondDenom))
			t.Logf("wrong-account-number finalization: code=%d; balance and sequence unchanged", delivered.Code)
			recovered := recheckResult(t, c, raw, abci.CheckTxType_New)
			require.Zero(t, recovered.Code, recovered.Log)
			require.Equal(t, c.height, observedHeight)
			t.Logf("after first new committed block: store=%d ante=%d valid-code=%d", c.app.LastBlockHeight(), observedHeight, recovered.Code)
			ok := c.block(t, raw)
			require.Zero(t, ok.Code, ok.Log)
			require.Equal(t, seq+1, c.app.AccountKeeper.GetAccount(c.app.NewContext(true), owner).GetSequence())
		})
	}
}
