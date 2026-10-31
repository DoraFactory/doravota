package app_test

import (
	"encoding/json"
	"math/rand"
	"testing"
	"time"

	"github.com/DoraFactory/doravota/app"
	pqctypes "github.com/DoraFactory/doravota/x/pqcauth/types"
	abci "github.com/cometbft/cometbft/abci/types"
	"github.com/cometbft/cometbft/crypto/ed25519"
	tmtypes "github.com/cometbft/cometbft/types"
	"github.com/cosmos/cosmos-sdk/crypto/keys/mldsa65"
	"github.com/cosmos/cosmos-sdk/crypto/keys/secp256k1"
	cryptotypes "github.com/cosmos/cosmos-sdk/crypto/types"
	simtestutil "github.com/cosmos/cosmos-sdk/testutil/sims"
	sdk "github.com/cosmos/cosmos-sdk/types"
	authtypes "github.com/cosmos/cosmos-sdk/x/auth/types"
	banktypes "github.com/cosmos/cosmos-sdk/x/bank/types"
	"github.com/stretchr/testify/require"
)

func TestPQCAuthProposalRejectsFreshKeyBudgetPoisoning(t *testing.T) {
	a := policyTestApp(t)
	native, err := mldsa65.GenPrivKey()
	require.NoError(t, err)
	sender := sdk.AccAddress(native.PubKey().Address())
	recipient := sdk.AccAddress(ed25519.GenPrivKey().PubKey().Address())
	cp := tmtypes.DefaultConsensusParams().ToProto()
	genesis, err := simtestutil.GenesisStateWithValSet(a.AppCodec(), app.NewDefaultGenesisState(a.AppCodec()), tmtypes.NewValidatorSet([]*tmtypes.Validator{tmtypes.NewValidator(ed25519.GenPrivKey().PubKey(), 1)}), []authtypes.GenesisAccount{authtypes.NewBaseAccountWithAddress(sender)}, banktypes.Balance{Address: sender.String(), Coins: sdk.NewCoins(sdk.NewInt64Coin(sdk.DefaultBondDenom, 100000000))})
	require.NoError(t, err)
	var pqc pqctypes.GenesisState
	require.NoError(t, a.AppCodec().UnmarshalJSON(genesis[pqctypes.ModuleName], &pqc))
	pqc.Params.MaxPqcSigners = pqctypes.MinimumMaxPQCSigners
	pqc.Params.MaxPqcVerificationsPerTx = pqctypes.MinimumMaxPQCVerificationsPerTx
	pqc.Params.MaxPqcVerificationsPerBlock = pqctypes.MinimumMaxPQCVerificationsPerTx
	genesis[pqctypes.ModuleName], err = a.AppCodec().MarshalJSON(&pqc)
	require.NoError(t, err)
	raw, err := json.Marshal(genesis)
	require.NoError(t, err)
	stamp := time.Unix(1700000000, 0)
	_, err = a.InitChain(&abci.RequestInitChain{ChainId: "policy-test", InitialHeight: 1, Time: stamp, ConsensusParams: &cp, AppStateBytes: raw})
	require.NoError(t, err)
	_, err = a.FinalizeBlock(&abci.RequestFinalizeBlock{Height: 1, Time: stamp.Add(time.Second)})
	require.NoError(t, err)
	_, err = a.Commit()
	require.NoError(t, err)
	acc := a.AccountKeeper.GetAccount(a.NewContext(true), sender)
	require.Nil(t, acc.GetPubKey())
	makeTx := func(key cryptotypes.PrivKey, seq uint64) []byte {
		msg := banktypes.NewMsgSend(sender, recipient, sdk.NewCoins(sdk.NewInt64Coin(sdk.DefaultBondDenom, 7)))
		tx, err := simtestutil.GenSignedMockTx(rand.New(rand.NewSource(1)), a.TxConfig(), []sdk.Msg{msg}, nil, 1000000, "policy-test", []uint64{acc.GetAccountNumber()}, []uint64{seq}, key)
		require.NoError(t, err)
		raw, err := a.TxConfig().TxEncoder()(tx)
		require.NoError(t, err)
		return raw
	}
	txs := [][]byte{makeTx(secp256k1.GenPrivKey(), 0)}
	for seq := uint64(0); seq <= uint64(pqc.Params.MaxPqcVerificationsPerBlock); seq++ {
		txs = append(txs, makeTx(&native, seq))
	}
	selectedEnd := 1 + int(pqc.Params.MaxPqcVerificationsPerBlock)
	decision, err := a.ProcessProposal(&abci.RequestProcessProposal{Height: 2, Time: stamp.Add(2 * time.Second), Txs: txs})
	require.NoError(t, err)
	require.Equal(t, abci.ResponseProcessProposal_REJECT, decision.Status,
		"an unrelated first key must not hide native verifications beyond the block budget")
	prepared, err := a.PrepareProposal(&abci.RequestPrepareProposal{
		Height: 2, Time: stamp.Add(2 * time.Second), MaxTxBytes: 1000000, Txs: txs,
	})
	require.NoError(t, err)
	require.Equal(t, txs[1:selectedEnd], prepared.Txs,
		"skip the poison transaction and retain exactly the native verification budget")
	decision, err = a.ProcessProposal(&abci.RequestProcessProposal{
		Height: 2, Time: stamp.Add(2 * time.Second), Txs: prepared.Txs,
	})
	require.NoError(t, err)
	require.Equal(t, abci.ResponseProcessProposal_ACCEPT, decision.Status)
	result, err := a.FinalizeBlock(&abci.RequestFinalizeBlock{
		Height: 2, Time: stamp.Add(2 * time.Second), Txs: prepared.Txs,
	})
	require.NoError(t, err)
	require.Len(t, result.TxResults, int(pqc.Params.MaxPqcVerificationsPerBlock))
	for _, txResult := range result.TxResults {
		require.Zero(t, txResult.Code, txResult.Log)
	}
	_, err = a.Commit()
	require.NoError(t, err)
	decision, err = a.ProcessProposal(&abci.RequestProcessProposal{
		Height: 3, Time: stamp.Add(3 * time.Second), Txs: txs[selectedEnd:],
	})
	require.NoError(t, err)
	require.Equal(t, abci.ResponseProcessProposal_ACCEPT, decision.Status)
	result, err = a.FinalizeBlock(&abci.RequestFinalizeBlock{
		Height: 3, Time: stamp.Add(3 * time.Second), Txs: txs[selectedEnd:],
	})
	require.NoError(t, err)
	require.Len(t, result.TxResults, 1)
	require.Zero(t, result.TxResults[0].Code, result.TxResults[0].Log)
}
