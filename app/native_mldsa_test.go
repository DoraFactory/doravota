package app_test

import (
	"encoding/json"
	"math/rand"
	"testing"
	"time"

	sdkmath "cosmossdk.io/math"
	"github.com/DoraFactory/doravota/app"
	abci "github.com/cometbft/cometbft/abci/types"
	"github.com/cometbft/cometbft/crypto/ed25519"
	cmtmldsa "github.com/cometbft/cometbft/crypto/mldsa65"
	tmtypes "github.com/cometbft/cometbft/types"
	cryptocodec "github.com/cosmos/cosmos-sdk/crypto/codec"
	"github.com/cosmos/cosmos-sdk/crypto/keys/mldsa65"
	simtestutil "github.com/cosmos/cosmos-sdk/testutil/sims"
	sdk "github.com/cosmos/cosmos-sdk/types"
	authtypes "github.com/cosmos/cosmos-sdk/x/auth/types"
	banktypes "github.com/cosmos/cosmos-sdk/x/bank/types"
	stakingtypes "github.com/cosmos/cosmos-sdk/x/staking/types"
	"github.com/stretchr/testify/require"
)

// Exercise the actual codec, standard Ante, transaction decoder and block lifecycle.
// Production consensus remains Ed25519 while the user account uses ML-DSA.
func TestNativeMLDSAAccountTransactions(t *testing.T) {
	a := policyTestApp(t)
	key, err := mldsa65.GenPrivKey()
	require.NoError(t, err)
	sender := sdk.AccAddress(key.PubKey().Address())
	recipient := sdk.AccAddress(ed25519.GenPrivKey().PubKey().Address())
	val := ed25519.GenPrivKey().PubKey()
	cp := tmtypes.DefaultConsensusParams().ToProto()
	genesis, err := simtestutil.GenesisStateWithValSet(a.AppCodec(), app.NewDefaultGenesisState(a.AppCodec()),
		tmtypes.NewValidatorSet([]*tmtypes.Validator{tmtypes.NewValidator(val, 1)}),
		[]authtypes.GenesisAccount{authtypes.NewBaseAccountWithAddress(sender)},
		banktypes.Balance{Address: sender.String(), Coins: sdk.NewCoins(sdk.NewInt64Coin(sdk.DefaultBondDenom, 100000000))})
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
	for sequence := uint64(0); sequence < 2; sequence++ {
		ctx := a.NewContext(true)
		acc := a.AccountKeeper.GetAccount(ctx, sender)
		require.Equal(t, sequence, acc.GetSequence())
		if sequence == 0 {
			require.Nil(t, acc.GetPubKey())
		}
		msg := banktypes.NewMsgSend(sender, recipient, sdk.NewCoins(sdk.NewInt64Coin(sdk.DefaultBondDenom, 7)))
		tx, err := simtestutil.GenSignedMockTx(rand.New(rand.NewSource(1)), a.TxConfig(), []sdk.Msg{msg}, nil, 1000000, "policy-test", []uint64{acc.GetAccountNumber()}, []uint64{sequence}, &key)
		require.NoError(t, err)
		txBytes, err := a.TxConfig().TxEncoder()(tx)
		require.NoError(t, err)
		checked, err := a.CheckTx(&abci.RequestCheckTx{Tx: txBytes})
		require.NoError(t, err)
		require.Zero(t, checked.Code, checked.Log)
		result, err := a.FinalizeBlock(&abci.RequestFinalizeBlock{Height: int64(sequence + 2), Time: stamp.Add(time.Duration(sequence+2) * time.Second), Txs: [][]byte{txBytes}})
		require.NoError(t, err)
		require.Len(t, result.TxResults, 1)
		require.Zero(t, result.TxResults[0].Code, result.TxResults[0].Log)
		_, err = a.Commit()
		require.NoError(t, err)
		stored := a.AccountKeeper.GetAccount(a.NewContext(true), sender)
		require.True(t, key.PubKey().Equals(stored.GetPubKey()))
		// Replaying the now committed sequence must fail before another block.
		replay, err := a.CheckTx(&abci.RequestCheckTx{Tx: txBytes})
		require.NoError(t, err)
		require.NotZero(t, replay.Code)
	}
	ctx := a.NewContext(true)
	require.Equal(t, sdkmath.NewInt(14), a.BankKeeper.GetBalance(ctx, recipient, sdk.DefaultBondDenom).Amount)
	require.Equal(t, []string{"ed25519"}, a.GetConsensusParams(ctx).Validator.PubKeyTypes)
	require.NotContains(t, app.GetMaccPerms(), "pqcauth")
	require.NotContains(t, app.GetMaccPerms(), "sponsor")
	require.Contains(t, app.GetMaccPerms()[stakingtypes.KeyRotationFeePoolName], authtypes.Burner)
}

func TestNativeMLDSAConsensusCodec(t *testing.T) {
	encoding := app.MakeEncodingConfig()
	key, err := cmtmldsa.GenPrivKey()
	require.NoError(t, err)
	pub, err := cryptocodec.FromCmtPubKeyInterface(key.PubKey())
	require.NoError(t, err)
	encoded, err := encoding.Marshaler.MarshalInterfaceJSON(pub)
	require.NoError(t, err)
	require.Contains(t, string(encoded), "cosmos.crypto.mldsa65.PubKey")
	restored, err := cryptocodec.ToCmtPubKeyInterface(pub)
	require.NoError(t, err)
	require.True(t, restored.Equals(key.PubKey()))
	message := []byte("isolated SDK 0.55 consensus codec test")
	signature, err := key.Sign(message)
	require.NoError(t, err)
	require.Len(t, restored.Bytes(), 1952)
	require.Len(t, signature, 3309)
	require.True(t, restored.VerifySignature(message, signature))
	require.False(t, restored.VerifySignature([]byte("wrong"), signature))
	require.False(t, restored.VerifySignature(message, signature[:len(signature)-1]))
}
