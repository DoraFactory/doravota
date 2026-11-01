package app_test

import (
	"testing"

	abci "github.com/cometbft/cometbft/abci/types"
	sdktx "github.com/cosmos/cosmos-sdk/client/tx"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/cosmos/cosmos-sdk/types/tx/signing"
	banktypes "github.com/cosmos/cosmos-sdk/x/bank/types"
	"github.com/stretchr/testify/require"
)

func TestPQCAuthFreshClassicSDKDryRun(t *testing.T) {
	c := newPQCChain(t)
	owner := sdk.AccAddress(c.key.PubKey().Address())
	recipient := sdk.AccAddress(c.other.PubKey().Address())
	account := c.app.AccountKeeper.GetAccount(c.app.NewContext(true), owner)
	require.Nil(t, account.GetPubKey())
	before := c.app.BankKeeper.GetBalance(c.app.NewContext(true), owner, sdk.DefaultBondDenom)
	msg := banktypes.NewMsgSend(owner, recipient, sdk.NewCoins(sdk.NewInt64Coin(sdk.DefaultBondDenom, 1)))
	factory := (sdktx.Factory{}).WithTxConfig(c.app.TxConfig()).WithChainID("policy-test").WithGas(3_000_000)
	raw, err := factory.BuildSimTx(msg)
	require.NoError(t, err)
	gas, _, err := c.app.Simulate(raw)
	require.NoError(t, err, "SDK empty public-key placeholder must work for ordinary fresh accounts")
	require.Positive(t, gas.GasUsed)

	decoded, err := c.app.TxConfig().TxDecoder()(raw)
	require.NoError(t, err)
	builder, err := c.app.TxConfig().WrapTxBuilder(decoded)
	require.NoError(t, err)
	require.NoError(t, builder.SetSignatures(signing.SignatureV2{PubKey: c.key.PubKey(), Data: &signing.SingleSignatureData{SignMode: signing.SignMode_SIGN_MODE_UNSPECIFIED}}))
	realKeySimulation, err := c.app.TxConfig().TxEncoder()(builder.GetTx())
	require.NoError(t, err)
	_, _, err = c.app.Simulate(realKeySimulation)
	require.NoError(t, err)
	account = c.app.AccountKeeper.GetAccount(c.app.NewContext(true), owner)
	require.Nil(t, account.GetPubKey(), "simulation cannot persist a key")
	require.Zero(t, account.GetSequence())
	require.Equal(t, before, c.app.BankKeeper.GetBalance(c.app.NewContext(true), owner, sdk.DefaultBondDenom))

	check, err := c.app.CheckTx(&abci.RequestCheckTx{Tx: raw})
	require.NoError(t, err)
	require.NotZero(t, check.Code, "the simulation placeholder must not be accepted as a real signature")
	decision, err := c.app.ProcessProposal(&abci.RequestProcessProposal{Height: c.height + 1, Txs: [][]byte{raw}})
	require.NoError(t, err)
	require.Equal(t, abci.ResponseProcessProposal_REJECT, decision.Status)
	result := c.block(t, raw)
	require.NotZero(t, result.Code)
	require.Nil(t, c.app.AccountKeeper.GetAccount(c.app.NewContext(true), owner).GetPubKey())
	result = c.block(t, c.tx(t, c.key, nil, msg))
	require.Zero(t, result.Code, result.Log)
	raw, err = factory.WithSequence(1).BuildSimTx(msg)
	require.NoError(t, err)
	_, _, err = c.app.Simulate(raw)
	require.NoError(t, err, "persisted-account simulation remains compatible")
}

func TestPQCAuthProtectedSimulationVersusDeliveryGas(t *testing.T) {
	c := newPQCChain(t)
	factor, _ := reviewEnroll(t, c)
	owner := sdk.AccAddress(c.key.PubKey().Address())
	recipient := sdk.AccAddress(c.other.PubKey().Address())
	msg := banktypes.NewMsgSend(owner, recipient, sdk.NewCoins(sdk.NewInt64Coin(sdk.DefaultBondDenom, 1)))
	raw := c.tx(t, c.key, factor, msg)
	gas, _, err := c.app.Simulate(raw)
	require.NoError(t, err)
	result := c.block(t, raw)
	require.Zero(t, result.Code, result.Log)
	require.GreaterOrEqual(t, gas.GasUsed, uint64(result.GasUsed))
}
