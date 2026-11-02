package app_test

import (
	"fmt"
	"testing"

	pqctypes "github.com/DoraFactory/doravota/x/pqcauth/types"
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
	// SDK NoOp ProcessProposal does not authenticate; FinalizeBlock below must reject.
	require.Equal(t, abci.ResponseProcessProposal_ACCEPT, decision.Status)
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

// Compare actual signed protected sends, not just the estimation helper.
// 750 and 751 have equal protobuf varint length, so the one-gas difference
// isolates one authorization verification without changing parameter-read gas.
func TestPQCAuthVerificationPriceAppliedToSimulationAndDelivery(t *testing.T) {
	simulated := make(map[uint64]uint64)
	delivered := make(map[uint64]int64)
	for _, price := range []uint64{750, 751, 250_000} {
		t.Run(fmt.Sprint(price), func(t *testing.T) {
			p := pqctypes.DefaultParams()
			p.VerificationGas = price
			c := newPQCChain(t, p)
			factor, _ := reviewEnroll(t, c)
			msg := selectionSend(c.key, c.other)
			raw := c.tx(t, c.key, factor, msg)
			gas, _, err := c.app.Simulate(raw)
			require.NoError(t, err)
			check, err := c.app.CheckTx(&abci.RequestCheckTx{Tx: raw})
			require.NoError(t, err)
			require.Zero(t, check.Code, check.Log)
			result := c.block(t, raw)
			require.Zero(t, result.Code, result.Log)
			require.GreaterOrEqual(t, gas.GasUsed, uint64(result.GasUsed))
			simulated[price], delivered[price] = gas.GasUsed, result.GasUsed
			t.Logf("verification price=%d, tx bytes=%d, simulated=%d, delivered=%d", price, len(raw), gas.GasUsed, result.GasUsed)
			// A valid classical signature is still insufficient without the factor.
			rejected := c.block(t, c.tx(t, c.key, nil, msg))
			require.NotZero(t, rejected.Code)
			c.block(t, nil)
			require.True(t, c.app.PQCAuthKeeper.AuditState(c.app.NewContext(true).WithBlockHeight(c.height), 100).Consistent)
		})
	}
	require.Equal(t, uint64(1), simulated[751]-simulated[750])
	require.Equal(t, int64(1), delivered[751]-delivered[750])
	require.Greater(t, simulated[250_000], simulated[750])
	require.Greater(t, delivered[250_000], delivered[750])
}

func TestPQCAuthProofPriceAppliedToSimulationAndDelivery(t *testing.T) {
	simulated := make(map[uint64]uint64)
	delivered := make(map[uint64]int64)
	for _, price := range []uint64{750, 751, 250_000} {
		t.Run(fmt.Sprint(price), func(t *testing.T) {
			p := pqctypes.DefaultParams()
			p.VerificationGas = price
			c := newPQCChain(t, p)
			msg, _ := auditRegister(t, c)
			raw := c.tx(t, c.key, nil, msg)
			gas, _, err := c.app.Simulate(raw)
			require.NoError(t, err)
			check, err := c.app.CheckTx(&abci.RequestCheckTx{Tx: raw})
			require.NoError(t, err)
			require.Zero(t, check.Code, check.Log)
			result := c.block(t, raw)
			require.Zero(t, result.Code, result.Log)
			require.GreaterOrEqual(t, gas.GasUsed, uint64(result.GasUsed))
			simulated[price], delivered[price] = gas.GasUsed, result.GasUsed
			t.Logf("proof price=%d, tx bytes=%d, simulated=%d, delivered=%d", price, len(raw), gas.GasUsed, result.GasUsed)
			c.block(t, nil)
			require.True(t, c.app.PQCAuthKeeper.AuditState(c.app.NewContext(true).WithBlockHeight(c.height), 100).Consistent)
		})
	}
	// Signing and recovery key enrollment each verify one proof.
	require.Equal(t, uint64(2), simulated[751]-simulated[750])
	require.Equal(t, int64(2), delivered[751]-delivered[750])
	require.Greater(t, simulated[250_000], simulated[750])
	require.Greater(t, delivered[250_000], delivered[750])
}
