package app_test

import (
	"context"
	"testing"
	"time"

	pqcclient "github.com/DoraFactory/doravota/x/pqcauth/client"
	pqctypes "github.com/DoraFactory/doravota/x/pqcauth/types"
	abci "github.com/cometbft/cometbft/abci/types"
	sdkclient "github.com/cosmos/cosmos-sdk/client"
	sdktx "github.com/cosmos/cosmos-sdk/client/tx"
	codectypes "github.com/cosmos/cosmos-sdk/codec/types"
	cryptotypes "github.com/cosmos/cosmos-sdk/crypto/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
	txtypes "github.com/cosmos/cosmos-sdk/types/tx"
	"github.com/cosmos/cosmos-sdk/types/tx/signing"
	authsigning "github.com/cosmos/cosmos-sdk/x/auth/signing"
	banktypes "github.com/cosmos/cosmos-sdk/x/bank/types"
	"github.com/stretchr/testify/require"
)

func selectionSend(from, to cryptotypes.PrivKey) sdk.Msg {
	return banktypes.NewMsgSend(sdk.AccAddress(from.PubKey().Address()), sdk.AccAddress(to.PubKey().Address()), sdk.NewCoins(sdk.NewInt64Coin(sdk.DefaultBondDenom, 1)))
}

// Sign the actual transaction, including explicit future sequences, using all
// classic/native keys and any protected factors. Keys are in SDK signer order.
func selectionTx(t *testing.T, c *pqcChain, keys []cryptotypes.PrivKey, factors []pqcclient.PQCSigner, offsets []uint64, payer sdk.AccAddress, msgs ...sdk.Msg) []byte {
	t.Helper()
	return selectionTxWithGas(t, c, 5_000_000, keys, factors, offsets, payer, msgs...)
}

func selectionTxWithGas(t *testing.T, c *pqcChain, gas uint64, keys []cryptotypes.PrivKey, factors []pqcclient.PQCSigner, offsets []uint64, payer sdk.AccAddress, msgs ...sdk.Msg) []byte {
	t.Helper()
	ctx := c.app.NewContext(true).WithBlockHeight(c.height + 1)
	b := c.app.TxConfig().NewTxBuilder()
	require.NoError(t, b.SetMsgs(msgs...))
	b.SetGasLimit(gas)
	b.SetFeeAmount(sdk.NewCoins(sdk.NewInt64Coin(sdk.DefaultBondDenom, 10)))
	if payer != nil {
		b.SetFeePayer(payer)
	}
	sigs := make([]signing.SignatureV2, len(keys))
	for i, key := range keys {
		acc := c.app.AccountKeeper.GetAccount(ctx, sdk.AccAddress(key.PubKey().Address()))
		sigs[i] = signing.SignatureV2{PubKey: key.PubKey(), Sequence: acc.GetSequence() + offsets[i], Data: &signing.SingleSignatureData{SignMode: signing.SignMode_SIGN_MODE_DIRECT}}
	}
	require.NoError(t, b.SetSignatures(sigs...))
	ext := &pqctypes.ExtensionPQCAuth{FormatVersion: 1}
	for i, factor := range factors {
		if factor == nil {
			continue
		}
		owner := sdk.AccAddress(keys[i].PubKey().Address())
		acc := c.app.AccountKeeper.GetAccount(ctx, owner)
		record, policy, active := c.app.PQCAuthKeeper.GetActiveSigningKey(ctx, owner)
		require.True(t, active)
		protoTx := b.(interface{ GetProtoTx() *txtypes.Tx }).GetProtoTx()
		doc, err := pqctypes.NewPQCSignDocV1(protoTx, c.app.PQCAuthKeeper.GetParams(ctx).NetworkId, "policy-test", acc.GetAccountNumber(), sigs[i].Sequence, uint32(i), owner.String(), record.KeyId, record.Algorithm, policy.PolicyVersion)
		require.NoError(t, err)
		bz, err := pqctypes.MarshalPQCSignDocV1(doc)
		require.NoError(t, err)
		sig, err := factor.Sign(context.Background(), bz, []byte(pqctypes.TxSignatureContext))
		require.NoError(t, err)
		ext.Signatures = append(ext.Signatures, pqctypes.SignerPQCSignature{Signer: owner.String(), SignerIndex: uint32(i), KeyId: record.KeyId, Algorithm: record.Algorithm, PolicyVersion: policy.PolicyVersion, Signature: sig})
	}
	if len(ext.Signatures) != 0 {
		option, err := codectypes.NewAnyWithValue(ext)
		require.NoError(t, err)
		b.(sdkclient.ExtendedTxBuilder).SetExtensionOptions(option)
	}
	for i, key := range keys {
		owner := sdk.AccAddress(key.PubKey().Address())
		acc := c.app.AccountKeeper.GetAccount(ctx, owner)
		var err error
		sigs[i], err = sdktx.SignWithPrivKey(context.Background(), signing.SignMode_SIGN_MODE_DIRECT, authsigning.SignerData{Address: owner.String(), ChainID: "policy-test", AccountNumber: acc.GetAccountNumber(), Sequence: sigs[i].Sequence, PubKey: key.PubKey()}, b, key, c.app.TxConfig(), sigs[i].Sequence)
		require.NoError(t, err)
	}
	require.NoError(t, b.SetSignatures(sigs...))
	raw, err := c.app.TxConfig().TxEncoder()(b.GetTx())
	require.NoError(t, err)
	return raw
}

func selectionCheck(t *testing.T, c *pqcChain, txs [][]byte) {
	t.Helper()
	for _, raw := range txs {
		r, err := c.app.CheckTx(&abci.RequestCheckTx{Tx: raw})
		require.NoError(t, err)
		require.Zero(t, r.Code, r.Log)
	}
}

func selectionExecute(t *testing.T, c *pqcChain, candidates, want [][]byte) {
	t.Helper()
	h := c.height + 1
	stamp := c.stamp.Add(time.Duration(h) * time.Second)
	prepared, err := c.app.PrepareProposal(&abci.RequestPrepareProposal{Height: h, Time: stamp, MaxTxBytes: 1_000_000, Txs: candidates})
	require.NoError(t, err)
	require.Equal(t, want, prepared.Txs)
	processed, err := c.app.ProcessProposal(&abci.RequestProcessProposal{Height: h, Time: stamp, Txs: prepared.Txs})
	require.NoError(t, err)
	require.Equal(t, abci.ResponseProcessProposal_ACCEPT, processed.Status)
	result, err := c.app.FinalizeBlock(&abci.RequestFinalizeBlock{Height: h, Time: stamp, Txs: prepared.Txs})
	require.NoError(t, err)
	require.Len(t, result.TxResults, len(want))
	for _, r := range result.TxResults {
		require.Zero(t, r.Code, r.Log)
	}
	_, err = c.app.Commit()
	require.NoError(t, err)
	c.height = h
	c.block(t, nil)
	require.True(t, c.app.PQCAuthKeeper.AuditState(c.app.NewContext(true).WithBlockHeight(c.height), 100).Consistent)
}
