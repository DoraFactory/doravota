package app_test

import (
	"context"
	pqcclient "github.com/DoraFactory/doravota/x/pqcauth/client"
	pqctypes "github.com/DoraFactory/doravota/x/pqcauth/types"
	abci "github.com/cometbft/cometbft/abci/types"
	sdktx "github.com/cosmos/cosmos-sdk/client/tx"
	"github.com/cosmos/cosmos-sdk/crypto/keys/secp256k1"
	sdk "github.com/cosmos/cosmos-sdk/types"
	txtypes "github.com/cosmos/cosmos-sdk/types/tx"
	"github.com/cosmos/cosmos-sdk/types/tx/signing"
	authsigning "github.com/cosmos/cosmos-sdk/x/auth/signing"
	banktypes "github.com/cosmos/cosmos-sdk/x/bank/types"
	"github.com/stretchr/testify/require"
	"testing"
	"time"
)

func auditRegister(t *testing.T, c *pqcChain) (*pqctypes.MsgRegisterKey, pqcclient.PQCSigner) {
	msg, factor, _ := auditRegisterRecovery(t, c)
	return msg, factor
}

func auditRegisterRecovery(t *testing.T, c *pqcChain) (*pqctypes.MsgRegisterKey, pqcclient.PQCSigner, pqcclient.PQCSigner) {
	factor, recovery := capacityFactor(t, c), capacityFactor(t, c)
	pub, proof := reviewProof(t, c, factor, 1, pqctypes.KeyRole_KEY_ROLE_SIGNING, pqctypes.PurposeRegisterSigning, 0, pqctypes.RegisterProofContext)
	rpub, rproof := reviewProof(t, c, recovery, 2, pqctypes.KeyRole_KEY_ROLE_RECOVERY, pqctypes.PurposeRegisterRecovery, 0, pqctypes.RegisterProofContext)
	return &pqctypes.MsgRegisterKey{Owner: sdk.AccAddress(c.key.PubKey().Address()).String(), ExpectedSigningKeyId: 1, SigningAlgorithm: pqctypes.Algorithm_ALGORITHM_ML_DSA_65, SigningPublicKey: pub, SigningKeyProof: proof, SelfEnforce: true, RecoveryAlgorithm: pqctypes.Algorithm_ALGORITHM_ML_DSA_65, RecoveryPublicKey: rpub, RecoveryKeyProof: rproof}, factor, recovery
}

func auditResign(t *testing.T, c *pqcChain, key *secp256k1.PrivKey, raw []byte, gas, seq uint64, mode signing.SignMode) []byte {
	decoded, err := c.app.TxConfig().TxDecoder()(raw)
	require.NoError(t, err)
	b, err := c.app.TxConfig().WrapTxBuilder(decoded)
	require.NoError(t, err)
	b.SetGasLimit(gas)
	require.NoError(t, b.SetSignatures(signing.SignatureV2{PubKey: key.PubKey(), Sequence: seq, Data: &signing.SingleSignatureData{SignMode: mode}}))
	owner := sdk.AccAddress(key.PubKey().Address())
	acc := c.app.AccountKeeper.GetAccount(c.app.NewContext(true), owner)
	sig, err := sdktx.SignWithPrivKey(context.Background(), mode, authsigning.SignerData{Address: owner.String(), ChainID: "policy-test", AccountNumber: acc.GetAccountNumber(), Sequence: seq, PubKey: key.PubKey()}, b, key, c.app.TxConfig(), seq)
	require.NoError(t, err)
	require.NoError(t, b.SetSignatures(sig))
	out, err := c.app.TxConfig().TxEncoder()(b.GetTx())
	require.NoError(t, err)
	return out
}

func TestPQCAuthRegistrationRequiresDirect(t *testing.T) {
	c := newPQCChain(t)
	msg, factor, recovery := auditRegisterRecovery(t, c)
	raw := auditResign(t, c, c.key, c.tx(t, c.key, nil, msg), 3000000, 0, signing.SignMode_SIGN_MODE_LEGACY_AMINO_JSON)
	r := c.block(t, raw)
	require.NotZero(t, r.Code)
	require.Contains(t, r.Log, "DIRECT")
	require.Zero(t, c.app.AccountKeeper.GetAccount(c.app.NewContext(true), sdk.AccAddress(c.key.PubKey().Address())).GetSequence())
	_, found := c.app.PQCAuthKeeper.GetAccountPolicy(c.app.NewContext(true), sdk.AccAddress(c.key.PubKey().Address()))
	require.False(t, found)
	r = c.block(t, c.tx(t, c.key, nil, msg))
	require.Zero(t, r.Code, r.Log)
	c.block(t, nil)
	owner := sdk.AccAddress(c.key.PubKey().Address())
	send := banktypes.NewMsgSend(owner, sdk.AccAddress(c.other.PubKey().Address()), sdk.NewCoins(sdk.NewInt64Coin(sdk.DefaultBondDenom, 1)))
	raw = auditResign(t, c, c.key, c.tx(t, c.key, nil, send), 3000000, 1, signing.SignMode_SIGN_MODE_LEGACY_AMINO_JSON)
	r = c.block(t, raw)
	require.NotZero(t, r.Code)
	require.Contains(t, r.Log, "PQC authorization is required")
	t.Logf("direct enrollment succeeded, protected amino send rejected: %s", r.Log)
	off := &pqctypes.MsgSetProtection{Owner: owner.String(), Enabled: false}
	raw = auditResign(t, c, c.key, c.tx(t, c.key, nil, off), 3000000, 1, signing.SignMode_SIGN_MODE_LEGACY_AMINO_JSON)
	r = c.block(t, raw)
	require.NotZero(t, r.Code)
	t.Logf("amino protection disable rejected: %s", r.Log)
	next := capacityFactor(t, c)
	pub, proof := reviewProof(t, c, next, 3, pqctypes.KeyRole_KEY_ROLE_SIGNING, pqctypes.PurposeRecoverSigning, 1, pqctypes.RecoveryKeyProofContext)
	params := c.app.PQCAuthKeeper.GetParams(c.app.NewContext(true))
	recoverMsg := &pqctypes.MsgRecoverKey{Owner: owner.String(), RecoveryKeyId: 2, ExpectedNewSigningKeyId: 3, ExpectedRecoveryDelayBlocks: params.RecoveryDelayBlocks, NewSigningAlgorithm: pqctypes.Algorithm_ALGORITHM_ML_DSA_65, NewSigningPublicKey: pub, NewSigningKeyProof: proof}
	raw = auditResign(t, c, c.key, c.tx(t, c.key, nil, recoverMsg), 3000000, 1, signing.SignMode_SIGN_MODE_LEGACY_AMINO_JSON)
	decoded, err := c.app.TxConfig().TxDecoder()(raw)
	require.NoError(t, err)
	b, err := c.app.TxConfig().WrapTxBuilder(decoded)
	require.NoError(t, err)
	protoTx := b.(interface{ GetProtoTx() *txtypes.Tx }).GetProtoTx()
	acc := c.app.AccountKeeper.GetAccount(c.app.NewContext(true), owner)
	doc, err := pqctypes.NewRecoverySignDocV1(protoTx, params.NetworkId, "policy-test", acc.GetAccountNumber(), 1, 0, owner.String(), owner.String(), 2, 3, recoverMsg.NewSigningAlgorithm, pub, 1)
	require.NoError(t, err)
	bz, err := pqctypes.MarshalRecoverySignDocV1(doc)
	require.NoError(t, err)
	recoverMsg.RecoverySignature, err = recovery.Sign(context.Background(), bz, []byte(pqctypes.RecoverySignatureContext))
	require.NoError(t, err)
	require.NoError(t, b.SetMsgs(recoverMsg))
	raw, err = c.app.TxConfig().TxEncoder()(b.GetTx())
	require.NoError(t, err)
	raw = auditResign(t, c, c.key, raw, 3000000, 1, signing.SignMode_SIGN_MODE_LEGACY_AMINO_JSON)
	r = c.block(t, raw)
	require.NotZero(t, r.Code)
	require.Contains(t, r.Log, "DIRECT")
	t.Logf("valid amino recovery rejected: %s", r.Log)
	r = c.block(t, c.tx(t, c.key, factor, send))
	require.Zero(t, r.Code, r.Log)
}

func TestPQCAuthOpenRegistrationCanRetryAfterMessageFailure(t *testing.T) {
	for _, mode := range []pqctypes.EnforcementMode{pqctypes.EnforcementMode_ENFORCEMENT_MODE_OPTIONAL, pqctypes.EnforcementMode_ENFORCEMENT_MODE_REQUIRED} {
		t.Run(mode.String(), func(t *testing.T) {
			p := pqctypes.DefaultParams()
			p.EnforcementMode = mode
			c := newPQCChain(t, p)
			msg, factor := auditRegister(t, c)
			owner := sdk.AccAddress(c.key.PubKey().Address())
			raw := auditResign(t, c, c.key, c.tx(t, c.key, nil, msg), 679790, 0, signing.SignMode_SIGN_MODE_DIRECT)
			r := c.block(t, raw)
			require.NotZero(t, r.Code)
			require.Contains(t, r.Log, "out of gas")
			acc := c.app.AccountKeeper.GetAccount(c.app.NewContext(true), owner)
			require.Equal(t, uint64(1), acc.GetSequence())
			require.NotNil(t, acc.GetPubKey())
			_, found := c.app.PQCAuthKeeper.GetAccountPolicy(c.app.NewContext(true), owner)
			require.False(t, found)
			r = c.block(t, c.tx(t, c.key, nil, msg))
			require.Zero(t, r.Code, r.Log)
			c.block(t, nil)
			send := banktypes.NewMsgSend(owner, sdk.AccAddress(c.other.PubKey().Address()), sdk.NewCoins(sdk.NewInt64Coin(sdk.DefaultBondDenom, 1)))
			r = c.block(t, c.tx(t, c.key, factor, send))
			require.Zero(t, r.Code, r.Log)
		})
	}
}

func TestPQCAuthProposalPreservesSequenceDependencies(t *testing.T) {
	c := newPQCChain(t, minimumCapacityParams())
	akey, bkey := c.key, c.other
	amsg, _ := auditRegister(t, c)
	araw := c.tx(t, akey, nil, amsg)
	c.key = bkey
	bmsg, _ := auditRegister(t, c)
	braw := c.tx(t, bkey, nil, bmsg)
	c.key = akey
	send := banktypes.NewMsgSend(sdk.AccAddress(akey.PubKey().Address()), sdk.AccAddress(bkey.PubKey().Address()), sdk.NewCoins(sdk.NewInt64Coin(sdk.DefaultBondDenom, 1)))
	tail := auditResign(t, c, akey, c.tx(t, akey, nil, send), 3000000, 1, signing.SignMode_SIGN_MODE_DIRECT)
	txs := [][]byte{braw, araw, tail}
	for _, raw := range txs {
		r, err := c.app.CheckTx(&abci.RequestCheckTx{Tx: raw})
		require.NoError(t, err)
		require.Zero(t, r.Code, r.Log)
	}
	prepared, err := c.app.PrepareProposal(&abci.RequestPrepareProposal{Height: c.height + 1, Time: c.stamp.Add(time.Duration(c.height+1) * time.Second), MaxTxBytes: 1000000, Txs: txs})
	require.NoError(t, err)
	require.Equal(t, [][]byte{braw}, prepared.Txs)
	accepted, err := c.app.ProcessProposal(&abci.RequestProcessProposal{Height: c.height + 1, Txs: prepared.Txs})
	require.NoError(t, err)
	require.Equal(t, abci.ResponseProcessProposal_ACCEPT, accepted.Status)
	c.height++
	res, err := c.app.FinalizeBlock(&abci.RequestFinalizeBlock{Height: c.height, Time: c.stamp.Add(time.Duration(c.height) * time.Second), Txs: prepared.Txs})
	require.NoError(t, err)
	require.Len(t, res.TxResults, 1)
	require.Zero(t, res.TxResults[0].Code, res.TxResults[0].Log)
	_, err = c.app.Commit()
	require.NoError(t, err)
	c.block(t, nil)
	// The omitted account's sequence remains zero; its registration can retry.
	r := c.block(t, araw)
	require.Zero(t, r.Code, r.Log)
	t.Log("all 3 passed sequential CheckTx; budget truncates before A, preserving its prerequisites")
}
