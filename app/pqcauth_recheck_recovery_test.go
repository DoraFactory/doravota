package app_test

// Regression adapted from Claude ROUND9's review probe: a recovery transaction admitted
// against policy version V, followed by the same account's earlier-sequence
// SetProtection that moves the policy to V+1. MsgRecoverKey carries no
// extension entry, so its policy binding exists only inside the signed
// recovery/key-proof documents.

import (
	"context"
	"testing"

	pqcclient "github.com/DoraFactory/doravota/x/pqcauth/client"
	pqctypes "github.com/DoraFactory/doravota/x/pqcauth/types"
	abci "github.com/cometbft/cometbft/abci/types"
	sdktx "github.com/cosmos/cosmos-sdk/client/tx"
	sdk "github.com/cosmos/cosmos-sdk/types"
	txtypes "github.com/cosmos/cosmos-sdk/types/tx"
	"github.com/cosmos/cosmos-sdk/types/tx/signing"
	authsigning "github.com/cosmos/cosmos-sdk/x/auth/signing"
	"github.com/stretchr/testify/require"
)

func recoverTxAtSequenceForRecheck(t *testing.T, c *pqcChain, msg *pqctypes.MsgRecoverKey, recoveryFactor pqcclient.PQCSigner, seq uint64) []byte {
	t.Helper()
	ctx := c.app.NewContext(true).WithBlockHeight(c.height + 1)
	owner := sdk.AccAddress(c.key.PubKey().Address())
	acc := c.app.AccountKeeper.GetAccount(ctx, owner)
	b := c.app.TxConfig().NewTxBuilder()
	require.NoError(t, b.SetMsgs(msg))
	b.SetGasLimit(3_000_000)
	b.SetFeeAmount(sdk.NewCoins(sdk.NewInt64Coin(sdk.DefaultBondDenom, 10)))
	require.NoError(t, b.SetSignatures(signing.SignatureV2{PubKey: c.key.PubKey(), Sequence: seq, Data: &signing.SingleSignatureData{SignMode: signing.SignMode_SIGN_MODE_DIRECT}}))
	params := c.app.PQCAuthKeeper.GetParams(ctx)
	policy, _ := c.app.PQCAuthKeeper.GetEffectiveAccountPolicy(ctx, owner)
	protoTx := b.(interface{ GetProtoTx() *txtypes.Tx }).GetProtoTx()
	doc, err := pqctypes.NewRecoverySignDocV1(protoTx, params.NetworkId, "policy-test", acc.GetAccountNumber(), seq, 0, owner.String(), owner.String(), msg.RecoveryKeyId, msg.ExpectedNewSigningKeyId, msg.NewSigningAlgorithm, msg.NewSigningPublicKey, policy.PolicyVersion)
	require.NoError(t, err)
	bz, err := pqctypes.MarshalRecoverySignDocV1(doc)
	require.NoError(t, err)
	msg.RecoverySignature, err = recoveryFactor.Sign(context.Background(), bz, []byte(pqctypes.RecoverySignatureContext))
	require.NoError(t, err)
	require.NoError(t, b.SetMsgs(msg))
	sig, err := sdktx.SignWithPrivKey(context.Background(), signing.SignMode_SIGN_MODE_DIRECT, authsigning.SignerData{Address: owner.String(), ChainID: "policy-test", AccountNumber: acc.GetAccountNumber(), Sequence: seq, PubKey: c.key.PubKey()}, b, c.key, c.app.TxConfig(), seq)
	require.NoError(t, err)
	require.NoError(t, b.SetSignatures(sig))
	raw, err := c.app.TxConfig().TxEncoder()(b.GetTx())
	require.NoError(t, err)
	return raw
}

func TestPQCAuthRecheckEvictsStaleRecoveryDuringPendingPolicy(t *testing.T) {
	p := pqctypes.DefaultParams()
	p.RecoveryDelayBlocks = 3
	c := newPQCChain(t, p)
	factor, recovery, next := reviewEnrollWithRecovery(t, c)
	owner := sdk.AccAddress(c.key.PubKey().Address())
	ctx := c.app.NewContext(true).WithBlockHeight(c.height + 1)
	seq := c.app.AccountKeeper.GetAccount(ctx, owner).GetSequence()
	policy, found := c.app.PQCAuthKeeper.GetEffectiveAccountPolicy(ctx, owner)
	require.True(t, found)
	t.Logf("start: height=%d seq=%d policy_version=%d self_enforced=%v", c.height, seq, policy.PolicyVersion, policy.SelfEnforced)

	head := c.tx(t, c.key, factor, &pqctypes.MsgSetProtection{Owner: owner.String(), Enabled: !policy.SelfEnforced})
	pub, proof := reviewProof(t, c, next, 3, pqctypes.KeyRole_KEY_ROLE_SIGNING, pqctypes.PurposeRecoverSigning, policy.PolicyVersion, pqctypes.RecoveryKeyProofContext)
	tail := recoverTxAtSequenceForRecheck(t, c, &pqctypes.MsgRecoverKey{Owner: owner.String(), RecoveryKeyId: 2, ExpectedNewSigningKeyId: 3, ExpectedRecoveryDelayBlocks: 3, NewSigningAlgorithm: pqctypes.Algorithm_ALGORITHM_ML_DSA_65, NewSigningPublicKey: pub, NewSigningKeyProof: proof}, recovery, seq+1)

	check := func(raw []byte, kind abci.CheckTxType) *abci.ResponseCheckTx {
		res, err := c.app.CheckTx(&abci.RequestCheckTx{Tx: raw, Type: kind})
		require.NoError(t, err)
		return res
	}
	r := check(head, abci.CheckTxType_New)
	require.Zero(t, r.Code, r.Log)
	r = check(tail, abci.CheckTxType_New)
	require.Zero(t, r.Code, r.Log)
	t.Logf("both admitted by CheckTx(New): SetProtection seq=%d, RecoverKey seq=%d (bound to policy_version=%d)", seq, seq+1, policy.PolicyVersion)

	res := c.block(t, head)
	require.Zero(t, res.Code, res.Log)
	r = check(tail, abci.CheckTxType_Recheck)
	t.Logf("recheck after SetProtection committed at height %d: code=%d log=%q", c.height, r.Code, r.Log)
	require.NotZero(t, r.Code, "real CometBFT evicts here: first recheck sees the pending change")
	require.Contains(t, r.Log, "policy change is already pending")
	// Below: the same bytes are rechecked again only to probe the trust boundary.
	for i := 1; i <= 2; i++ {
		c.block(t, nil)
		after, _ := c.app.PQCAuthKeeper.GetEffectiveAccountPolicy(c.app.NewContext(true).WithBlockHeight(c.height+1), owner)
		r = check(tail, abci.CheckTxType_Recheck)
		t.Logf("recheck at height %d (effective policy_version=%d): code=%d log=%q", c.height, after.PolicyVersion, r.Code, r.Log)
	}

	// NewContext(true) reads CheckTx state, which a passing recheck mutates.
	// Commit an empty block first so the snapshot equals committed state.
	c.block(t, nil)
	balance := c.app.BankKeeper.GetBalance(c.app.NewContext(true), owner, sdk.DefaultBondDenom)
	seqBefore := c.app.AccountKeeper.GetAccount(c.app.NewContext(true), owner).GetSequence()
	policyBefore, _ := c.app.PQCAuthKeeper.GetAccountPolicy(c.app.NewContext(true), owner)
	res = c.block(t, tail)
	t.Logf("FinalizeBlock of the stale recovery: code=%d log=%q", res.Code, res.Log)
	require.NotZero(t, res.Code)
	require.Equal(t, balance, c.app.BankKeeper.GetBalance(c.app.NewContext(true), owner, sdk.DefaultBondDenom))
	require.Equal(t, seqBefore, c.app.AccountKeeper.GetAccount(c.app.NewContext(true), owner).GetSequence())
	policyAfter, _ := c.app.PQCAuthKeeper.GetAccountPolicy(c.app.NewContext(true), owner)
	require.Equal(t, policyBefore, policyAfter)
	t.Logf("state unchanged after failed execution: balance, sequence and policy identical")
}
