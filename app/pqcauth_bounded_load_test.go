package app_test

import (
	"context"
	"testing"
	"time"

	pqcclient "github.com/DoraFactory/doravota/x/pqcauth/client"
	pqctypes "github.com/DoraFactory/doravota/x/pqcauth/types"
	abci "github.com/cometbft/cometbft/abci/types"
	tmproto "github.com/cometbft/cometbft/proto/tendermint/types"
	"github.com/cosmos/cosmos-sdk/crypto/keys/mldsa65"
	"github.com/cosmos/cosmos-sdk/crypto/keys/secp256k1"
	cryptotypes "github.com/cosmos/cosmos-sdk/crypto/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
	txtypes "github.com/cosmos/cosmos-sdk/types/tx"
	banktypes "github.com/cosmos/cosmos-sdk/x/bank/types"
	"github.com/stretchr/testify/require"
)

// A bounded, deterministic application workload, not a network fairness or
// minimum-hardware benchmark. Keep the default 750 price and 400/block budget.
func TestPQCAuthBoundedMixedBudgetAndRecovery(t *testing.T) {
	p := pqctypes.DefaultParams()
	p.RecoveryDelayBlocks = 4 // Shorten only the recovery window in this fixture.
	c := newPQCChain(t, p)
	native, err := mldsa65.GenPrivKey()
	require.NoError(t, err)
	plain := secp256k1.GenPrivKey()
	for _, key := range []cryptotypes.PrivKey{&native, plain} {
		fund := banktypes.NewMsgSend(sdk.AccAddress(c.key.PubKey().Address()), sdk.AccAddress(key.PubKey().Address()), sdk.NewCoins(sdk.NewInt64Coin(sdk.DefaultBondDenom, 100000)))
		r := c.block(t, c.tx(t, c.key, nil, fund))
		require.Zero(t, r.Code, r.Log)
	}
	ownerKey := c.key
	c.key = c.other
	hybrid, _ := reviewEnroll(t, c)
	c.key = ownerKey
	ownerFactor, recovery, replacement := reviewEnrollWithRecovery(t, c)
	ctx := c.app.NewNextBlockContext(tmproto.Header{ChainID: "policy-test", Height: c.height + 1})
	cp, err := c.app.ConsensusParamsKeeper.ParamsStore.Get(ctx)
	require.NoError(t, err)
	cp.Block.MaxGas, cp.Block.MaxBytes = 600_000_000, 10_000_000
	require.NoError(t, c.app.ConsensusParamsKeeper.ParamsStore.Set(ctx, cp))
	c.app.SimWriteState()
	c.block(t, nil)
	owner := sdk.AccAddress(c.key.PubKey().Address())
	policy, ok := c.app.PQCAuthKeeper.GetEffectiveAccountPolicy(c.app.NewContext(true).WithBlockHeight(c.height+1), owner)
	require.True(t, ok)
	pub, proof := reviewProof(t, c, replacement, 3, pqctypes.KeyRole_KEY_ROLE_SIGNING, pqctypes.PurposeRecoverSigning, policy.PolicyVersion, pqctypes.RecoveryKeyProofContext)
	msg := &pqctypes.MsgRecoverKey{Owner: owner.String(), RecoveryKeyId: 2, ExpectedNewSigningKeyId: 3, ExpectedRecoveryDelayBlocks: 4, NewSigningAlgorithm: pqctypes.Algorithm_ALGORITHM_ML_DSA_65, NewSigningPublicKey: pub, NewSigningKeyProof: proof}
	unsigned, err := c.app.TxConfig().TxDecoder()(c.tx(t, c.key, nil, msg))
	require.NoError(t, err)
	acc := c.app.AccountKeeper.GetAccount(c.app.NewContext(true), owner)
	doc, err := pqctypes.NewRecoverySignDocV1(unsigned.(interface{ GetProtoTx() *txtypes.Tx }).GetProtoTx(), c.app.PQCAuthKeeper.GetParams(c.app.NewContext(true)).NetworkId, "policy-test", acc.GetAccountNumber(), acc.GetSequence(), 0, owner.String(), owner.String(), 2, 3, msg.NewSigningAlgorithm, pub, policy.PolicyVersion)
	require.NoError(t, err)
	bz, err := pqctypes.MarshalRecoverySignDocV1(doc)
	require.NoError(t, err)
	msg.RecoverySignature, err = recovery.Sign(context.Background(), bz, []byte(pqctypes.RecoverySignatureContext))
	require.NoError(t, err)
	escape := c.tx(t, c.key, nil, msg)
	// Three saturated blocks postpone recovery. Prioritize it in the fourth;
	// then postpone cancellation once and prioritize it before its deadline.
	for round := 0; round < 6; round++ {
		var noise [][]byte
		for i := uint64(0); i < 200; i++ {
			noise = append(noise,
				selectionTxWithGas(t, c, 500000, []cryptotypes.PrivKey{&native}, nil, []uint64{i}, nil, selectionSend(&native, ownerKey)),
				selectionTxWithGas(t, c, 500000, []cryptotypes.PrivKey{c.other}, []pqcclient.PQCSigner{hybrid}, []uint64{i}, nil, selectionSend(c.other, ownerKey)))
		}
		ordinary := selectionTxWithGas(t, c, 500000, []cryptotypes.PrivKey{plain}, nil, []uint64{0}, nil, selectionSend(plain, ownerKey))
		prioritized := round == 3 || round == 5
		var candidates, want [][]byte
		if prioritized {
			cost := 2
			if round == 5 {
				cost = 1
			}
			candidates = append([][]byte{escape}, noise...)
			want = append([][]byte{escape}, noise[:400-cost]...)
		} else {
			candidates = append(append([][]byte{}, noise...), escape)
			want = append([][]byte{}, noise...)
		}
		candidates, want = append(candidates, ordinary), append(want, ordinary)
		start := time.Now()
		selectionCheck(t, c, candidates)
		checkTime := time.Since(start)
		h := c.height + 1
		stamp := c.stamp.Add(time.Duration(h) * time.Second)
		start = time.Now()
		prepared, err := c.app.PrepareProposal(&abci.RequestPrepareProposal{Height: h, Time: stamp, MaxTxBytes: 10_000_000, Txs: candidates})
		require.NoError(t, err)
		require.Equal(t, want, prepared.Txs)
		prepareTime := time.Since(start)
		processed, err := c.app.ProcessProposal(&abci.RequestProcessProposal{Height: h, Time: stamp, Txs: prepared.Txs})
		require.NoError(t, err)
		require.Equal(t, abci.ResponseProcessProposal_ACCEPT, processed.Status)
		start = time.Now()
		result, err := c.app.FinalizeBlock(&abci.RequestFinalizeBlock{Height: h, Time: stamp, Txs: prepared.Txs})
		require.NoError(t, err)
		require.Len(t, result.TxResults, len(want))
		var gas int64
		for _, r := range result.TxResults {
			require.Zero(t, r.Code, r.Log)
			gas += r.GasUsed
		}
		_, err = c.app.Commit()
		require.NoError(t, err)
		c.height = h
		t.Logf("round=%d candidates=%d included=%d prioritized_escape=%t gas=%d check=%s prepare=%s finalize_commit=%s", round, len(candidates), len(want), prioritized, gas, checkTime, prepareTime, time.Since(start))
		state, found := c.app.PQCAuthKeeper.GetEffectiveAccountPolicy(c.app.NewContext(true).WithBlockHeight(c.height), owner)
		require.True(t, found)
		if round < 3 || round == 5 {
			require.Zero(t, state.PendingSigningKeyId)
		} else {
			require.Equal(t, uint64(3), state.PendingSigningKeyId)
		}
		if round == 3 {
			escape = c.tx(t, c.key, ownerFactor, &pqctypes.MsgCancelRecovery{Owner: owner.String(), ExpectedPendingSigningKeyId: 3, ExpectedPendingPolicyVersion: state.PendingPolicyVersion})
		}
		require.True(t, c.app.PQCAuthKeeper.AuditState(c.app.NewContext(true).WithBlockHeight(c.height), 100).Consistent)
	}
	c.block(t, nil)
	r := c.block(t, c.tx(t, c.key, ownerFactor, selectionSend(c.key, plain)))
	require.Zero(t, r.Code, r.Log)
}

// Invalid factors are signed by the correct classic key: these requests reach
// PQC verification, rather than merely failing outer signature verification.
func TestPQCAuthBoundedInvalidAdmission(t *testing.T) {
	c := newPQCChain(t)
	factor, _ := reviewEnroll(t, c)
	wrong := capacityFactor(t, c)
	bad := c.tx(t, c.key, wrong, selectionSend(c.key, c.other))
	good := c.tx(t, c.key, factor, selectionSend(c.key, c.other))
	owner := sdk.AccAddress(c.key.PubKey().Address())
	before := c.app.AccountKeeper.GetAccount(c.app.NewContext(true), owner).GetSequence()
	balance := c.app.BankKeeper.GetBalance(c.app.NewContext(true), owner, sdk.DefaultBondDenom)
	for _, kind := range []abci.CheckTxType{abci.CheckTxType_New, abci.CheckTxType_Recheck} {
		start := time.Now()
		for i := 0; i < 300; i++ {
			r, err := c.app.CheckTx(&abci.RequestCheckTx{Tx: bad, Type: kind})
			require.NoError(t, err)
			require.NotZero(t, r.Code)
			require.Contains(t, r.Log, "invalid PQC signature at signer index 0")
		}
		t.Logf("invalid_admission type=%s requests=300 elapsed=%s", kind, time.Since(start))
	}
	start := time.Now()
	for i := 0; i < 100; i++ {
		_, _, err := c.app.Simulate(good)
		require.NoError(t, err)
	}
	t.Logf("simulation requests=100 elapsed=%s (simulation does not prove cryptographic validity)", time.Since(start))
	require.Equal(t, before, c.app.AccountKeeper.GetAccount(c.app.NewContext(true), owner).GetSequence())
	require.Equal(t, balance, c.app.BankKeeper.GetBalance(c.app.NewContext(true), owner, sdk.DefaultBondDenom))
	r := c.block(t, bad)
	require.NotZero(t, r.Code)
	require.Equal(t, before, c.app.AccountKeeper.GetAccount(c.app.NewContext(true), owner).GetSequence())
	require.Equal(t, balance, c.app.BankKeeper.GetBalance(c.app.NewContext(true), owner, sdk.DefaultBondDenom))
	selectionCheck(t, c, [][]byte{good})
	r = c.block(t, good)
	require.Zero(t, r.Code, r.Log)
	c.block(t, nil)
	require.True(t, c.app.PQCAuthKeeper.AuditState(c.app.NewContext(true).WithBlockHeight(c.height), 100).Consistent)
}
