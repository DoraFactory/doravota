package app_test

import (
	"testing"
	"time"

	pqcclient "github.com/DoraFactory/doravota/x/pqcauth/client"
	pqckeeper "github.com/DoraFactory/doravota/x/pqcauth/keeper"
	pqctypes "github.com/DoraFactory/doravota/x/pqcauth/types"
	abci "github.com/cometbft/cometbft/abci/types"
	tmproto "github.com/cometbft/cometbft/proto/tendermint/types"
	"github.com/cosmos/cosmos-sdk/crypto/keys/secp256k1"
	cryptotypes "github.com/cosmos/cosmos-sdk/crypto/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
	banktypes "github.com/cosmos/cosmos-sdk/x/bank/types"
	"github.com/stretchr/testify/require"
)

func recheckResult(t *testing.T, c *pqcChain, raw []byte, kind abci.CheckTxType) *abci.ResponseCheckTx {
	t.Helper()
	r, err := c.app.CheckTx(&abci.RequestCheckTx{Tx: raw, Type: kind})
	require.NoError(t, err)
	return r
}

// Real signatures and normal CheckTx -> empty committed block -> Recheck ->
// FinalizeBlock, rather than injecting never-admitted invalid bytes as recheck.
// Invalid variants below are deliberately synthetic and test the trust boundary.
func recheckFixture(t *testing.T, operation, invalid string) (*pqcChain, []byte) {
	t.Helper()
	p := pqctypes.DefaultParams()
	p.RecoveryDelayBlocks = 3
	c := newPQCChain(t, p)
	if operation == "register" {
		msg, _ := auditRegister(t, c)
		if invalid != "" {
			msg.SigningKeyProof[0] ^= 1
		}
		return c, c.tx(t, c.key, nil, msg)
	}
	factor, recovery, next := reviewEnrollWithRecovery(t, c)
	owner := sdk.AccAddress(c.key.PubKey().Address()).String()
	var msg sdk.Msg
	switch operation {
	case "send":
		msg = selectionSend(c.key, c.other)
	case "rotate", "rotate-recovery":
		role, purpose, domain := pqctypes.KeyRole_KEY_ROLE_SIGNING, pqctypes.PurposeRotateSigning, pqctypes.RotateProofContext
		if operation == "rotate-recovery" {
			role, purpose, domain = pqctypes.KeyRole_KEY_ROLE_RECOVERY, pqctypes.PurposeRotateRecovery, pqctypes.RotateRecoveryContext
		}
		pub, proof := reviewProof(t, c, next, 3, role, purpose, 1, domain)
		if invalid == "proof" {
			proof[0] ^= 1
		}
		if operation == "rotate" {
			msg = &pqctypes.MsgRotateKey{Owner: owner, ExpectedNewKeyId: 3, NewAlgorithm: pqctypes.Algorithm_ALGORITHM_ML_DSA_65, NewPublicKey: pub, NewKeyProof: proof}
		} else {
			msg = &pqctypes.MsgRotateRecoveryKey{Owner: owner, ExpectedNewKeyId: 3, NewAlgorithm: pqctypes.Algorithm_ALGORITHM_ML_DSA_65, NewPublicKey: pub, NewKeyProof: proof}
		}
	case "recover", "recover-protected-payer", "cancel":
		var payer pqcclient.PQCSigner
		if operation == "recover-protected-payer" {
			original := c.key
			c.key = c.other
			payer, _ = reviewEnroll(t, c)
			c.key = original
		}
		pub, proof := reviewProof(t, c, next, 3, pqctypes.KeyRole_KEY_ROLE_SIGNING, pqctypes.PurposeRecoverSigning, 1, pqctypes.RecoveryKeyProofContext)
		if invalid == "proof" {
			proof[0] ^= 1
		}
		r := &pqctypes.MsgRecoverKey{Owner: owner, RecoveryKeyId: 2, ExpectedNewSigningKeyId: 3, ExpectedRecoveryDelayBlocks: 3, NewSigningAlgorithm: pqctypes.Algorithm_ALGORITHM_ML_DSA_65, NewSigningPublicKey: pub, NewSigningKeyProof: proof}
		if invalid == "recovery" {
			recovery = capacityFactor(t, c)
		}
		if invalid == "payer" {
			payer = capacityFactor(t, c)
		}
		raw := capacityPayerTx(t, c, r, nil, payer, recovery)
		if operation != "cancel" {
			return c, raw
		}
		result := c.block(t, raw)
		require.Zero(t, result.Code, result.Log)
		msg = &pqctypes.MsgCancelRecovery{Owner: owner, ExpectedPendingSigningKeyId: 3, ExpectedPendingPolicyVersion: 2}
	default:
		t.Fatalf("unknown operation %q", operation)
	}
	if invalid == "factor" {
		factor = capacityFactor(t, c)
	}
	return c, c.tx(t, c.key, factor, msg)
}

func TestPQCAuthRecheckPreservesGasAndDelivery(t *testing.T) {
	for _, operation := range []string{"register", "send", "rotate", "rotate-recovery", "recover", "recover-protected-payer", "cancel"} {
		t.Run(operation, func(t *testing.T) {
			c, raw := recheckFixture(t, operation, "")
			first := recheckResult(t, c, raw, abci.CheckTxType_New)
			require.Zero(t, first.Code, first.Log)
			c.block(t, nil)
			again := recheckResult(t, c, raw, abci.CheckTxType_Recheck)
			require.Zero(t, again.Code, again.Log)
			require.Equal(t, first.GasWanted, again.GasWanted)
			// Crypto prices are asserted separately with recording gas meters.
			// Store reads can differ across heights for first registration and
			// pending recovery; total SDK gas is not a crypto-only measurement.
			if operation != "register" && operation != "cancel" {
				require.Equal(t, first.GasUsed, again.GasUsed)
			}
			t.Logf("operation=%s new_gas=%d recheck_gas=%d", operation, first.GasUsed, again.GasUsed)
			r := c.block(t, raw)
			require.Zero(t, r.Code, r.Log)
			c.block(t, nil)
			require.True(t, c.app.PQCAuthKeeper.AuditState(c.app.NewContext(true).WithBlockHeight(c.height), 100).Consistent)
		})
	}
}

func TestPQCAuthRecheckDoesNotAuthenticateNewBytes(t *testing.T) {
	for _, tc := range []struct{ operation, invalid string }{
		{"send", "factor"}, {"register", "proof"}, {"rotate", "proof"},
		{"rotate-recovery", "proof"}, {"recover", "proof"}, {"recover", "recovery"},
		{"recover-protected-payer", "payer"}, {"cancel", "factor"},
	} {
		t.Run(tc.operation+"/"+tc.invalid, func(t *testing.T) {
			c, raw := recheckFixture(t, tc.operation, tc.invalid)
			owner := sdk.AccAddress(c.key.PubKey().Address())
			before := c.app.AccountKeeper.GetAccount(c.app.NewContext(true), owner).GetSequence()
			balance := c.app.BankKeeper.GetBalance(c.app.NewContext(true), owner, sdk.DefaultBondDenom)
			first := recheckResult(t, c, raw, abci.CheckTxType_New)
			require.NotZero(t, first.Code, "invalid bytes must never enter the mempool")
			c.block(t, nil)
			// Synthetic ABCI call: no real CometBFT mempool rechecks a rejected tx.
			again := recheckResult(t, c, raw, abci.CheckTxType_Recheck)
			require.Zero(t, again.Code, again.Log)
			r := c.block(t, raw)
			require.NotZero(t, r.Code, "even a malicious proposer cannot reuse recheck to bypass delivery verification")
			require.Equal(t, before, c.app.AccountKeeper.GetAccount(c.app.NewContext(true), owner).GetSequence())
			require.Equal(t, balance, c.app.BankKeeper.GetBalance(c.app.NewContext(true), owner, sdk.DefaultBondDenom))
		})
	}
}

func TestPQCAuthRecheckRejectsChangedPolicy(t *testing.T) {
	for _, operation := range []string{"rotate", "rotate-recovery", "disable-protection", "recover"} {
		t.Run(operation, func(t *testing.T) {
			var c *pqcChain
			var head []byte
			var factor pqcclient.PQCSigner
			if operation == "disable-protection" {
				c = newPQCChain(t)
				factor, _ = reviewEnroll(t, c)
				head = c.tx(t, c.key, factor, &pqctypes.MsgSetProtection{Owner: sdk.AccAddress(c.key.PubKey().Address()).String(), Enabled: false})
			} else {
				p := pqctypes.DefaultParams()
				p.RecoveryDelayBlocks = 3
				c = newPQCChain(t, p)
				var recovery, next pqcclient.PQCSigner
				factor, recovery, next = reviewEnrollWithRecovery(t, c)
				owner := sdk.AccAddress(c.key.PubKey().Address()).String()
				role, purpose, domain := pqctypes.KeyRole_KEY_ROLE_SIGNING, pqctypes.PurposeRotateSigning, pqctypes.RotateProofContext
				if operation == "rotate-recovery" {
					role, purpose, domain = pqctypes.KeyRole_KEY_ROLE_RECOVERY, pqctypes.PurposeRotateRecovery, pqctypes.RotateRecoveryContext
				} else if operation == "recover" {
					purpose, domain = pqctypes.PurposeRecoverSigning, pqctypes.RecoveryKeyProofContext
				}
				pub, proof := reviewProof(t, c, next, 3, role, purpose, 1, domain)
				switch operation {
				case "rotate":
					head = c.tx(t, c.key, factor, &pqctypes.MsgRotateKey{Owner: owner, ExpectedNewKeyId: 3, NewAlgorithm: pqctypes.Algorithm_ALGORITHM_ML_DSA_65, NewPublicKey: pub, NewKeyProof: proof})
				case "rotate-recovery":
					head = c.tx(t, c.key, factor, &pqctypes.MsgRotateRecoveryKey{Owner: owner, ExpectedNewKeyId: 3, NewAlgorithm: pqctypes.Algorithm_ALGORITHM_ML_DSA_65, NewPublicKey: pub, NewKeyProof: proof})
				case "recover":
					p := c.app.PQCAuthKeeper.GetParams(c.app.NewContext(true))
					head = capacityPayerTx(t, c, &pqctypes.MsgRecoverKey{Owner: owner, RecoveryKeyId: 2, ExpectedNewSigningKeyId: 3, ExpectedRecoveryDelayBlocks: p.RecoveryDelayBlocks, NewSigningAlgorithm: pqctypes.Algorithm_ALGORITHM_ML_DSA_65, NewSigningPublicKey: pub, NewSigningKeyProof: proof}, nil, nil, recovery)
				}
			}
			tail := selectionTx(t, c, []cryptotypes.PrivKey{c.key}, []pqcclient.PQCSigner{factor}, []uint64{1}, nil, selectionSend(c.key, c.other))
			selectionCheck(t, c, [][]byte{head, tail})
			r := c.block(t, head)
			require.Zero(t, r.Code, r.Log)
			if operation == "recover" {
				p, _ := c.app.PQCAuthKeeper.GetAccountPolicy(c.app.NewContext(true), sdk.AccAddress(c.key.PubKey().Address()))
				for uint64(c.height+1) < p.PendingEffectiveHeight {
					c.block(t, nil)
				}
			}
			c.block(t, nil)
			rc := recheckResult(t, c, tail, abci.CheckTxType_Recheck)
			require.NotZero(t, rc.Code)
			require.Contains(t, rc.Log, "key or policy mismatch")
			r = c.block(t, tail)
			require.NotZero(t, r.Code)
		})
	}
}

func TestPQCAuthRecheckRejectsPauseAndSequence(t *testing.T) {
	for _, pause := range []bool{false, true} {
		t.Run(map[bool]string{false: "sequence", true: "pause"}[pause], func(t *testing.T) {
			c, raw := recheckFixture(t, "send", "")
			selectionCheck(t, c, [][]byte{raw})
			if pause {
				ctx := c.app.NewNextBlockContext(tmproto.Header{ChainID: "policy-test", Height: c.height + 1})
				p := c.app.PQCAuthKeeper.GetParams(ctx)
				p.EmergencyMode = pqctypes.EmergencyMode_EMERGENCY_MODE_PAUSE_PQC_TRANSACTIONS
				_, err := pqckeeper.NewMsgServer(c.app.PQCAuthKeeper).UpdateParams(ctx, &pqctypes.MsgUpdateParams{Authority: c.app.PQCAuthKeeper.Authority(), Params: p, EmergencyOnly: true})
				require.NoError(t, err)
				c.app.SimWriteState()
				c.block(t, nil)
				c.block(t, nil)
			} else {
				r := c.block(t, raw)
				require.Zero(t, r.Code, r.Log)
			}
			rc := recheckResult(t, c, raw, abci.CheckTxType_Recheck)
			require.NotZero(t, rc.Code)
			if pause {
				require.Contains(t, rc.Log, "pause")
			} else {
				require.Contains(t, rc.Log, "sequence")
			}
		})
	}
}

func TestPQCAuthRecheckRequiresOrderedLifecycle(t *testing.T) {
	c := newPQCChain(t)
	// An unordered owner operation could change policy version without moving
	// sequence. Recovery sign docs derive that version from state, not a field
	// in MsgRecoverKey. Revisit crypto-result reuse before enabling this SDK opt-in.
	require.False(t, c.app.AccountKeeper.UnorderedTransactionsEnabled())
	raw := c.tx(t, c.key, nil, selectionSend(c.key, c.other))
	decoded, err := c.app.TxConfig().TxDecoder()(raw)
	require.NoError(t, err)
	b, err := c.app.TxConfig().WrapTxBuilder(decoded)
	require.NoError(t, err)
	b.SetUnordered(true)
	b.SetTimeoutTimestamp(c.stamp.Add(time.Minute))
	raw, err = c.app.TxConfig().TxEncoder()(b.GetTx())
	require.NoError(t, err)
	for _, kind := range []abci.CheckTxType{abci.CheckTxType_New, abci.CheckTxType_Recheck} {
		r := recheckResult(t, c, raw, kind)
		require.NotZero(t, r.Code)
		require.Contains(t, r.Log, "unordered transactions are not enabled")
	}
}

// Bounded application benchmark: 200 sequential real CheckTx admissions and
// three rechecks after empty commits. This is NOT a 5,000-entry CometBFT or
// multi-node workload, and has no hardware-specific timing pass threshold.
func TestPQCAuthRecheckBoundedSevenSigners(t *testing.T) {
	c := newPQCChain(t)
	keys := []cryptotypes.PrivKey{c.key}
	factor, _ := reviewEnroll(t, c)
	factors := []pqcclient.PQCSigner{factor}
	for i := 1; i < 7; i++ {
		key := secp256k1.GenPrivKey()
		fund := banktypes.NewMsgSend(sdk.AccAddress(c.key.PubKey().Address()), sdk.AccAddress(key.PubKey().Address()), sdk.NewCoins(sdk.NewInt64Coin(sdk.DefaultBondDenom, 100000)))
		r := c.block(t, c.tx(t, c.key, factor, fund))
		require.Zero(t, r.Code, r.Log)
		original := c.key
		c.key = key
		f, _ := reviewEnroll(t, c)
		c.key = original
		keys, factors = append(keys, key), append(factors, f)
	}
	msgs := make([]sdk.Msg, len(keys))
	for i, key := range keys {
		msgs[i] = selectionSend(key, c.other)
	}
	const n = 200
	txs := make([][]byte, n)
	for i := range txs {
		offsets := make([]uint64, len(keys))
		for j := range offsets {
			offsets[j] = uint64(i)
		}
		txs[i] = selectionTxWithGas(t, c, 1_000_000, keys, factors, offsets, nil, msgs...)
	}
	var baselineGas int64
	for round := 0; round < 4; round++ {
		kind := abci.CheckTxType_New
		if round > 0 {
			kind = abci.CheckTxType_Recheck
		}
		start := time.Now()
		for i, raw := range txs {
			r := recheckResult(t, c, raw, kind)
			require.Zero(t, r.Code, r.Log)
			if i == 0 {
				if round == 0 {
					baselineGas = r.GasUsed
				} else {
					require.Equal(t, baselineGas, r.GasUsed)
				}
			}
		}
		t.Logf("mode=%s round=%d count=%d bytes=%d first_gas=%d elapsed=%s us_per_tx=%.1f", kind, round, n, len(txs[0]), baselineGas, time.Since(start), float64(time.Since(start).Microseconds())/n)
		c.block(t, nil)
	}
	// Delivery still independently verifies all seven factors.
	r := c.block(t, txs[0])
	require.Zero(t, r.Code, r.Log)
}
