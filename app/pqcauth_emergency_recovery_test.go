package app_test

import (
	"context"
	"testing"

	pqcante "github.com/DoraFactory/doravota/x/pqcauth/ante"
	pqckeeper "github.com/DoraFactory/doravota/x/pqcauth/keeper"
	pqctypes "github.com/DoraFactory/doravota/x/pqcauth/types"
	abci "github.com/cometbft/cometbft/abci/types"
	tmproto "github.com/cometbft/cometbft/proto/tendermint/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
	txtypes "github.com/cosmos/cosmos-sdk/types/tx"
	"github.com/cosmos/cosmos-sdk/types/tx/signing"
	authsigning "github.com/cosmos/cosmos-sdk/x/auth/signing"
	"github.com/stretchr/testify/require"
)

func TestPQCAuthFullPauseProtectedRecoveryPayer(t *testing.T) {
	for _, tc := range []struct {
		name                                       string
		pause, protectedPayer, omitFactor, selfPay bool
		invalid                                    string
	}{
		{name: "normal-protected-payer", protectedPayer: true},
		{name: "paused-protected-payer", pause: true, protectedPayer: true},
		{name: "paused-protected-payer-without-extension", pause: true, protectedPayer: true, omitFactor: true},
		{name: "paused-unprotected-payer", pause: true},
		{name: "paused-owner-self-pay", pause: true, selfPay: true},
		{name: "paused-bad-payer-factor", pause: true, protectedPayer: true, invalid: "payer"},
		{name: "paused-bad-recovery-factor", pause: true, protectedPayer: true, invalid: "recovery"},
		{name: "paused-bad-new-key-proof", pause: true, protectedPayer: true, invalid: "proof"},
		{name: "paused-bad-owner-signature", pause: true, protectedPayer: true, invalid: "owner"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := newPQCChain(t, minimumCapacityParams())
			payerFactor := capacityFactor(t, c)
			if tc.protectedPayer {
				original := c.key
				c.key = c.other
				payerFactor, _ = reviewEnroll(t, c)
				c.key = original
			}
			_, recovery, replacement := reviewEnrollWithRecovery(t, c)
			if tc.pause {
				ctx := c.app.NewNextBlockContext(tmproto.Header{ChainID: "policy-test", Height: c.height + 1})
				p := c.app.PQCAuthKeeper.GetParams(ctx)
				p.EmergencyMode = pqctypes.EmergencyMode_EMERGENCY_MODE_PAUSE_PQC_TRANSACTIONS
				r, err := pqckeeper.NewMsgServer(c.app.PQCAuthKeeper).UpdateParams(ctx, &pqctypes.MsgUpdateParams{Authority: c.app.PQCAuthKeeper.Authority(), Params: p})
				require.NoError(t, err)
				c.app.SimWriteState()
				for uint64(c.height) <= r.ActivationHeight {
					c.block(t, nil)
				}
				require.Equal(t, pqctypes.EmergencyMode_EMERGENCY_MODE_PAUSE_PQC_TRANSACTIONS, c.app.PQCAuthKeeper.GetParams(c.app.NewContext(true)).Effective(c.height).EmergencyMode)
			}
			owner := sdk.AccAddress(c.key.PubKey().Address())
			payer := sdk.AccAddress(c.other.PubKey().Address())
			beforeOwner := c.app.AccountKeeper.GetAccount(c.app.NewContext(true), owner).GetSequence()
			beforePayer := c.app.AccountKeeper.GetAccount(c.app.NewContext(true), payer).GetSequence()
			beforeOwnerBalance := c.app.BankKeeper.GetBalance(c.app.NewContext(true), owner, sdk.DefaultBondDenom)
			beforePayerBalance := c.app.BankKeeper.GetBalance(c.app.NewContext(true), payer, sdk.DefaultBondDenom)
			policy, found := c.app.PQCAuthKeeper.GetEffectiveAccountPolicy(c.app.NewContext(true).WithBlockHeight(c.height+1), owner)
			require.True(t, found)
			pub, proof := reviewProof(t, c, replacement, 3, pqctypes.KeyRole_KEY_ROLE_SIGNING, pqctypes.PurposeRecoverSigning, policy.PolicyVersion, pqctypes.RecoveryKeyProofContext)
			msg := &pqctypes.MsgRecoverKey{Owner: owner.String(), RecoveryKeyId: 2, ExpectedNewSigningKeyId: 3, ExpectedRecoveryDelayBlocks: 2, NewSigningAlgorithm: pqctypes.Algorithm_ALGORITHM_ML_DSA_65, NewSigningPublicKey: pub, NewSigningKeyProof: proof}
			if !tc.protectedPayer || tc.omitFactor {
				payerFactor = nil
			}
			var raw []byte
			switch tc.invalid {
			case "payer":
				payerFactor = capacityFactor(t, c)
			case "recovery":
				recovery = capacityFactor(t, c)
			case "proof":
				msg.NewSigningKeyProof[0] ^= 1
			}
			if tc.selfPay {
				unsigned, err := c.app.TxConfig().TxDecoder()(c.tx(t, c.key, nil, msg))
				require.NoError(t, err)
				ctx := c.app.NewContext(true)
				acc := c.app.AccountKeeper.GetAccount(ctx, owner)
				doc, err := pqctypes.NewRecoverySignDocV1(unsigned.(interface{ GetProtoTx() *txtypes.Tx }).GetProtoTx(), c.app.PQCAuthKeeper.GetParams(ctx).NetworkId, "policy-test", acc.GetAccountNumber(), acc.GetSequence(), 0, owner.String(), owner.String(), 2, 3, msg.NewSigningAlgorithm, pub, policy.PolicyVersion)
				require.NoError(t, err)
				bz, err := pqctypes.MarshalRecoverySignDocV1(doc)
				require.NoError(t, err)
				msg.RecoverySignature, err = recovery.Sign(context.Background(), bz, []byte(pqctypes.RecoverySignatureContext))
				require.NoError(t, err)
				raw = c.tx(t, c.key, nil, msg)
			} else {
				raw = capacityPayerTx(t, c, msg, nil, payerFactor, recovery)
			}
			if tc.invalid == "owner" {
				decoded, err := c.app.TxConfig().TxDecoder()(raw)
				require.NoError(t, err)
				builder, err := c.app.TxConfig().WrapTxBuilder(decoded)
				require.NoError(t, err)
				sigs, err := decoded.(authsigning.SigVerifiableTx).GetSignaturesV2()
				require.NoError(t, err)
				sigs[0].Data.(*signing.SingleSignatureData).Signature[0] ^= 1
				require.NoError(t, builder.SetSignatures(sigs...))
				raw, err = c.app.TxConfig().TxEncoder()(builder.GetTx())
				require.NoError(t, err)
			}
			if !tc.omitFactor && tc.invalid == "" {
				decoded, err := c.app.TxConfig().TxDecoder()(raw)
				require.NoError(t, err)
				ctx := c.app.NewContext(true).WithBlockHeight(c.height + 1)
				inspection, err := pqcante.NewPQCVerificationBudgetTracker(c.app.AccountKeeper).Inspect(ctx, decoded, c.app.PQCAuthKeeper.GetParams(ctx).Effective(c.height+1))
				require.NoError(t, err)
				want := uint64(2)
				if tc.protectedPayer {
					want++
				}
				require.Equal(t, want, inspection.Cost.Total(), "recovery escape must retain payer and proof budget charges")
			}
			check, err := c.app.CheckTx(&abci.RequestCheckTx{Tx: raw})
			require.NoError(t, err)
			r := c.block(t, raw)
			if (tc.pause && tc.protectedPayer && tc.omitFactor) || tc.invalid != "" {
				require.NotZero(t, check.Code)
				require.NotZero(t, r.Code)
				if tc.omitFactor {
					require.Contains(t, r.Log, "pause")
				}
				require.Equal(t, beforeOwner, c.app.AccountKeeper.GetAccount(c.app.NewContext(true), owner).GetSequence())
				require.Equal(t, beforePayer, c.app.AccountKeeper.GetAccount(c.app.NewContext(true), payer).GetSequence())
				require.Equal(t, beforeOwnerBalance, c.app.BankKeeper.GetBalance(c.app.NewContext(true), owner, sdk.DefaultBondDenom))
				require.Equal(t, beforePayerBalance, c.app.BankKeeper.GetBalance(c.app.NewContext(true), payer, sdk.DefaultBondDenom))
			} else {
				require.Zero(t, check.Code, check.Log)
				require.Zero(t, r.Code, r.Log)
				p, ok := c.app.PQCAuthKeeper.GetAccountPolicy(c.app.NewContext(true), owner)
				require.True(t, ok)
				require.Equal(t, uint64(3), p.PendingSigningKeyId)
			}
			t.Logf("CheckTx=%d FinalizeBlock=%d log=%s", check.Code, r.Code, r.Log)
			c.block(t, nil)
			require.True(t, c.app.PQCAuthKeeper.AuditState(c.app.NewContext(true).WithBlockHeight(c.height), 100).Consistent)
		})
	}
}
