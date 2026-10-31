package app_test

import (
	"context"
	"testing"

	pqcclient "github.com/DoraFactory/doravota/x/pqcauth/client"
	pqckeeper "github.com/DoraFactory/doravota/x/pqcauth/keeper"
	pqctypes "github.com/DoraFactory/doravota/x/pqcauth/types"
	abci "github.com/cometbft/cometbft/abci/types"
	tmproto "github.com/cometbft/cometbft/proto/tendermint/types"
	sdkclient "github.com/cosmos/cosmos-sdk/client"
	sdktx "github.com/cosmos/cosmos-sdk/client/tx"
	codectypes "github.com/cosmos/cosmos-sdk/codec/types"
	"github.com/cosmos/cosmos-sdk/crypto/hd"
	"github.com/cosmos/cosmos-sdk/crypto/keyring"
	"github.com/cosmos/cosmos-sdk/crypto/keys/mldsa65"
	kmultisig "github.com/cosmos/cosmos-sdk/crypto/keys/multisig"
	cryptotypes "github.com/cosmos/cosmos-sdk/crypto/types"
	"github.com/cosmos/cosmos-sdk/crypto/types/multisig"
	sdk "github.com/cosmos/cosmos-sdk/types"
	txtypes "github.com/cosmos/cosmos-sdk/types/tx"
	"github.com/cosmos/cosmos-sdk/types/tx/signing"
	authsigning "github.com/cosmos/cosmos-sdk/x/auth/signing"
	banktypes "github.com/cosmos/cosmos-sdk/x/bank/types"
	"github.com/stretchr/testify/require"
)

func minimumCapacityParams() pqctypes.Params {
	p := pqctypes.DefaultParams()
	p.MaxPqcSigners = pqctypes.MinimumMaxPQCSigners
	p.MaxPqcAuthBytes = pqctypes.MinimumPQCAuthBytes(p.MaxPqcSigners)
	p.MaxPqcVerificationsPerTx = pqctypes.MinimumMaxPQCVerificationsPerTx
	p.MaxPqcVerificationsPerBlock = p.MaxPqcVerificationsPerTx
	p.GovernanceSafetyDelayBlocks, p.RecoveryDelayBlocks = 2, 2
	return p
}

func TestPQCAuthGovernanceRejectsUnusableCapacity(t *testing.T) {
	p := pqctypes.DefaultParams()
	p.GovernanceSafetyDelayBlocks, p.RecoveryDelayBlocks = 2, 2
	c := newPQCChain(t, p)
	factor, _ := reviewEnroll(t, c)
	ctx := c.app.NewNextBlockContext(tmproto.Header{ChainID: "policy-test", Height: c.height + 1})
	before := c.app.PQCAuthKeeper.GetParams(ctx)
	for _, mutate := range []func(*pqctypes.Params){
		func(p *pqctypes.Params) { p.MaxPqcAuthBytes = 1 },
		func(p *pqctypes.Params) { p.MaxPqcVerificationsPerTx = 1 },
		func(p *pqctypes.Params) { p.MaxPqcVerificationsPerTx = 2 },
		func(p *pqctypes.Params) { p.MaxPqcVerificationsPerBlock = 1 },
		func(p *pqctypes.Params) { p.MaxPqcSigners = 1 },
	} {
		requested := before
		mutate(&requested)
		_, err := pqckeeper.NewMsgServer(c.app.PQCAuthKeeper).UpdateParams(ctx, &pqctypes.MsgUpdateParams{Authority: c.app.PQCAuthKeeper.Authority(), Params: requested})
		require.Error(t, err)
		require.Equal(t, before, c.app.PQCAuthKeeper.GetParams(ctx), "rejection must not write a pending policy")
	}
	requested := minimumCapacityParams()
	requested.NetworkId = before.NetworkId
	response, err := pqckeeper.NewMsgServer(c.app.PQCAuthKeeper).UpdateParams(ctx, &pqctypes.MsgUpdateParams{Authority: c.app.PQCAuthKeeper.Authority(), Params: requested})
	require.NoError(t, err)
	c.app.SimWriteState()
	for uint64(c.height) <= response.ActivationHeight {
		c.block(t, nil)
	}
	owner := sdk.AccAddress(c.key.PubKey().Address())
	send := banktypes.NewMsgSend(owner, sdk.AccAddress(c.other.PubKey().Address()), sdk.NewCoins(sdk.NewInt64Coin(sdk.DefaultBondDenom, 1)))
	r := c.block(t, c.tx(t, c.key, factor, send))
	require.Zero(t, r.Code, r.Log)
	for _, enabled := range []bool{false, true} {
		r = c.block(t, c.tx(t, c.key, factor, &pqctypes.MsgSetProtection{Owner: owner.String(), Enabled: enabled}))
		require.Zero(t, r.Code, r.Log)
		c.block(t, nil)
	}
	require.True(t, c.app.PQCAuthKeeper.AuditState(c.app.NewContext(true).WithBlockHeight(c.height), 20).Consistent)
}

func capacityFactor(t *testing.T, c *pqcChain) pqcclient.PQCSigner {
	t.Helper()
	keys := keyring.NewInMemory(c.app.AppCodec())
	_, _, err := keys.NewMnemonic("factor", keyring.English, "m/44'/118'/0'/0/0", "", hd.MlDsa65)
	require.NoError(t, err)
	f, err := pqcclient.NewKeyringSigner(keys, "factor")
	require.NoError(t, err)
	return f
}

// Build a real direct transaction with an independently signing fee payer.
// Recovery is signed first, then payer/owner PQC factors, then SDK signatures.
func capacityPayerTx(t *testing.T, c *pqcChain, msg sdk.Msg, ownerFactor, payerFactor, recoveryFactor pqcclient.PQCSigner) []byte {
	t.Helper()
	ctx := c.app.NewContext(true).WithBlockHeight(c.height + 1)
	keys := []cryptotypes.PrivKey{c.key, c.other}
	factors := []pqcclient.PQCSigner{ownerFactor, payerFactor}
	b := c.app.TxConfig().NewTxBuilder()
	require.NoError(t, b.SetMsgs(msg))
	b.SetFeePayer(sdk.AccAddress(c.other.PubKey().Address()))
	b.SetGasLimit(3_000_000)
	b.SetFeeAmount(sdk.NewCoins(sdk.NewInt64Coin(sdk.DefaultBondDenom, 10)))
	sigs := make([]signing.SignatureV2, len(keys))
	for i, key := range keys {
		acc := c.app.AccountKeeper.GetAccount(ctx, sdk.AccAddress(key.PubKey().Address()))
		sigs[i] = signing.SignatureV2{PubKey: key.PubKey(), Sequence: acc.GetSequence(), Data: &signing.SingleSignatureData{SignMode: signing.SignMode_SIGN_MODE_DIRECT}}
	}
	require.NoError(t, b.SetSignatures(sigs...))
	protoTx := func() *txtypes.Tx { return b.(interface{ GetProtoTx() *txtypes.Tx }).GetProtoTx() }
	params := c.app.PQCAuthKeeper.GetParams(ctx)
	if recoveryFactor != nil {
		r := msg.(*pqctypes.MsgRecoverKey)
		owner := sdk.AccAddress(c.key.PubKey().Address())
		acc := c.app.AccountKeeper.GetAccount(ctx, owner)
		policy, _ := c.app.PQCAuthKeeper.GetEffectiveAccountPolicy(ctx, owner)
		doc, err := pqctypes.NewRecoverySignDocV1(protoTx(), params.NetworkId, "policy-test", acc.GetAccountNumber(), acc.GetSequence(), 0, owner.String(), owner.String(), r.RecoveryKeyId, r.ExpectedNewSigningKeyId, r.NewSigningAlgorithm, r.NewSigningPublicKey, policy.PolicyVersion)
		require.NoError(t, err)
		bz, err := pqctypes.MarshalRecoverySignDocV1(doc)
		require.NoError(t, err)
		r.RecoverySignature, err = recoveryFactor.Sign(context.Background(), bz, []byte(pqctypes.RecoverySignatureContext))
		require.NoError(t, err)
		require.NoError(t, b.SetMsgs(r))
	}
	ext := &pqctypes.ExtensionPQCAuth{FormatVersion: 1}
	for i, factor := range factors {
		if factor == nil {
			continue
		}
		owner := sdk.AccAddress(keys[i].PubKey().Address())
		acc := c.app.AccountKeeper.GetAccount(ctx, owner)
		record, policy, active := c.app.PQCAuthKeeper.GetActiveSigningKey(ctx, owner)
		require.True(t, active)
		doc, err := pqctypes.NewPQCSignDocV1(protoTx(), params.NetworkId, "policy-test", acc.GetAccountNumber(), acc.GetSequence(), uint32(i), owner.String(), record.KeyId, record.Algorithm, policy.PolicyVersion)
		require.NoError(t, err)
		bz, err := pqctypes.MarshalPQCSignDocV1(doc)
		require.NoError(t, err)
		sig, err := factor.Sign(context.Background(), bz, []byte(pqctypes.TxSignatureContext))
		require.NoError(t, err)
		ext.Signatures = append(ext.Signatures, pqctypes.SignerPQCSignature{Signer: owner.String(), SignerIndex: uint32(i), KeyId: record.KeyId, Algorithm: record.Algorithm, PolicyVersion: policy.PolicyVersion, Signature: sig})
	}
	if len(ext.Signatures) > 0 {
		option, err := codectypes.NewAnyWithValue(ext)
		require.NoError(t, err)
		b.(sdkclient.ExtendedTxBuilder).SetExtensionOptions(option)
	}
	for i, key := range keys {
		owner := sdk.AccAddress(key.PubKey().Address())
		acc := c.app.AccountKeeper.GetAccount(ctx, owner)
		var err error
		sigs[i], err = sdktx.SignWithPrivKey(context.Background(), signing.SignMode_SIGN_MODE_DIRECT, authsigning.SignerData{Address: owner.String(), ChainID: "policy-test", AccountNumber: acc.GetAccountNumber(), Sequence: acc.GetSequence(), PubKey: key.PubKey()}, b, key, c.app.TxConfig(), acc.GetSequence())
		require.NoError(t, err)
	}
	require.NoError(t, b.SetSignatures(sigs...))
	raw, err := c.app.TxConfig().TxEncoder()(b.GetTx())
	require.NoError(t, err)
	return raw
}

func TestPQCAuthMinimumCapacityLifecycleWithProtectedPayer(t *testing.T) {
	c := newPQCChain(t, minimumCapacityParams())
	ownerKey := c.key
	c.key = c.other
	payerFactor, _ := reviewEnroll(t, c)
	c.key = ownerKey
	owner := sdk.AccAddress(c.key.PubKey().Address()).String()
	factor, recovery, next := capacityFactor(t, c), capacityFactor(t, c), capacityFactor(t, c)
	pub, proof := reviewProof(t, c, factor, 1, pqctypes.KeyRole_KEY_ROLE_SIGNING, pqctypes.PurposeRegisterSigning, 0, pqctypes.RegisterProofContext)
	rpub, rproof := reviewProof(t, c, recovery, 2, pqctypes.KeyRole_KEY_ROLE_RECOVERY, pqctypes.PurposeRegisterRecovery, 0, pqctypes.RegisterProofContext)
	register := &pqctypes.MsgRegisterKey{Owner: owner, ExpectedSigningKeyId: 1, SigningAlgorithm: pqctypes.Algorithm_ALGORITHM_ML_DSA_65, SigningPublicKey: pub, SigningKeyProof: proof, SelfEnforce: true, RecoveryAlgorithm: pqctypes.Algorithm_ALGORITHM_ML_DSA_65, RecoveryPublicKey: rpub, RecoveryKeyProof: rproof}
	check := func(raw []byte) {
		decision, err := c.app.ProcessProposal(&abci.RequestProcessProposal{Height: c.height + 1, Txs: [][]byte{raw}})
		require.NoError(t, err)
		require.Equal(t, abci.ResponseProcessProposal_ACCEPT, decision.Status)
		r := c.block(t, raw)
		require.Zero(t, r.Code, r.Log)
	}
	check(capacityPayerTx(t, c, register, nil, payerFactor, nil)) // 2 proofs + payer
	c.block(t, nil)
	pub, proof = reviewProof(t, c, next, 3, pqctypes.KeyRole_KEY_ROLE_SIGNING, pqctypes.PurposeRotateSigning, 1, pqctypes.RotateProofContext)
	rotate := &pqctypes.MsgRotateKey{Owner: owner, ExpectedNewKeyId: 3, NewAlgorithm: pqctypes.Algorithm_ALGORITHM_ML_DSA_65, NewPublicKey: pub, NewKeyProof: proof}
	check(capacityPayerTx(t, c, rotate, factor, payerFactor, nil)) // current + new proof + payer
	c.block(t, nil)
	replacement := capacityFactor(t, c)
	policy, _ := c.app.PQCAuthKeeper.GetEffectiveAccountPolicy(c.app.NewContext(true).WithBlockHeight(c.height+1), sdk.MustAccAddressFromBech32(owner))
	pub, proof = reviewProof(t, c, replacement, 4, pqctypes.KeyRole_KEY_ROLE_SIGNING, pqctypes.PurposeRecoverSigning, policy.PolicyVersion, pqctypes.RecoveryKeyProofContext)
	recover := &pqctypes.MsgRecoverKey{Owner: owner, RecoveryKeyId: 2, ExpectedNewSigningKeyId: 4, ExpectedRecoveryDelayBlocks: 2, NewSigningAlgorithm: pqctypes.Algorithm_ALGORITHM_ML_DSA_65, NewSigningPublicKey: pub, NewSigningKeyProof: proof}
	check(capacityPayerTx(t, c, recover, nil, payerFactor, recovery)) // recovery + proof + payer
	c.block(t, nil)
	c.block(t, nil)
	send := banktypes.NewMsgSend(sdk.MustAccAddressFromBech32(owner), sdk.AccAddress(c.other.PubKey().Address()), sdk.NewCoins(sdk.NewInt64Coin(sdk.DefaultBondDenom, 1)))
	check(capacityPayerTx(t, c, send, replacement, payerFactor, nil))
	check(capacityPayerTx(t, c, &pqctypes.MsgSetProtection{Owner: owner, Enabled: false}, replacement, payerFactor, nil))
	require.True(t, c.app.PQCAuthKeeper.AuditState(c.app.NewContext(true).WithBlockHeight(c.height), 20).Consistent)
}

func TestPQCAuthNativeMultisigAtMinimumBudget(t *testing.T) {
	for _, leaves := range []int{2, 3, 4, 7} {
		t.Run(string(rune('0'+leaves))+" leaves", func(t *testing.T) {
			params := minimumCapacityParams()
			if leaves == 7 {
				params.MaxPqcVerificationsPerTx, params.MaxPqcVerificationsPerBlock = 16, 400
			}
			c := newPQCChain(t, params)
			keys := make([]cryptotypes.PrivKey, leaves)
			pubs := make([]cryptotypes.PubKey, leaves)
			for i := range keys {
				k, err := mldsa65.GenPrivKey()
				require.NoError(t, err)
				keys[i], pubs[i] = &k, k.PubKey()
			}
			pub := kmultisig.NewLegacyAminoPubKey(leaves, pubs)
			owner := sdk.AccAddress(pub.Address())
			fund := banktypes.NewMsgSend(sdk.AccAddress(c.key.PubKey().Address()), owner, sdk.NewCoins(sdk.NewInt64Coin(sdk.DefaultBondDenom, 100000)))
			r := c.block(t, c.tx(t, c.key, nil, fund))
			require.Zero(t, r.Code, r.Log)
			acc := c.app.AccountKeeper.GetAccount(c.app.NewContext(true), owner)
			b := c.app.TxConfig().NewTxBuilder()
			require.NoError(t, b.SetMsgs(banktypes.NewMsgSend(owner, sdk.AccAddress(c.key.PubKey().Address()), sdk.NewCoins(sdk.NewInt64Coin(sdk.DefaultBondDenom, 1)))))
			b.SetGasLimit(3_000_000)
			b.SetFeeAmount(sdk.NewCoins(sdk.NewInt64Coin(sdk.DefaultBondDenom, 10)))
			multi := multisig.NewMultisig(leaves)
			require.NoError(t, b.SetSignatures(signing.SignatureV2{PubKey: pub, Sequence: acc.GetSequence(), Data: multi}))
			bz, err := authsigning.GetSignBytesAdapter(context.Background(), c.app.TxConfig().SignModeHandler(), signing.SignMode_SIGN_MODE_LEGACY_AMINO_JSON, authsigning.SignerData{Address: owner.String(), ChainID: "policy-test", AccountNumber: acc.GetAccountNumber(), Sequence: acc.GetSequence(), PubKey: pub}, b.GetTx())
			require.NoError(t, err)
			for _, key := range keys {
				sig, err := key.Sign(bz)
				require.NoError(t, err)
				require.NoError(t, multisig.AddSignatureV2(multi, signing.SignatureV2{PubKey: key.PubKey(), Data: &signing.SingleSignatureData{SignMode: signing.SignMode_SIGN_MODE_LEGACY_AMINO_JSON, Signature: sig}}, pubs))
			}
			require.NoError(t, b.SetSignatures(signing.SignatureV2{PubKey: pub, Sequence: acc.GetSequence(), Data: multi}))
			raw, err := c.app.TxConfig().TxEncoder()(b.GetTx())
			require.NoError(t, err)
			r = c.block(t, raw)
			if leaves > int(params.MaxPqcVerificationsPerTx) {
				require.NotZero(t, r.Code)
				require.Contains(t, r.Log, "PQC verifications")
			} else {
				require.Zero(t, r.Code, r.Log)
			}
			_, enrolled := c.app.PQCAuthKeeper.GetAccountPolicy(c.app.NewContext(true), owner)
			require.False(t, enrolled)
			// A rejected over-budget native multisig never blocks ordinary work.
			r = c.block(t, c.tx(t, c.key, nil, fund))
			require.Zero(t, r.Code, r.Log)
			c.block(t, nil)
		})
	}
}
