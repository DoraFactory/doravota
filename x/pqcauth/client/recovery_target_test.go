package client

import (
	"context"
	"crypto/sha256"
	"strings"
	"testing"

	pqccrypto "github.com/DoraFactory/doravota/x/pqcauth/crypto"
	"github.com/DoraFactory/doravota/x/pqcauth/types"
	"github.com/stretchr/testify/require"
)

func TestRecoverySigningTargetRejectsInternallyConsistentSubstitution(t *testing.T) {
	txConfig := testTxConfig()
	honest, recoveryPrivate := testUnsignedRecoveryBundle(t, txConfig)
	defer clear(recoveryPrivate)
	honestSummary, err := ValidateRecoverySignBundle(txConfig, honest, false)
	require.NoError(t, err)

	// The attacker owns a genuine replacement key and can supply a valid PoP,
	// not merely a zero proof. Rebuild the transaction, sign doc and BOTH hashes.
	attackerPublic, attackerPrivate, err := pqccrypto.GenerateMLDSA65Key(nil)
	require.NoError(t, err)
	defer clear(attackerPrivate)
	swapped := cloneRecoverySignBundle(honest)
	var doc types.RecoverySignDocV1
	require.NoError(t, doc.Unmarshal(swapped.SignDoc))
	tx, err := txConfig.TxDecoder()(swapped.UnsignedTx)
	require.NoError(t, err)
	msg, err := recoveryMessageFromTx(tx)
	require.NoError(t, err)
	msg.NewSigningPublicKey = attackerPublic
	proofDoc, err := types.MarshalKeyProofDocV1(types.KeyProofDocV1{
		FormatVersion: types.FormatVersionV1, NetworkId: doc.NetworkId, ChainId: doc.ChainId,
		Owner: doc.Owner, ProposedKeyId: doc.ProposedSigningKeyId,
		Algorithm: doc.ProposedAlgorithm, PublicKey: attackerPublic,
		Role: types.KeyRole_KEY_ROLE_SIGNING, Purpose: types.PurposeRecoverSigning,
		CurrentPolicyVersion: doc.CurrentPolicyVersion,
	})
	require.NoError(t, err)
	msg.NewSigningKeyProof, err = pqccrypto.SignMLDSA65(attackerPrivate, proofDoc, []byte(types.RecoveryKeyProofContext), true)
	require.NoError(t, err)
	require.NoError(t, pqccrypto.Verify(pqccrypto.AlgorithmMLDSA65, attackerPublic, proofDoc, []byte(types.RecoveryKeyProofContext), msg.NewSigningKeyProof))
	builder, err := txConfig.WrapTxBuilder(tx)
	require.NoError(t, err)
	require.NoError(t, builder.SetMsgs(msg))
	newDoc, err := types.NewRecoverySignDocV1(builder.GetTx().(protoTxProvider).GetProtoTx(),
		doc.NetworkId, doc.ChainId, doc.AccountNumber, doc.Sequence, doc.SignerIndex,
		doc.Signer, doc.Owner, doc.RecoveryKeyId, doc.ProposedSigningKeyId,
		doc.ProposedAlgorithm, attackerPublic, doc.CurrentPolicyVersion)
	require.NoError(t, err)
	swapped.SignDoc, err = types.MarshalRecoverySignDocV1(newDoc)
	require.NoError(t, err)
	swapped.UnsignedTx, err = txConfig.TxEncoder()(builder.GetTx())
	require.NoError(t, err)
	txHash, docHash := sha256.Sum256(swapped.UnsignedTx), sha256.Sum256(swapped.SignDoc)
	swapped.UnsignedTxSHA256, swapped.SignDocSHA256 = txHash[:], docHash[:]
	swappedSummary, err := ValidateRecoverySignBundle(txConfig, swapped, false)
	require.NoError(t, err, "internal consistency cannot establish the user's intended key")
	require.Equal(t, honestSummary.ProposedSigningKeyID, swappedSummary.ProposedSigningKeyID)
	require.NotEqual(t, honestSummary.ProposedPublicKeySHA256, swappedSummary.ProposedPublicKeySHA256)

	signer := &recordingBundleSigner{publicKey: honest.OnChainRecoveryPublicKey, privateKey: recoveryPrivate}
	for _, expected := range []string{"", "abcd", strings.Repeat("z", 64), honestSummary.ProposedPublicKeySHA256} {
		signed, _, err := SignRecoverySignBundleForTarget(context.Background(), txConfig, swapped, signer, expected)
		require.Error(t, err)
		require.Nil(t, signed)
		require.Empty(t, signer.message, "must reject before calling the recovery signer")
	}
	signed, summary, err := SignRecoverySignBundleForTarget(context.Background(), txConfig, honest, signer, strings.ToUpper(honestSummary.ProposedPublicKeySHA256))
	require.NoError(t, err)
	require.True(t, summary.Signed)
	_, err = ValidateRecoverySignBundle(txConfig, signed, true)
	require.NoError(t, err)
	_, _, err = SignRecoverySignBundleForTarget(context.Background(), txConfig, nil, signer, honestSummary.ProposedPublicKeySHA256)
	require.Error(t, err)
	wrongAlgorithm := honestSummary
	wrongAlgorithm.ProposedAlgorithm = types.Algorithm(99)
	require.ErrorContains(t, ValidateRecoverySigningTarget(wrongAlgorithm, honestSummary.ProposedPublicKeySHA256), "ML-DSA-65")
}
