package client

import (
	"context"
	"crypto/sha256"
	"strings"
	"testing"

	pqccrypto "github.com/DoraFactory/doravota/x/pqcauth/crypto"
	"github.com/DoraFactory/doravota/x/pqcauth/types"
	sdkclient "github.com/cosmos/cosmos-sdk/client"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/stretchr/testify/require"
)

func rotationBundleForTarget(t *testing.T, cfg sdkclient.TxConfig, base *PQCSignBundleV1, recovery bool, newPrivate []byte, duplicate bool) *PQCSignBundleV1 {
	t.Helper()
	var doc types.PQCSignDocV1
	require.NoError(t, doc.Unmarshal(base.SignDoc))
	tx, err := cfg.TxDecoder()(base.UnsignedTx)
	require.NoError(t, err)
	builder, err := cfg.WrapTxBuilder(tx)
	require.NoError(t, err)
	publicKey, err := pqccrypto.MLDSA65PublicKeyFromPrivate(newPrivate)
	require.NoError(t, err)
	role, purpose, domain := types.KeyRole_KEY_ROLE_SIGNING, types.PurposeRotateSigning, types.RotateProofContext
	if recovery {
		role, purpose, domain = types.KeyRole_KEY_ROLE_RECOVERY, types.PurposeRotateRecovery, types.RotateRecoveryContext
	}
	proofDoc, err := types.MarshalKeyProofDocV1(types.KeyProofDocV1{
		FormatVersion: 1, NetworkId: doc.NetworkId, ChainId: doc.ChainId,
		Owner: doc.Signer, ProposedKeyId: 11, Algorithm: types.Algorithm_ALGORITHM_ML_DSA_65,
		PublicKey: publicKey, Role: role, Purpose: purpose, CurrentPolicyVersion: doc.PolicyVersion,
	})
	require.NoError(t, err)
	proof, err := pqccrypto.SignMLDSA65(newPrivate, proofDoc, []byte(domain), true)
	require.NoError(t, err)
	require.NoError(t, pqccrypto.Verify(pqccrypto.AlgorithmMLDSA65, publicKey, proofDoc, []byte(domain), proof))
	var msg sdk.Msg = &types.MsgRotateKey{Owner: doc.Signer, ExpectedNewKeyId: 11,
		NewAlgorithm: types.Algorithm_ALGORITHM_ML_DSA_65, NewPublicKey: publicKey, NewKeyProof: proof}
	if recovery {
		msg = &types.MsgRotateRecoveryKey{Owner: doc.Signer, ExpectedNewKeyId: 11,
			NewAlgorithm: types.Algorithm_ALGORITHM_ML_DSA_65, NewPublicKey: publicKey, NewKeyProof: proof}
	}
	msgs := []sdk.Msg{msg}
	if duplicate {
		msgs = append(msgs, msg)
	}
	require.NoError(t, builder.SetMsgs(msgs...))
	doc, err = types.NewPQCSignDocV1(builder.GetTx().(protoTxProvider).GetProtoTx(), doc.NetworkId, doc.ChainId,
		doc.AccountNumber, doc.Sequence, doc.SignerIndex, doc.Signer, doc.KeyId, doc.Algorithm, doc.PolicyVersion)
	require.NoError(t, err)
	b := clonePQCSignBundle(base)
	b.SignDoc, err = types.MarshalPQCSignDocV1(doc)
	require.NoError(t, err)
	b.UnsignedTx, err = cfg.TxEncoder()(builder.GetTx())
	require.NoError(t, err)
	txHash, docHash := sha256.Sum256(b.UnsignedTx), sha256.Sum256(b.SignDoc)
	b.UnsignedTxSHA256, b.SignDocSHA256 = txHash[:], docHash[:]
	return b
}

func TestRotationSigningTargetRejectsConsistentSubstitution(t *testing.T) {
	cfg := testTxConfig()
	base, currentPrivate := testUnsignedBundle(t, cfg)
	defer clear(currentPrivate)
	trustedPublic, trustedPrivate, err := pqccrypto.GenerateMLDSA65Key(nil)
	require.NoError(t, err)
	defer clear(trustedPrivate)
	_, attackerPrivate, err := pqccrypto.GenerateMLDSA65Key(nil)
	require.NoError(t, err)
	defer clear(attackerPrivate)
	expected := PublicKeySHA256(trustedPublic)
	for _, recovery := range []bool{false, true} {
		name := "rotate-key"
		role := "signing"
		if recovery {
			name, role = "rotate-recovery-key", "recovery"
		}
		t.Run(name, func(t *testing.T) {
			honest := rotationBundleForTarget(t, cfg, base, recovery, trustedPrivate, false)
			swapped := rotationBundleForTarget(t, cfg, base, recovery, attackerPrivate, false)
			honestSummary, err := ValidatePQCSignBundle(cfg, honest, false)
			require.NoError(t, err)
			swappedSummary, err := ValidatePQCSignBundle(cfg, swapped, false)
			require.NoError(t, err, "valid PoP and recomputed hashes are internally consistent")
			require.Equal(t, name, honestSummary.KeyChange.Operation)
			require.Equal(t, role, honestSummary.KeyChange.Role)
			require.Equal(t, uint64(11), honestSummary.KeyChange.NewKeyID)
			require.Equal(t, expected, honestSummary.KeyChange.PublicKeySHA256)
			require.NotEqual(t, expected, swappedSummary.KeyChange.PublicKeySHA256)
			for _, target := range []string{"", "abcd", strings.Repeat("z", 64), expected} {
				signer := &recordingBundleSigner{publicKey: base.OnChainPublicKey, privateKey: currentPrivate}
				result, _, err := SignPQCSignBundleForTarget(context.Background(), cfg, swapped, signer, target)
				require.Error(t, err)
				require.Nil(t, result)
				require.Empty(t, signer.message)
			}
			signer := &recordingBundleSigner{publicKey: base.OnChainPublicKey, privateKey: currentPrivate}
			signed, summary, err := SignPQCSignBundleForTarget(context.Background(), cfg, honest, signer, strings.ToUpper(expected))
			require.NoError(t, err)
			require.True(t, summary.Signed)
			_, err = ValidatePQCSignBundle(cfg, signed, true)
			require.NoError(t, err)
			duplicate := rotationBundleForTarget(t, cfg, base, recovery, trustedPrivate, true)
			_, err = ValidatePQCSignBundle(cfg, duplicate, false)
			require.ErrorContains(t, err, "only top-level message")
		})
	}
	// A supplied target cannot be silently ignored after changing the action.
	signer := &recordingBundleSigner{publicKey: base.OnChainPublicKey, privateKey: currentPrivate}
	_, _, err = SignPQCSignBundleForTarget(context.Background(), cfg, base, signer, expected)
	require.ErrorContains(t, err, "not a key rotation")
	require.Empty(t, signer.message)
	_, summary, err := SignPQCSignBundleForTarget(context.Background(), cfg, base, signer, "")
	require.NoError(t, err)
	require.Nil(t, summary.KeyChange)
	_, _, err = SignPQCSignBundleForTarget(context.Background(), cfg, nil, signer, expected)
	require.Error(t, err)
}
