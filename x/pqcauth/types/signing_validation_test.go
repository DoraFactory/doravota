package types

import (
	"testing"

	"github.com/stretchr/testify/require"

	pqccrypto "github.com/DoraFactory/doravota/x/pqcauth/crypto"
)

func TestSigningDocumentValidationMatrix(t *testing.T) {
	validSignDoc := PQCSignDocV1{
		FormatVersion: FormatVersionV1,
		NetworkId:     []byte("network"),
		ChainId:       "chain",
		Signer:        "signer",
		KeyId:         1,
		Algorithm:     Algorithm_ALGORITHM_ML_DSA_65,
	}
	_, err := MarshalPQCSignDocV1(validSignDoc)
	require.NoError(t, err)
	for _, mutate := range []func(*PQCSignDocV1){
		func(doc *PQCSignDocV1) { doc.FormatVersion = 2 },
		func(doc *PQCSignDocV1) { doc.NetworkId = nil },
		func(doc *PQCSignDocV1) { doc.Algorithm = Algorithm(99) },
	} {
		doc := validSignDoc
		mutate(&doc)
		_, err = MarshalPQCSignDocV1(doc)
		require.Error(t, err)
	}

	validProofDoc := KeyProofDocV1{
		FormatVersion: FormatVersionV1,
		NetworkId:     []byte("network"),
		ChainId:       "chain",
		Owner:         "owner",
		ProposedKeyId: 1,
		Algorithm:     Algorithm_ALGORITHM_ML_DSA_65,
		PublicKey:     []byte{1},
		Role:          KeyRole_KEY_ROLE_SIGNING,
		Purpose:       PurposeRegisterSigning,
	}
	_, err = MarshalKeyProofDocV1(validProofDoc)
	require.NoError(t, err)
	for _, mutate := range []func(*KeyProofDocV1){
		func(doc *KeyProofDocV1) { doc.FormatVersion = 2 },
		func(doc *KeyProofDocV1) { doc.Owner = "" },
		func(doc *KeyProofDocV1) { doc.Algorithm = Algorithm(99) },
		func(doc *KeyProofDocV1) { doc.Role = KeyRole_KEY_ROLE_UNSPECIFIED },
	} {
		doc := validProofDoc
		mutate(&doc)
		_, err = MarshalKeyProofDocV1(doc)
		require.Error(t, err)
	}

	validRecoveryDoc := RecoverySignDocV1{
		FormatVersion:        FormatVersionV1,
		NetworkId:            []byte("network"),
		ChainId:              "chain",
		Owner:                "owner",
		RecoveryKeyId:        1,
		ProposedSigningKeyId: 2,
		ProposedAlgorithm:    Algorithm_ALGORITHM_ML_DSA_65,
		ProposedPublicKey:    []byte{1},
		Signer:               "owner",
		BodyBytesWithoutPqcAuthAndRecoverySignature: []byte{1},
		AuthInfoBytes: []byte{1},
	}
	_, err = MarshalRecoverySignDocV1(validRecoveryDoc)
	require.NoError(t, err)
	for _, mutate := range []func(*RecoverySignDocV1){
		func(doc *RecoverySignDocV1) { doc.FormatVersion = 2 },
		func(doc *RecoverySignDocV1) { doc.RecoveryKeyId = 0 },
		func(doc *RecoverySignDocV1) { doc.ProposedAlgorithm = Algorithm(99) },
		func(doc *RecoverySignDocV1) { doc.Signer = "" },
		func(doc *RecoverySignDocV1) {
			doc.BodyBytesWithoutPqcAuthAndRecoverySignature = nil
		},
		func(doc *RecoverySignDocV1) { doc.AuthInfoBytes = nil },
	} {
		doc := validRecoveryDoc
		mutate(&doc)
		_, err = MarshalRecoverySignDocV1(doc)
		require.Error(t, err)
	}
}

func TestValidatePublicKeyAndProofLengthsMatrix(t *testing.T) {
	publicKeySize, signatureSize, err := pqccrypto.Sizes(pqccrypto.AlgorithmMLDSA65)
	require.NoError(t, err)
	publicKey := make([]byte, publicKeySize)
	proof := make([]byte, signatureSize)

	require.NoError(t, ValidatePublicKeyAndProofLengths(
		Algorithm_ALGORITHM_ML_DSA_65,
		publicKey,
		proof,
	))
	require.Error(t, ValidatePublicKeyAndProofLengths(Algorithm(99), publicKey, proof))
	require.ErrorIs(
		t,
		ValidatePublicKeyAndProofLengths(
			Algorithm_ALGORITHM_ML_DSA_65,
			publicKey[:1],
			proof,
		),
		ErrInvalidKey,
	)
	require.ErrorIs(
		t,
		ValidatePublicKeyAndProofLengths(
			Algorithm_ALGORITHM_ML_DSA_65,
			publicKey,
			proof[:1],
		),
		ErrInvalidKeyProof,
	)
}
