package types

import (
	"bytes"
	"testing"

	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/stretchr/testify/require"

	pqccrypto "github.com/DoraFactory/doravota/x/pqcauth/crypto"
)

type legacyMessage interface {
	sdk.Msg
	Route() string
	Type() string
	GetSignBytes() []byte
}

func TestLifecycleMessageLegacySDKSurface(t *testing.T) {
	owner := sdk.AccAddress(bytes.Repeat([]byte{0x81}, 20)).String()
	publicKey, _, err := pqccrypto.GenerateMLDSA65Key(nil)
	require.NoError(t, err)
	_, signatureSize, err := pqccrypto.Sizes(pqccrypto.AlgorithmMLDSA65)
	require.NoError(t, err)
	proof := make([]byte, signatureSize)

	testCases := []struct {
		message legacyMessage
		name    string
	}{
		{
			message: &MsgRegisterKey{
				Owner:                owner,
				ExpectedSigningKeyId: 1,
				SigningAlgorithm:     Algorithm_ALGORITHM_ML_DSA_65,
				SigningPublicKey:     publicKey,
				SigningKeyProof:      proof,
			},
			name: "register_key",
		},
		{
			message: &MsgRotateKey{
				Owner:            owner,
				ExpectedNewKeyId: 2,
				NewAlgorithm:     Algorithm_ALGORITHM_ML_DSA_65,
				NewPublicKey:     publicKey,
				NewKeyProof:      proof,
			},
			name: "rotate_key",
		},
		{
			message: &MsgRotateRecoveryKey{
				Owner:            owner,
				ExpectedNewKeyId: 2,
				NewAlgorithm:     Algorithm_ALGORITHM_ML_DSA_65,
				NewPublicKey:     publicKey,
				NewKeyProof:      proof,
			},
			name: "rotate_recovery_key",
		},
		{
			message: &MsgSetProtection{Owner: owner, Enabled: true},
			name:    "set_protection",
		},
		{
			message: &MsgRevokeKey{Owner: owner, KeyId: 2},
			name:    "revoke_key",
		},
		{
			message: &MsgRecoverKey{
				Owner:                   owner,
				RecoveryKeyId:           2,
				RecoverySignature:       proof,
				ExpectedNewSigningKeyId: 3,
				NewSigningAlgorithm:     Algorithm_ALGORITHM_ML_DSA_65,
				NewSigningPublicKey:     publicKey,
				NewSigningKeyProof:      proof,
			},
			name: "recover_key",
		},
		{
			message: &MsgUpdateParams{
				Authority: owner,
				Params:    DefaultParams(),
			},
			name: "update_params",
		},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			require.NoError(t, testCase.message.ValidateBasic())
			require.Equal(t, RouterKey, testCase.message.Route())
			require.Equal(t, testCase.name, testCase.message.Type())
			require.Equal(
				t,
				[]sdk.AccAddress{sdk.MustAccAddressFromBech32(owner)},
				testCase.message.GetSigners(),
			)
			require.NotEmpty(t, testCase.message.GetSignBytes())
		})
	}
}

func TestLifecycleMessageValidateBasicRejectsMalformedInputs(t *testing.T) {
	owner := sdk.AccAddress(bytes.Repeat([]byte{0x82}, 20)).String()
	publicKey, _, err := pqccrypto.GenerateMLDSA65Key(nil)
	require.NoError(t, err)
	_, signatureSize, err := pqccrypto.Sizes(pqccrypto.AlgorithmMLDSA65)
	require.NoError(t, err)
	proof := make([]byte, signatureSize)

	testCases := []struct {
		name    string
		message sdk.Msg
	}{
		{"register owner", &MsgRegisterKey{Owner: "invalid"}},
		{"register id", &MsgRegisterKey{Owner: owner}},
		{"register key length", &MsgRegisterKey{
			Owner:                owner,
			ExpectedSigningKeyId: 1,
			SigningAlgorithm:     Algorithm_ALGORITHM_ML_DSA_65,
		}},
		{"register recovery", &MsgRegisterKey{
			Owner:                owner,
			ExpectedSigningKeyId: 1,
			SigningAlgorithm:     Algorithm_ALGORITHM_ML_DSA_65,
			SigningPublicKey:     publicKey,
			SigningKeyProof:      proof,
			RecoveryAlgorithm:    Algorithm_ALGORITHM_ML_DSA_65,
		}},
		{"rotate owner", &MsgRotateKey{Owner: "invalid"}},
		{"rotate id", &MsgRotateKey{Owner: owner}},
		{"rotate proof", &MsgRotateKey{
			Owner:            owner,
			ExpectedNewKeyId: 2,
			NewAlgorithm:     Algorithm_ALGORITHM_ML_DSA_65,
		}},
		{"rotate recovery owner", &MsgRotateRecoveryKey{Owner: "invalid"}},
		{"rotate recovery id", &MsgRotateRecoveryKey{Owner: owner}},
		{"set protection owner", &MsgSetProtection{Owner: "invalid"}},
		{"revoke owner", &MsgRevokeKey{Owner: "invalid"}},
		{"revoke id", &MsgRevokeKey{Owner: owner}},
		{"recover owner", &MsgRecoverKey{Owner: "invalid"}},
		{"recover ids", &MsgRecoverKey{Owner: owner}},
		{"recover new key", &MsgRecoverKey{
			Owner:                   owner,
			RecoveryKeyId:           1,
			ExpectedNewSigningKeyId: 2,
			NewSigningAlgorithm:     Algorithm_ALGORITHM_ML_DSA_65,
		}},
		{"recover signature", &MsgRecoverKey{
			Owner:                   owner,
			RecoveryKeyId:           1,
			ExpectedNewSigningKeyId: 2,
			NewSigningAlgorithm:     Algorithm_ALGORITHM_ML_DSA_65,
			NewSigningPublicKey:     publicKey,
			NewSigningKeyProof:      proof,
		}},
		{"update authority", &MsgUpdateParams{
			Authority: "invalid",
			Params:    DefaultParams(),
		}},
		{"update params", &MsgUpdateParams{
			Authority: owner,
			Params:    Params{},
		}},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			require.Error(t, testCase.message.ValidateBasic())
		})
	}
}
