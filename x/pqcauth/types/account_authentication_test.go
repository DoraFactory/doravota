package types

import (
	"testing"

	"github.com/cosmos/cosmos-sdk/crypto/keys/ed25519"
	"github.com/cosmos/cosmos-sdk/crypto/keys/mldsa65"
	"github.com/cosmos/cosmos-sdk/crypto/keys/multisig"
	"github.com/cosmos/cosmos-sdk/crypto/keys/secp256k1"
	"github.com/cosmos/cosmos-sdk/crypto/keys/secp256r1"
	cryptotypes "github.com/cosmos/cosmos-sdk/crypto/types"
	"github.com/stretchr/testify/require"
)

func TestClassifyAccountAuthentication(t *testing.T) {
	mlDsaPrivateKey, err := mldsa65.GenPrivKey()
	require.NoError(t, err)
	secp256r1PrivateKey, err := secp256r1.GenPrivKey()
	require.NoError(t, err)

	testCases := []struct {
		name      string
		publicKey cryptotypes.PubKey
		expected  AccountAuthentication
	}{
		{
			name:      "native ML-DSA",
			publicKey: mlDsaPrivateKey.PubKey(),
			expected:  AccountAuthenticationNativePQC,
		},
		{
			name:      "secp256k1",
			publicKey: secp256k1.GenPrivKey().PubKey(),
			expected:  AccountAuthenticationClassic,
		},
		{
			name:      "ed25519",
			publicKey: ed25519.GenPrivKey().PubKey(),
			expected:  AccountAuthenticationClassic,
		},
		{
			name:      "secp256r1",
			publicKey: secp256r1PrivateKey.PubKey(),
			expected:  AccountAuthenticationClassic,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			require.Equal(
				t,
				testCase.expected,
				ClassifyAccountAuthentication(testCase.publicKey),
			)
		})
	}

	require.Equal(
		t,
		AccountAuthenticationUnsupported,
		ClassifyAccountAuthentication(nil),
	)
	require.Equal(
		t,
		AccountAuthenticationUnsupported,
		ClassifyAccountAuthentication(multisig.NewLegacyAminoPubKey(
			1,
			[]cryptotypes.PubKey{secp256k1.GenPrivKey().PubKey()},
		)),
	)
}
