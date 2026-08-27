package main

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cosmos/cosmos-sdk/crypto/keys/mldsa65"
	"github.com/cosmos/cosmos-sdk/crypto/keys/secp256k1"
	cryptotypes "github.com/cosmos/cosmos-sdk/crypto/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
	txsigning "github.com/cosmos/cosmos-sdk/types/tx/signing"
	authsigning "github.com/cosmos/cosmos-sdk/x/auth/signing"

	"github.com/DoraFactory/doravota/app"
	pqccrypto "github.com/DoraFactory/doravota/x/pqcauth/crypto"
	pqctypes "github.com/DoraFactory/doravota/x/pqcauth/types"
)

func TestBuildTransactionSignatures(t *testing.T) {
	configureSDK()
	encoding := app.MakeEncodingConfig()
	config := fixtureConfig{
		ChainID: "pqcload-test-1", Denom: "peaka", Seed: "unit-test",
		Fee: defaultFee, Transfer: defaultTransfer,
	}
	networkID := pqctypes.NetworkIDForChain(config.ChainID)
	recipientKey := secp256k1.GenPrivKeyFromSecret([]byte("recipient"))
	recipient := sdk.AccAddress(recipientKey.PubKey().Address())

	classic := secp256k1.GenPrivKeyFromSecret([]byte("classic"))
	nativeValue, err := mldsa65.GenPrivKeyFromSeed(deriveSeed(config.Seed, "native", 0))
	require.NoError(t, err)
	native := cryptotypes.PrivKey(&nativeValue)
	hybrid := secp256k1.GenPrivKeyFromSecret([]byte("hybrid"))
	hybridPQC, err := mldsa65.GenPrivKeyFromSeed(deriveSeed(config.Seed, "hybrid", 0))
	require.NoError(t, err)

	tests := []struct {
		mode       string
		privateKey cryptotypes.PrivKey
		pqcKey     []byte
		gas        uint64
	}{
		{mode: "classic", privateKey: classic, gas: 90_000},
		{mode: "hybrid", privateKey: hybrid, pqcKey: hybridPQC.Bytes(), gas: 400_000},
		{mode: "native", privateKey: native, gas: 250_000},
	}
	for index, test := range tests {
		t.Run(test.mode, func(t *testing.T) {
			accountNumber := uint64(1_000_000 + index)
			signer := sdk.AccAddress(test.privateKey.PubKey().Address())
			raw := buildTransaction(
				test.mode, test.privateKey, test.pqcKey, signer, recipient,
				accountNumber, test.gas, config, networkID, encoding.TxConfig,
			)
			decoded, err := encoding.TxConfig.TxDecoder()(raw)
			require.NoError(t, err)
			verifiable, ok := decoded.(authsigning.Tx)
			require.True(t, ok)
			signatures, err := verifiable.GetSignaturesV2()
			require.NoError(t, err)
			require.Len(t, signatures, 1)
			single, ok := signatures[0].Data.(*txsigning.SingleSignatureData)
			require.True(t, ok)
			require.Equal(t, txsigning.SignMode_SIGN_MODE_DIRECT, single.SignMode)
			signerData := authsigning.SignerData{
				ChainID: config.ChainID, AccountNumber: accountNumber, Sequence: 0,
				PubKey: test.privateKey.PubKey(), Address: signer.String(),
			}
			signBytes, err := authsigning.GetSignBytesAdapter(
				context.Background(), encoding.TxConfig.SignModeHandler(), single.SignMode,
				signerData, decoded,
			)
			require.NoError(t, err)
			require.True(t, test.privateKey.PubKey().VerifySignature(signBytes, single.Signature))

			provider, ok := decoded.(protoTxProvider)
			require.True(t, ok)
			options := provider.GetProtoTx().Body.ExtensionOptions
			if test.mode != "hybrid" {
				require.Empty(t, options)
				return
			}
			require.Len(t, options, 1)
			var extension pqctypes.ExtensionPQCAuth
			require.NoError(t, extension.Unmarshal(options[0].Value))
			require.Len(t, extension.Signatures, 1)
			entry := extension.Signatures[0]
			doc, err := pqctypes.NewPQCSignDocV1(
				provider.GetProtoTx(), networkID, config.ChainID, accountNumber, 0, 0,
				signer.String(), 1, pqctypes.Algorithm_ALGORITHM_ML_DSA_65, 1,
			)
			require.NoError(t, err)
			pqcSignBytes, err := pqctypes.MarshalPQCSignDocV1(doc)
			require.NoError(t, err)
			require.NoError(t, pqccrypto.Verify(
				pqccrypto.AlgorithmMLDSA65, hybridPQC.PubKey().Bytes(), pqcSignBytes,
				[]byte(pqctypes.TxSignatureContext), entry.Signature,
			))
		})
	}
}

func TestGenesisPatchUsesIndependentAccountsAndHybridPolicies(t *testing.T) {
	configureSDK()
	classic := secp256k1.GenPrivKeyFromSecret([]byte("classic-genesis"))
	hybrid := secp256k1.GenPrivKeyFromSecret([]byte("hybrid-genesis"))
	signing, err := mldsa65.GenPrivKeyFromSeed(deriveSeed("genesis", "signing", 0))
	require.NoError(t, err)
	recovery, err := mldsa65.GenPrivKeyFromSeed(deriveSeed("genesis", "recovery", 0))
	require.NoError(t, err)

	var patch genesisPatch
	appendGenesisAccount(&patch, sdk.AccAddress(classic.PubKey().Address()), nil, 100, "peaka", 1_000)
	owner := sdk.AccAddress(hybrid.PubKey().Address())
	appendGenesisAccount(&patch, owner, hybrid.PubKey(), 101, "peaka", 1_000)
	appendHybridGenesis(&patch, owner, signing.PubKey().Bytes(), recovery.PubKey().Bytes())

	require.Len(t, patch.AuthAccounts, 2)
	require.Len(t, patch.BankBalances, 2)
	require.Len(t, patch.PQCKeys, 2)
	require.Len(t, patch.PQCPolicies, 1)
	require.Len(t, patch.PQCKeySequences, 1)
	require.NotEqual(t, patch.PQCKeys[0]["public_key"], patch.PQCKeys[1]["public_key"])
	require.Nil(t, patch.AuthAccounts[0]["pub_key"])
	require.NotNil(t, patch.AuthAccounts[1]["pub_key"])
}
