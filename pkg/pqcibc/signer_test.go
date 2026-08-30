package pqcibc_test

import (
	"testing"

	"github.com/cometbft/cometbft/crypto/mldsa65"
	"github.com/cosmos/cosmos-sdk/codec"
	codectypes "github.com/cosmos/cosmos-sdk/codec/types"
	cryptocodec "github.com/cosmos/cosmos-sdk/crypto/codec"
	"github.com/cosmos/cosmos-sdk/crypto/hd"
	"github.com/cosmos/cosmos-sdk/crypto/keyring"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/stretchr/testify/require"

	"github.com/DoraFactory/doravota/pkg/pqcibc"
)

func TestNativeMLDSA65RelayerSigner(t *testing.T) {
	registry := codectypes.NewInterfaceRegistry()
	cryptocodec.RegisterInterfaces(registry)
	cdc := codec.NewProtoCodec(registry)
	kb, err := keyring.New(
		"pqc-ibc-relayer",
		keyring.BackendMemory,
		t.TempDir(),
		nil,
		cdc,
		pqcibc.KeyringOption(nil, nil),
	)
	require.NoError(t, err)

	software, ledger := kb.SupportedAlgorithms()
	require.True(t, software.Contains(hd.MlDsa65))
	require.False(t, ledger.Contains(hd.MlDsa65))

	record, mnemonic, err := pqcibc.NewNativeMLDSA65Key(kb, "relayer")
	require.NoError(t, err)
	require.NotEmpty(t, mnemonic)
	publicKey, err := record.GetPubKey()
	require.NoError(t, err)
	require.Equal(t, mldsa65.KeyType, publicKey.Type())

	signer, err := pqcibc.NewKeyringSigner(kb, "relayer")
	require.NoError(t, err)
	require.Equal(t, publicKey.Address().Bytes(), signer.Address().Bytes())

	signBytes := []byte("canonical MsgUpdateClient SIGN_MODE_DIRECT bytes")
	signature, err := signer.SignDirect(signBytes)
	require.NoError(t, err)
	require.Len(t, signature, mldsa65.SignatureSize)
	require.True(t, signer.PublicKey().VerifySignature(signBytes, signature))
}

func TestRelayerSignerRejectsClassicKey(t *testing.T) {
	registry := codectypes.NewInterfaceRegistry()
	cryptocodec.RegisterInterfaces(registry)
	kb, err := keyring.New(
		"pqc-ibc-relayer",
		keyring.BackendMemory,
		t.TempDir(),
		nil,
		codec.NewProtoCodec(registry),
		pqcibc.KeyringOption(nil, nil),
	)
	require.NoError(t, err)
	_, _, err = kb.NewMnemonic(
		"classic",
		keyring.English,
		sdk.FullFundraiserPath,
		keyring.DefaultBIP39Passphrase,
		hd.Secp256k1,
	)
	require.NoError(t, err)

	_, err = pqcibc.NewKeyringSigner(kb, "classic")
	require.ErrorContains(t, err, "expected \"ml_dsa_65\"")
}
