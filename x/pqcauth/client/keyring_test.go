package client

import (
	"context"
	pqccrypto "github.com/DoraFactory/doravota/x/pqcauth/crypto"
	"github.com/cosmos/cosmos-sdk/codec"
	codectypes "github.com/cosmos/cosmos-sdk/codec/types"
	cryptocodec "github.com/cosmos/cosmos-sdk/crypto/codec"
	"github.com/cosmos/cosmos-sdk/crypto/hd"
	"github.com/cosmos/cosmos-sdk/crypto/keyring"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestSDKKeyringFactorSigningRecoveryAndReuseGuard(t *testing.T) {
	reg := codectypes.NewInterfaceRegistry()
	cryptocodec.RegisterInterfaces(reg)
	keys := keyring.NewInMemory(codec.NewProtoCodec(reg))
	path := "m/44'/118'/0'/0/0"
	_, mnemonic, err := keys.NewMnemonic("owner", keyring.English, path, "", hd.Secp256k1)
	require.NoError(t, err)
	_, err = keys.NewAccount("coupled", mnemonic, "", path, hd.MlDsa65)
	require.NoError(t, err)
	bad, err := NewKeyringSigner(keys, "coupled")
	require.NoError(t, err)
	badPub, err := bad.PublicKey(context.Background())
	require.NoError(t, err)
	checked, err := CheckFactorIndependence(keys, "owner", badPub)
	require.True(t, checked)
	require.ErrorContains(t, err, "unsafe PQC factor")
	_, dedicated, err := keys.NewMnemonic("factor", keyring.English, path, "", hd.MlDsa65)
	require.NoError(t, err)
	signer, err := NewKeyringSigner(keys, "factor")
	require.NoError(t, err)
	pub, err := signer.PublicKey(context.Background())
	require.NoError(t, err)
	checked, err = CheckFactorIndependence(keys, "owner", pub)
	require.True(t, checked)
	require.NoError(t, err)
	sig, err := signer.Sign(context.Background(), []byte("document"), []byte("domain"))
	require.NoError(t, err)
	require.NoError(t, pqccrypto.Verify(pqccrypto.AlgorithmMLDSA65, pub, []byte("document"), []byte("domain"), sig))
	require.Error(t, pqccrypto.Verify(pqccrypto.AlgorithmMLDSA65, pub, []byte("document"), []byte("other-domain"), sig))
	require.Error(t, pqccrypto.Verify(pqccrypto.AlgorithmMLDSA65, pub, []byte("changed"), []byte("domain"), sig))
	_, err = NewKeyringSigner(keys, "owner")
	require.ErrorContains(t, err, "ml_dsa_65")
	// Restore the dedicated factor into a different keyring: restoration is valid.
	restored := keyring.NewInMemory(codec.NewProtoCodec(reg))
	_, err = restored.NewAccount("restored", dedicated, "", path, hd.MlDsa65)
	require.NoError(t, err)
	recovered, err := NewKeyringSigner(restored, "restored")
	require.NoError(t, err)
	recoveredPub, err := recovered.PublicKey(context.Background())
	require.NoError(t, err)
	require.Equal(t, pub, recoveredPub)
	recoveredSig, err := recovered.Sign(context.Background(), []byte("document"), []byte("domain"))
	require.NoError(t, err)
	require.Equal(t, sig, recoveredSig)
	// A watch-only owner record is explicitly uncheckable, not falsely safe.
	owner, err := keys.Key("owner")
	require.NoError(t, err)
	ownerPub, err := owner.GetPubKey()
	require.NoError(t, err)
	_, err = restored.SaveOfflineKey("watch", ownerPub)
	require.NoError(t, err)
	checked, err = CheckFactorIndependence(restored, "watch", pub)
	require.NoError(t, err)
	require.False(t, checked)
}
