package ante

import (
	"errors"
	"testing"

	codectypes "github.com/cosmos/cosmos-sdk/codec/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
	txtypes "github.com/cosmos/cosmos-sdk/types/tx"
	"github.com/stretchr/testify/require"

	"github.com/DoraFactory/doravota/x/pqcauth/types"
)

func TestCanonicalPQCAuthTxDecoderChecksOriginalWireBytes(t *testing.T) {
	canonical := encodedWireTx(t, false, false)
	called := false
	decoder := CanonicalPQCAuthTxDecoder(func([]byte) (sdk.Tx, error) {
		called = true
		return nil, nil
	})

	_, err := decoder(canonical)
	require.NoError(t, err)
	require.True(t, called)

	called = false
	_, err = decoder(encodedWireTx(t, true, false))
	require.ErrorIs(t, err, types.ErrInvalidExtension)
	require.False(t, called)
}

func TestCanonicalPQCAuthTxDecoderChecksNonCriticalOptions(t *testing.T) {
	decoder := CanonicalPQCAuthTxDecoder(func([]byte) (sdk.Tx, error) {
		return nil, nil
	})
	_, err := decoder(encodedWireTx(t, true, true))
	require.ErrorIs(t, err, types.ErrInvalidExtension)
}

func TestCanonicalPQCAuthTxDecoderDelegatesOrdinaryWire(t *testing.T) {
	called := false
	wantErr := errors.New("default decoder rejection")
	decoder := CanonicalPQCAuthTxDecoder(func([]byte) (sdk.Tx, error) {
		called = true
		return nil, wantErr
	})
	_, err := decoder([]byte{0xff})
	require.ErrorIs(t, err, wantErr)
	require.True(t, called)
}

func encodedWireTx(t *testing.T, nonCanonical, nonCritical bool) []byte {
	t.Helper()
	extension := types.ExtensionPQCAuth{FormatVersion: types.FormatVersionV1}
	value, err := extension.Marshal()
	require.NoError(t, err)
	if nonCanonical {
		value = append(value, 0x08, 0x01)
	}
	option := &codectypes.Any{TypeUrl: types.ExtensionPQCAuthTypeURL, Value: value}
	body := txtypes.TxBody{}
	if nonCritical {
		body.NonCriticalExtensionOptions = []*codectypes.Any{option}
	} else {
		body.ExtensionOptions = []*codectypes.Any{option}
	}
	bodyBytes, err := body.Marshal()
	require.NoError(t, err)
	rawBytes, err := (&txtypes.TxRaw{BodyBytes: bodyBytes}).Marshal()
	require.NoError(t, err)
	return rawBytes
}
