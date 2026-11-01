package ante

import (
	"bytes"
	"errors"
	"runtime"
	"testing"

	codectypes "github.com/cosmos/cosmos-sdk/codec/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
	txtypes "github.com/cosmos/cosmos-sdk/types/tx"
	"github.com/stretchr/testify/require"

	"github.com/DoraFactory/doravota/x/pqcauth/types"
)

func TestPQCWireRejectsAmplificationBeforeDecode(t *testing.T) {
	for _, nonCritical := range []bool{false, true} {
		for _, n := range []int{33, 32760, 500000} {
			ext := append([]byte{8, 1}, bytes.Repeat([]byte{18, 0}, n)...)
			body := &txtypes.TxBody{}
			options := []*codectypes.Any{{TypeUrl: types.ExtensionPQCAuthTypeURL, Value: ext}}
			if nonCritical {
				body.NonCriticalExtensionOptions = options
			} else {
				body.ExtensionOptions = options
			}
			bz, err := body.Marshal()
			require.NoError(t, err)
			raw, err := (&txtypes.TxRaw{BodyBytes: bz}).Marshal()
			require.NoError(t, err)
			called := false
			decoder := CanonicalPQCAuthTxDecoder(func([]byte) (sdk.Tx, error) { called = true; return nil, nil })
			runtime.GC()
			var before, after runtime.MemStats
			runtime.ReadMemStats(&before)
			_, err = decoder(raw)
			runtime.ReadMemStats(&after)
			require.ErrorIs(t, err, types.ErrInvalidExtension)
			require.False(t, called)
			// Generous bound for runtime/test noise; the old decoder allocated
			// 12.6 MB / 202.6 MB for the larger two cases.
			require.Less(t, after.TotalAlloc-before.TotalAlloc, uint64(1<<20))
		}
	}
}

func TestPQCWirePreflightBoundaries(t *testing.T) {
	for _, n := range []int{0, 1, 32} {
		raw := append([]byte{8, 1}, bytes.Repeat([]byte{18, 0}, n)...)
		require.NoError(t, preflightPQCExtension(raw, types.AbsoluteMaxPQCAuthBytes, types.AbsoluteMaxPQCSigners))
	}
	require.Error(t, preflightPQCExtension(bytes.Repeat([]byte{18, 0}, 3), 100, 2))
	for _, raw := range [][]byte{{0xff}, {18, 0xff}, {0}, {0x0b}, {18, 3, 1}, {8, 0xff}} {
		require.Error(t, preflightPQCExtension(raw, 100, 32))
	}
}

func FuzzPQCWirePreflightDoesNotPanic(f *testing.F) {
	f.Add([]byte{8, 1, 18, 0})
	f.Add([]byte{0xff})
	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > int(types.AbsoluteMaxPQCAuthBytes)+1 {
			return
		}
		_ = preflightPQCExtension(raw, types.AbsoluteMaxPQCAuthBytes, types.AbsoluteMaxPQCSigners)
		_ = preflightPQCWire(raw)
	})
}

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
