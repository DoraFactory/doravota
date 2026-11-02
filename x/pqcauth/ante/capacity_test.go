package ante

import (
	"math"
	"strings"
	"testing"

	"github.com/DoraFactory/doravota/x/pqcauth/types"
	codectypes "github.com/cosmos/cosmos-sdk/codec/types"
	"github.com/stretchr/testify/require"
)

func TestFixedExtensionCaps(t *testing.T) {
	p := types.DefaultParams()
	for _, count := range []uint32{2, types.MaxPQCSigners, types.MaxPQCSigners + 1} {
		ext := types.ExtensionPQCAuth{FormatVersion: types.FormatVersionV1}
		for i := uint32(0); i < count; i++ {
			e := validExtensionEntry()
			e.Signer = strings.Repeat("x", 1023)
			e.SignerIndex, e.KeyId, e.PolicyVersion = math.MaxUint32-count+1+i, math.MaxUint64, math.MaxUint64
			ext.Signatures = append(ext.Signatures, e)
		}
		tx := extensionOptionsTxStub{critical: []*codectypes.Any{encodedExtension(t, ext)}}
		_, found, err := ExtractExtension(tx, p)
		if count <= types.MaxPQCSigners {
			require.NoError(t, err)
			require.True(t, found)
		} else {
			require.ErrorContains(t, err, "too many PQC signer")
		}
	}
	tx := extensionOptionsTxStub{critical: []*codectypes.Any{{TypeUrl: types.ExtensionPQCAuthTypeURL, Value: make([]byte, types.MaxPQCAuthBytes+1)}}}
	_, _, err := ExtractExtension(tx, p)
	require.ErrorContains(t, err, "exceeds size limit")
}
