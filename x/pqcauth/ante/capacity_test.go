package ante

import (
	"math"
	"strings"
	"testing"

	"github.com/DoraFactory/doravota/x/pqcauth/types"
	codectypes "github.com/cosmos/cosmos-sdk/codec/types"
	"github.com/stretchr/testify/require"
)

func TestExtensionAtCapacityByteFloor(t *testing.T) {
	for _, count := range []uint32{2, 8, 32} {
		p := types.DefaultParams()
		p.MaxPqcSigners = count
		p.MaxPqcAuthBytes = types.MinimumPQCAuthBytes(count)
		p.MaxPqcVerificationsPerTx = max(count, types.MinimumMaxPQCVerificationsPerTx)
		require.NoError(t, p.Validate())
		ext := types.ExtensionPQCAuth{FormatVersion: types.FormatVersionV1}
		for i := uint32(0); i < count; i++ {
			e := validExtensionEntry()
			e.Signer = strings.Repeat("x", types.MaxPQCSignerAddressBytes)
			e.SignerIndex, e.KeyId, e.PolicyVersion = math.MaxUint32-count+1+i, math.MaxUint64, math.MaxUint64
			ext.Signatures = append(ext.Signatures, e)
		}
		tx := extensionOptionsTxStub{critical: []*codectypes.Any{encodedExtension(t, ext)}}
		_, found, err := ExtractExtension(tx, p)
		require.NoError(t, err, "maximum-width structure must fit the configured floor")
		require.True(t, found)
		p.MaxPqcAuthBytes--
		_, _, err = ExtractExtension(tx, p)
		require.ErrorContains(t, err, "exceeds size limit")
	}
}
