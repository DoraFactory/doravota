package types

import (
	"bytes"
	"compress/gzip"
	"io"
	"testing"

	"github.com/cosmos/gogoproto/proto"
	"github.com/cosmos/gogoproto/protoc-gen-gogo/descriptor"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/encoding/protowire"
)

func TestSimplifiedParamsReserveRemovedFields(t *testing.T) {
	raw, _ := (&Params{}).Descriptor()
	reader, err := gzip.NewReader(bytes.NewReader(raw))
	require.NoError(t, err)
	data, err := io.ReadAll(reader)
	require.NoError(t, err)
	require.NoError(t, reader.Close())
	var file descriptor.FileDescriptorProto
	require.NoError(t, proto.Unmarshal(data, &file))
	for _, tc := range []struct {
		name     string
		reserved []int32
		gas      int32
	}{
		{"Params", []int32{3, 4, 5, 6, 7, 8, 9, 16, 18, 19}, 21},
		{"ScheduledParams", []int32{2, 3, 4, 5, 6, 7, 8, 11, 12, 13}, 14},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var msg *descriptor.DescriptorProto
			for _, m := range file.MessageType {
				if m.GetName() == tc.name {
					msg = m
				}
			}
			require.NotNil(t, msg)
			for _, n := range tc.reserved {
				found := false
				for _, r := range msg.ReservedRange {
					if n >= r.GetStart() && n < r.GetEnd() {
						found = true
					}
				}
				require.True(t, found, "field %d must remain reserved", n)
				for _, f := range msg.Field {
					require.NotEqual(t, n, f.GetNumber())
				}
			}
			require.Len(t, msg.ReservedName, 10)
			found := false
			for _, f := range msg.Field {
				if f.GetName() == "verification_gas" {
					require.Equal(t, tc.gas, f.GetNumber())
					found = true
				}
			}
			require.True(t, found)
		})
	}
}

func TestLegacyPricesCannotSilentlyInitializeNewSchema(t *testing.T) {
	p := DefaultParams()
	p.VerificationGas = 0 // old schema never encoded field 21
	raw, err := p.Marshal()
	require.NoError(t, err)
	for _, n := range []protowire.Number{4, 5} {
		raw = protowire.AppendTag(raw, n, protowire.VarintType)
		raw = protowire.AppendVarint(raw, 250000)
	}
	var decoded Params
	require.NoError(t, decoded.Unmarshal(raw))
	require.Zero(t, decoded.VerificationGas)
	require.Error(t, decoded.Validate(), "reserved fields are not a state migration")
}
