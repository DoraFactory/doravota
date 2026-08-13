package app

import (
	"fmt"
	"testing"

	"github.com/shamaton/msgpack/v2"
	"github.com/stretchr/testify/require"
)

// TestMsgpackRejectsTruncatedExtensionFrames locks in the upstream v2 security
// backport used by WasmVM metrics decoding. Older tagged releases panic when a
// fixext marker is not followed by its type and payload bytes.
func TestMsgpackRejectsTruncatedExtensionFrames(t *testing.T) {
	decoders := map[string]func([]byte, interface{}) error{
		"default": msgpack.Unmarshal,
		"array":   msgpack.UnmarshalAsArray,
		"map":     msgpack.UnmarshalAsMap,
	}

	for name, decode := range decoders {
		decode := decode
		t.Run(name, func(t *testing.T) {
			for marker := byte(0xd4); marker <= 0xd8; marker++ {
				marker := marker
				t.Run(fmt.Sprintf("0x%02x", marker), func(t *testing.T) {
					var target interface{}
					var err error
					require.NotPanics(t, func() {
						err = decode([]byte{marker}, &target)
					})
					require.Error(t, err)
				})
			}
		})
	}
}
