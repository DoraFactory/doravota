package types

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParseExpiryIndexKey(t *testing.T) {
	fullIndexKey := GetExpiryIndexKey(123, "contract", "user", "digest")
	relativeIndexKey := fullIndexKey[len(ExpiryIndexKeyPrefix):]

	expiryHeight, ticketKey, ok := ParseExpiryIndexKey(relativeIndexKey)

	require.True(t, ok)
	require.Equal(t, uint64(123), expiryHeight)
	expectedTicketKey := GetPolicyTicketKey("contract", "user", "digest")[len(PolicyTicketKeyPrefix):]
	require.Equal(t, expectedTicketKey, ticketKey)
}

func TestParseExpiryIndexKeyRejectsMalformedKeys(t *testing.T) {
	testCases := [][]byte{
		nil,
		make([]byte, 7),
		make([]byte, 8),
		append(make([]byte, 8), ':'),
		append(make([]byte, 8), '/'),
	}

	for _, key := range testCases {
		_, _, ok := ParseExpiryIndexKey(key)
		require.False(t, ok)
	}
}

func TestParamsTicketGCPerBlockBound(t *testing.T) {
	params := DefaultParams()

	params.TicketGcPerBlock = 0
	require.NoError(t, params.Validate())

	params.TicketGcPerBlock = MaxTicketGCPerBlock
	require.NoError(t, params.Validate())

	params.TicketGcPerBlock = MaxTicketGCPerBlock + 1
	require.Error(t, params.Validate())
}
