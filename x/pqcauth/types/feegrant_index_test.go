package types

import (
	"bytes"
	"testing"
	"time"

	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/stretchr/testify/require"
)

func TestFeegrantIndexEncodingRoundTrip(t *testing.T) {
	encoded, err := EncodeFeegrantIndexValue(nil)
	require.NoError(t, err)
	require.Equal(t, []byte{0}, encoded)
	decoded, err := DecodeFeegrantIndexValue(encoded)
	require.NoError(t, err)
	require.Nil(t, decoded)

	expiration := time.Unix(1_900_000_000, 987_654_321).UTC()
	encoded, err = EncodeFeegrantIndexValue(&expiration)
	require.NoError(t, err)
	decoded, err = DecodeFeegrantIndexValue(encoded)
	require.NoError(t, err)
	require.True(t, expiration.Equal(*decoded))
}

func TestFeegrantIndexKeysRoundTrip(t *testing.T) {
	granter := sdk.AccAddress(bytes.Repeat([]byte{0x31}, 20))
	grantee := sdk.AccAddress(bytes.Repeat([]byte{0x32}, 32))
	reverseKey := FeegrantReverseKey(granter, grantee)
	decodedGranter, decodedGrantee, err := DecodeFeegrantReverseKey(reverseKey)
	require.NoError(t, err)
	require.Equal(t, granter, decodedGranter)
	require.Equal(t, grantee, decodedGrantee)

	expiration := time.Unix(1_900_000_000, 123).UTC()
	expiryKey, err := FeegrantExpiryKey(expiration, granter, grantee)
	require.NoError(t, err)
	decodedExpiration, decodedGranter, decodedGrantee, err := DecodeFeegrantExpiryKey(expiryKey)
	require.NoError(t, err)
	require.True(t, expiration.Equal(decodedExpiration))
	require.Equal(t, granter, decodedGranter)
	require.Equal(t, grantee, decodedGrantee)
}

func TestFeegrantExpiryKeyMatchesSDKQueueTieBreakOrder(t *testing.T) {
	expiration := time.Unix(1_900_000_000, 123).UTC()
	low := sdk.AccAddress(bytes.Repeat([]byte{0x11}, 20))
	high := sdk.AccAddress(bytes.Repeat([]byte{0x22}, 20))

	// With the same expiration, grantee order must take precedence over
	// granter order, exactly as in feegrant.FeeAllowanceQueue.
	first, err := FeegrantExpiryKey(expiration, high, low)
	require.NoError(t, err)
	second, err := FeegrantExpiryKey(expiration, low, high)
	require.NoError(t, err)
	require.Less(t, bytes.Compare(first, second), 0)
}

func TestFeegrantIndexDecodingRejectsMalformedData(t *testing.T) {
	_, err := DecodeFeegrantIndexValue(nil)
	require.Error(t, err)
	_, err = DecodeFeegrantIndexValue([]byte{2})
	require.Error(t, err)

	_, _, err = DecodeFeegrantReverseKey([]byte{FeegrantReverseKeyPrefix[0], 20, 1})
	require.Error(t, err)
	_, _, _, err = DecodeFeegrantExpiryKey([]byte{FeegrantExpiryKeyPrefix[0]})
	require.Error(t, err)
}
