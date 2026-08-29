package types

import (
	"encoding/binary"
	"errors"
	"fmt"
	"time"

	sdk "github.com/cosmos/cosmos-sdk/types"
)

const feegrantExpirationKeySize = 12

func EncodeFeegrantIndexValue(expiration *time.Time) ([]byte, error) {
	if expiration == nil {
		return []byte{0}, nil
	}
	if expiration.Unix() < 0 || expiration.Nanosecond() < 0 || expiration.Nanosecond() >= int(time.Second) {
		return nil, errors.New("feegrant expiration must be a non-negative canonical timestamp")
	}
	encoded := make([]byte, 1+feegrantExpirationKeySize)
	encoded[0] = 1
	binary.BigEndian.PutUint64(encoded[1:9], uint64(expiration.Unix()))
	binary.BigEndian.PutUint32(encoded[9:13], uint32(expiration.Nanosecond()))
	return encoded, nil
}

func DecodeFeegrantIndexValue(encoded []byte) (*time.Time, error) {
	if len(encoded) == 1 && encoded[0] == 0 {
		return nil, nil
	}
	if len(encoded) != 1+feegrantExpirationKeySize || encoded[0] != 1 {
		return nil, errors.New("invalid feegrant reverse-index value")
	}
	seconds := binary.BigEndian.Uint64(encoded[1:9])
	if seconds > uint64(^uint64(0)>>1) {
		return nil, errors.New("feegrant expiration exceeds int64")
	}
	nanos := binary.BigEndian.Uint32(encoded[9:13])
	if nanos >= uint32(time.Second) {
		return nil, errors.New("feegrant expiration has invalid nanoseconds")
	}
	expiration := time.Unix(int64(seconds), int64(nanos)).UTC()
	return &expiration, nil
}

func FeegrantExpiryKey(expiration time.Time, granter, grantee sdk.AccAddress) ([]byte, error) {
	encoded, err := EncodeFeegrantIndexValue(&expiration)
	if err != nil {
		return nil, err
	}
	key := make([]byte, 0, len(FeegrantExpiryKeyPrefix)+feegrantExpirationKeySize+2+len(granter)+len(grantee))
	key = append(key, FeegrantExpiryKeyPrefix...)
	key = append(key, encoded[1:]...)
	// Match the SDK feegrant queue order exactly: expiration, grantee,
	// granter. The SDK prunes a bounded number of entries per operation, so a
	// different tie-break order could otherwise remove a different subset of
	// allowances that share an expiration timestamp.
	key = appendFeegrantAddress(key, grantee)
	return appendFeegrantAddress(key, granter), nil
}

func DecodeFeegrantReverseKey(key []byte) (sdk.AccAddress, sdk.AccAddress, error) {
	if len(key) < 1 || key[0] != FeegrantReverseKeyPrefix[0] {
		return nil, nil, errors.New("invalid feegrant reverse-index prefix")
	}
	granter, offset, err := decodeFeegrantAddress(key, 1)
	if err != nil {
		return nil, nil, fmt.Errorf("decode feegrant granter: %w", err)
	}
	grantee, offset, err := decodeFeegrantAddress(key, offset)
	if err != nil {
		return nil, nil, fmt.Errorf("decode feegrant grantee: %w", err)
	}
	if offset != len(key) {
		return nil, nil, errors.New("feegrant reverse-index key has trailing bytes")
	}
	return granter, grantee, nil
}

func DecodeFeegrantExpiryKey(key []byte) (time.Time, sdk.AccAddress, sdk.AccAddress, error) {
	if len(key) < 1+feegrantExpirationKeySize || key[0] != FeegrantExpiryKeyPrefix[0] {
		return time.Time{}, nil, nil, errors.New("invalid feegrant expiry-index key")
	}
	expiration, err := DecodeFeegrantIndexValue(append([]byte{1}, key[1:1+feegrantExpirationKeySize]...))
	if err != nil {
		return time.Time{}, nil, nil, err
	}
	offset := 1 + feegrantExpirationKeySize
	grantee, offset, err := decodeFeegrantAddress(key, offset)
	if err != nil {
		return time.Time{}, nil, nil, fmt.Errorf("decode feegrant expiry grantee: %w", err)
	}
	granter, offset, err := decodeFeegrantAddress(key, offset)
	if err != nil {
		return time.Time{}, nil, nil, fmt.Errorf("decode feegrant expiry granter: %w", err)
	}
	if offset != len(key) {
		return time.Time{}, nil, nil, errors.New("feegrant expiry-index key has trailing bytes")
	}
	return *expiration, granter, grantee, nil
}

func appendFeegrantAddress(key []byte, address sdk.AccAddress) []byte {
	key = append(key, byte(len(address)))
	return append(key, address...)
}

func decodeFeegrantAddress(key []byte, offset int) (sdk.AccAddress, int, error) {
	if offset >= len(key) {
		return nil, offset, errors.New("missing address length")
	}
	length := int(key[offset])
	offset++
	if length == 0 || offset+length > len(key) {
		return nil, offset, errors.New("invalid address length")
	}
	address := append(sdk.AccAddress(nil), key[offset:offset+length]...)
	return address, offset + length, nil
}
