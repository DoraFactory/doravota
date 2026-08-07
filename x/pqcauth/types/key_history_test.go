package types

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestAccumulateKeyHistoryIsDeterministicAndCommitsRecordFields(t *testing.T) {
	record := PQCKeyRecord{
		Owner:              "dora1history",
		KeyId:              9,
		Algorithm:          Algorithm_ALGORITHM_ML_DSA_65,
		PublicKey:          bytes.Repeat([]byte{0x45}, 1952),
		Role:               KeyRole_KEY_ROLE_SIGNING,
		Status:             KeyStatus_KEY_STATUS_REVOKED,
		CreatedHeight:      2,
		EffectiveHeight:    3,
		InactiveFromHeight: 10,
	}
	first, err := AccumulateKeyHistory(nil, record)
	require.NoError(t, err)
	second, err := AccumulateKeyHistory(nil, record)
	require.NoError(t, err)
	require.Equal(t, first, second)
	require.Len(t, first, KeyHistoryAccumulatorSize)

	mutated := record
	mutated.InactiveFromHeight++
	different, err := AccumulateKeyHistory(nil, mutated)
	require.NoError(t, err)
	require.NotEqual(t, first, different)

	_, err = AccumulateKeyHistory([]byte{0x01}, record)
	require.ErrorIs(t, err, ErrInvalidKey)
}

func TestValidateDistinctRoleKeys(t *testing.T) {
	key := bytes.Repeat([]byte{0x23}, 1952)
	require.ErrorIs(t, ValidateDistinctRoleKeys(
		Algorithm_ALGORITHM_ML_DSA_65,
		key,
		Algorithm_ALGORITHM_ML_DSA_65,
		append([]byte(nil), key...),
	), ErrInvalidKey)

	different := append([]byte(nil), key...)
	different[len(different)-1] ^= 0xff
	require.NoError(t, ValidateDistinctRoleKeys(
		Algorithm_ALGORITHM_ML_DSA_65,
		key,
		Algorithm_ALGORITHM_ML_DSA_65,
		different,
	))
}
