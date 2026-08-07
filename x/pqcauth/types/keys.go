package types

import (
	"encoding/binary"

	sdk "github.com/cosmos/cosmos-sdk/types"
)

const (
	ModuleName = "pqcauth"
	StoreKey   = ModuleName
	RouterKey  = ModuleName
)

var (
	ParamsKey                = []byte{0x01}
	AccountPolicyKeyPrefix   = []byte{0x02}
	PQCKeyRecordKeyPrefix    = []byte{0x03}
	AccountSequenceKeyPrefix = []byte{0x04}
	AccountKeyHistoryPrefix  = []byte{0x05}
)

func accountScopedPrefix(prefix []byte, owner sdk.AccAddress) []byte {
	key := make([]byte, 0, len(prefix)+1+len(owner))
	key = append(key, prefix...)
	key = append(key, byte(len(owner)))
	key = append(key, owner...)
	return key
}

func AccountPolicyKey(owner sdk.AccAddress) []byte {
	return accountScopedPrefix(AccountPolicyKeyPrefix, owner)
}

func AccountSequenceKey(owner sdk.AccAddress) []byte {
	return accountScopedPrefix(AccountSequenceKeyPrefix, owner)
}

func AccountKeyHistoryKey(owner sdk.AccAddress, role KeyRole) []byte {
	key := accountScopedPrefix(AccountKeyHistoryPrefix, owner)
	return append(key, byte(role))
}

func PQCKeyRecordPrefix(owner sdk.AccAddress) []byte {
	return accountScopedPrefix(PQCKeyRecordKeyPrefix, owner)
}

func PQCKeyRecordKey(owner sdk.AccAddress, keyID uint64) []byte {
	key := PQCKeyRecordPrefix(owner)
	id := make([]byte, 8)
	binary.BigEndian.PutUint64(id, keyID)
	return append(key, id...)
}
