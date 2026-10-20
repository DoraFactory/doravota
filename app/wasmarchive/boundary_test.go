package wasmarchive

import (
	"cosmossdk.io/log/v2"
	"encoding/binary"
	dbm "github.com/cosmos/cosmos-db"
	"github.com/cosmos/cosmos-sdk/store/v2/rootmulti"
	storetypes "github.com/cosmos/cosmos-sdk/store/v2/types"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestPostArchiveModuleBoundary(t *testing.T) {
	for _, tc := range []struct {
		name, extraStore string
		version          uint64
		liveWasm, valid  bool
	}{
		{name: "existing archive", valid: true},
		{name: "initialized pqcauth", extraStore: "pqcauth", version: 2, valid: true},
		{name: "uninitialized store", extraStore: "pqcauth"},
		{name: "missing store", version: 2},
		{name: "wrong module version", extraStore: "pqcauth", version: 1},
		{name: "unknown store", extraStore: "unexpected"},
		{name: "live wasm conflict", extraStore: "pqcauth", version: 2, liveWasm: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db := dbm.NewMemDB()
			t.Cleanup(func() { require.NoError(t, db.Close()) })
			multi := rootmulti.NewStore(db, log.NewNopLogger())
			names := append([]string(nil), retainedStores...)
			if tc.extraStore != "" {
				names = append(names, tc.extraStore)
			}
			keys := map[string]*storetypes.KVStoreKey{}
			for _, name := range names {
				keys[name] = storetypes.NewKVStoreKey(name)
				multi.MountStoreWithDB(keys[name], storetypes.StoreTypeIAVL, nil)
			}
			require.NoError(t, multi.LoadLatestVersion())
			cache := multi.CacheMultiStore()
			for _, key := range keys {
				cache.GetKVStore(key).Set([]byte("sentinel"), []byte("preserve"))
			}
			versions := cache.GetKVStore(keys["upgrade"])
			writeVersion := func(name string, v uint64) {
				raw := make([]byte, 8)
				binary.BigEndian.PutUint64(raw, v)
				versions.Set(append([]byte{2}, []byte(name)...), raw)
			}
			writeVersion(GenesisKey, 1)
			if tc.version > 0 {
				writeVersion("pqcauth", tc.version)
			}
			if tc.liveWasm {
				writeVersion(StoreKey, 1)
			}
			cache.Write()
			multi.Commit()
			err := ValidateBoundaryWithModules(log.NewNopLogger(), db, t.TempDir(), nil, map[string]uint64{"pqcauth": 2})
			if tc.valid {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
			}
		})
	}
}
