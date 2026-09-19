package v0_5_0

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"

	"cosmossdk.io/log/v2"
	tmtypes "github.com/cometbft/cometbft/types"
	dbm "github.com/cosmos/cosmos-db"
	"github.com/cosmos/cosmos-sdk/store/v2/rootmulti"
	storetypes "github.com/cosmos/cosmos-sdk/store/v2/types"
	"github.com/cosmos/cosmos-sdk/types/module"
	authtypes "github.com/cosmos/cosmos-sdk/x/auth/types"
	govv1 "github.com/cosmos/cosmos-sdk/x/gov/types/v1"
	"github.com/stretchr/testify/require"
	"time"
)

func TestSourceVersionMap(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(module.VersionMap)
		bad    bool
	}{
		{"release", func(module.VersionMap) {}, false},
		{"historical crisis", func(m module.VersionMap) { m["crisis"] = 2 }, false},
		{"wrong crisis", func(m module.VersionMap) { m["crisis"] = 1 }, true},
		{"missing", func(m module.VersionMap) { delete(m, "bank") }, true},
		{"newer", func(m module.VersionMap) { m["ibc"] = 8 }, true},
		{"unknown", func(m module.VersionMap) { m["custom"] = 1 }, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := SourceVersionMap()
			tc.change(m)
			err := ValidateSourceVersionMap(m)
			if tc.bad {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestConsensusPreflight(t *testing.T) {
	p := tmtypes.DefaultConsensusParams().ToProto()
	require.NoError(t, ValidateLegacyConsensusParams(p))
	p.Version = nil
	require.NotPanics(t, func() { require.NoError(t, ValidateLegacyConsensusParams(p)) })
	p.Block.MaxBytes = 0
	require.Error(t, ValidateLegacyConsensusParams(p))
	p.Block = nil
	require.Error(t, ValidateLegacyConsensusParams(p))
}

func TestPreflightBeforeStoreDeletion(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(map[string]storetypes.KVStore)
		want   string
	}{
		{"empty fees", func(map[string]storetypes.KVStore) {}, ""},
		{"missing governance", func(s map[string]storetypes.KVStore) { s["gov"].Delete(legacyGovParamsKey) }, "governance parameters are missing"},
		{"incompatible rehearsal governance", func(s map[string]storetypes.KVStore) {
			p := govv1.DefaultParams()
			d := time.Minute
			p.VotingPeriod = &d
			b, err := p.Marshal()
			require.NoError(t, err)
			s["gov"].Set(legacyGovParamsKey, b)
		}, "strictly less"},
		{"legacy empty fee root", func(map[string]storetypes.KVStore) {}, ""},
		{"escrow", func(s map[string]storetypes.KVStore) {
			s["feeibc"].Set([]byte("feesInEscrow/transfer/channel-0/1"), []byte{1})
		}, "feeibc is not empty"},
		{"balance without fees", func(s map[string]storetypes.KVStore) {
			a := authtypes.NewModuleAddress("feeibc")
			k := append([]byte{2, byte(len(a))}, a...)
			s["bank"].Set(append(k, []byte("peaka")...), []byte("1"))
		}, "balance entry"},
		{"bad version", func(s map[string]storetypes.KVStore) {
			s["upgrade"].Set(append([]byte{2}, []byte("bank")...), []byte{1})
		}, "malformed module version"},
		{"missing consensus", func(s map[string]storetypes.KVStore) { s["upgrade"].Delete([]byte("Consensus")) }, "Consensus record is missing"},
		{"corrupt consensus", func(s map[string]storetypes.KVStore) { s["upgrade"].Set([]byte("Consensus"), []byte{255}) }, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db, err := dbm.NewDB("preflight", dbm.GoLevelDBBackend, t.TempDir())
			require.NoError(t, err)
			t.Cleanup(func() { require.NoError(t, db.Close()) })
			multi := rootmulti.NewStore(db, log.NewNopLogger())
			keys := map[string]*storetypes.KVStoreKey{}
			for _, name := range []string{"feeibc", "bank", "upgrade", "gov"} {
				keys[name] = storetypes.NewKVStoreKey(name)
				multi.MountStoreWithDB(keys[name], storetypes.StoreTypeIAVL, nil)
			}
			require.NoError(t, multi.LoadLatestVersion())
			require.NoError(t, multi.SetInitialVersion(9))
			stores := map[string]storetypes.KVStore{}
			for name, key := range keys {
				stores[name] = multi.GetKVStore(key)
			}
			for name, version := range SourceVersionMap() {
				b := make([]byte, 8)
				binary.BigEndian.PutUint64(b, version)
				stores["upgrade"].Set(append([]byte{2}, []byte(name)...), b)
			}
			p := tmtypes.DefaultConsensusParams().ToProto()
			b, err := p.Marshal()
			require.NoError(t, err)
			stores["upgrade"].Set([]byte("Consensus"), b)
			govParams := govv1.DefaultParams()
			voting := 24 * time.Hour
			govParams.VotingPeriod = &voting
			govRaw, err := govParams.Marshal()
			require.NoError(t, err)
			stores["gov"].Set(legacyGovParamsKey, govRaw)
			tc.change(stores)
			multi.Commit()
			if tc.name == "legacy empty fee root" {
				deletePrefix(t, db, []byte(iavlStorePrefix+"feeibc/"))
				prefix := dbm.NewPrefixDB(db, []byte(iavlStorePrefix+"feeibc/"))
				require.NoError(t, prefix.Set(legacyIAVLRootKey(9), []byte{}))
			}
			home := t.TempDir()
			require.NoError(t, os.MkdirAll(filepath.Join(home, "data"), 0700))
			require.NoError(t, os.WriteFile(filepath.Join(home, "data", "upgrade-info.json"), []byte(`{"name":"0.5.0","height":10}`), 0600))
			before := dumpDB(t, db)
			err = ValidateUpgradeBoundary(log.NewNopLogger(), db, home)
			if tc.name == "corrupt consensus" {
				require.Error(t, err)
			} else if tc.want != "" {
				require.ErrorContains(t, err, tc.want)
			} else {
				require.NoError(t, err)
			}
			require.Equal(t, before, dumpDB(t, db), "preflight must not write/delete any state")
		})
	}
}

func dumpDB(t *testing.T, db dbm.DB) map[string]string {
	t.Helper()
	it, err := db.Iterator(nil, nil)
	require.NoError(t, err)
	defer it.Close()
	out := map[string]string{}
	for ; it.Valid(); it.Next() {
		out[string(it.Key())] = string(it.Value())
	}
	require.NoError(t, it.Error())
	return out
}
