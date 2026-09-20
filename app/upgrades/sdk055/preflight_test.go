package sdk055

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"cosmossdk.io/log/v2"
	dbm "github.com/cosmos/cosmos-db"
	codectypes "github.com/cosmos/cosmos-sdk/codec/types"
	"github.com/cosmos/cosmos-sdk/store/v2/rootmulti"
	storetypes "github.com/cosmos/cosmos-sdk/store/v2/types"
	govtypes "github.com/cosmos/cosmos-sdk/x/gov/types/v1"
	upgradetypes "github.com/cosmos/cosmos-sdk/x/upgrade/types"
	"github.com/cosmos/gogoproto/proto"
	"github.com/stretchr/testify/require"
)

func encode(t *testing.T, m proto.Message) []byte {
	t.Helper()
	b, e := proto.Marshal(m)
	require.NoError(t, e)
	return b
}

// Fixtures are the observed 0.5.0 parameters at vota-testnet height 15003951.
// The database and scheduled plan below are synthetic; not a production snapshot.
func sourceFixture(t *testing.T, mutate func(map[string]storetypes.KVStore)) (dbm.DB, string) {
	t.Helper()
	db := dbm.NewMemDB()
	t.Cleanup(func() { require.NoError(t, db.Close()) })
	multi := rootmulti.NewStore(db, log.NewNopLogger())
	keys := map[string]*storetypes.KVStoreKey{}
	for _, name := range sourceStores {
		keys[name] = storetypes.NewKVStoreKey(name)
		multi.MountStoreWithDB(keys[name], storetypes.StoreTypeIAVL, nil)
	}
	require.NoError(t, multi.LoadLatestVersion())
	require.NoError(t, multi.SetInitialVersion(4))
	cache := multi.CacheMultiStore()
	stores := map[string]storetypes.KVStore{}
	for n, k := range keys {
		stores[n] = cache.GetKVStore(k)
	}
	raw, e := os.ReadFile("testdata/source-params.json")
	require.NoError(t, e)
	var params map[string]string
	require.NoError(t, json.Unmarshal(raw, &params))
	targets := map[string]struct {
		store string
		key   []byte
	}{
		"auth": {"acc", []byte{0}}, "bank": {"bank", []byte{5}}, "staking": {"staking", []byte{0x51}},
		"mint": {"mint", []byte{1}}, "distribution": {"distribution", []byte{9}}, "slashing": {"slashing", []byte{0}},
		"gov": {"gov", []byte{0x30}}, "wasm": {"wasm", []byte{0x10}}, "consensus": {"consensus", []byte("Consensus")},
		"ibc-client": {"ibc", []byte("clientParams")}, "ibc-connection": {"ibc", []byte("connectionParams")},
		"transfer": {"transfer", []byte("params")}, "icahost": {"icahost", []byte("params")}, "icacontroller": {"icacontroller", []byte("params")},
	}
	for name, at := range targets {
		b, e := base64.StdEncoding.DecodeString(params[name])
		require.NoError(t, e)
		stores[at.store].Set(at.key, b)
	}
	for k, v := range map[string]string{"ibc/AllowedClients": "[\"06-solomachine\",\"07-tendermint\",\"09-localhost\"]", "ibc/MaxExpectedTimePerBlock": "\"30000000000\"", "transfer/SendEnabled": "true", "transfer/ReceiveEnabled": "true", "icahost/HostEnabled": "true", "icahost/AllowMessages": "[\"*\"]", "icacontroller/ControllerEnabled": "true"} {
		stores["params"].Set([]byte(k), []byte(v))
	}
	for name, version := range SourceVersionMap() {
		b := make([]byte, 8)
		binary.BigEndian.PutUint64(b, version)
		stores["upgrade"].Set(append([]byte{2}, []byte(name)...), b)
	}
	for _, k := range []byte{1, 0x21, 0x31} {
		stores["group"].Set([]byte{k, 1}, make([]byte, 8))
	}
	plan := upgradetypes.Plan{Name: UpgradeName, Height: 5, Info: "fixture"}
	stores["upgrade"].Set(upgradetypes.PlanKey(), encode(t, &plan))
	if mutate != nil {
		mutate(stores)
	}
	cache.Write()
	multi.Commit()
	home := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(home, "data"), 0700))
	b, e := json.Marshal(plan)
	require.NoError(t, e)
	require.NoError(t, os.WriteFile(filepath.Join(home, "data", upgradetypes.UpgradeInfoFilename), b, 0600))
	return db, home
}

func snapshot(t *testing.T, db dbm.DB) map[string]string {
	t.Helper()
	it, e := db.Iterator(nil, nil)
	require.NoError(t, e)
	defer it.Close()
	out := map[string]string{}
	for ; it.Valid(); it.Next() {
		out[string(it.Key())] = string(it.Value())
	}
	require.NoError(t, it.Error())
	return out
}

func TestPreflightBeforeAnyStoreMutation(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(map[string]storetypes.KVStore)
		want   string
	}{
		{"audited source", nil, ""},
		{"unmigrated wasm", func(s map[string]storetypes.KVStore) { s["wasm"].Delete([]byte{0x10}) }, "missing migrated"},
		{"unknown legacy key", func(s map[string]storetypes.KVStore) { s["params"].Set([]byte("custom/fee"), []byte("1")) }, "unreviewed legacy"},
		{"different authoritative value", func(s map[string]storetypes.KVStore) {
			s["params"].Set([]byte("transfer/SendEnabled"), []byte("false"))
		}, "differs"},
		{"corrupt legacy value", func(s map[string]storetypes.KVStore) {
			s["params"].Set([]byte("transfer/SendEnabled"), []byte("broken"))
		}, "decode legacy"},
		{"group data", func(s map[string]storetypes.KVStore) { s["group"].Set([]byte{0, 0, 1}, []byte("member")) }, "group has business"},
		{"group used previously", func(s map[string]storetypes.KVStore) { s["group"].Set([]byte{1, 1}, []byte{0, 0, 0, 0, 0, 0, 0, 1}) }, "group has business"},
		{"group grant", func(s map[string]storetypes.KVStore) { s["authz"].Set([]byte{1}, []byte("/cosmos.group.v1.MsgExec")) }, "group reference"},
		{"wrong source version", func(s map[string]storetypes.KVStore) {
			s["upgrade"].Set(append([]byte{2}, []byte("wasm")...), []byte{0, 0, 0, 0, 0, 0, 0, 2})
		}, "unsupported source"},
		{"file alone cannot authorize", func(s map[string]storetypes.KVStore) { s["upgrade"].Delete(upgradetypes.PlanKey()) }, "missing migrated"},
		{"mismatched committed plan", func(s map[string]storetypes.KVStore) {
			s["upgrade"].Set(upgradetypes.PlanKey(), encode(t, &upgradetypes.Plan{Name: "other", Height: 5}))
		}, "does not match"},
		{"pending legacy proposal", func(s map[string]storetypes.KVStore) {
			p := govtypes.Proposal{Id: 9, Status: govtypes.StatusVotingPeriod, Messages: []*codectypes.Any{{TypeUrl: "/cosmos.gov.v1.MsgExecLegacyContent", Value: []byte("/cosmos.params.v1beta1.ParameterChangeProposal")}}}
			s["gov"].Set([]byte{0, 0, 0, 0, 0, 0, 0, 0, 9}, encode(t, &p))
		}, "unfinished proposal"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db, home := sourceFixture(t, tc.mutate)
			before := snapshot(t, db)
			err := ValidateBoundary(log.NewNopLogger(), db, home, nil)
			if tc.want == "" {
				require.NoError(t, err)
			} else {
				require.ErrorContains(t, err, tc.want)
			}
			require.Equal(t, before, snapshot(t, db), "preflight must not modify any database key")
		})
	}
}

func TestBoundaryRequiresExactUnskippedHalt(t *testing.T) {
	db, home := sourceFixture(t, nil)
	before := snapshot(t, db)
	require.ErrorContains(t, ValidateBoundary(log.NewNopLogger(), db, home, map[int64]bool{5: true}), "non-skipped")
	path := filepath.Join(home, "data", upgradetypes.UpgradeInfoFilename)
	require.NoError(t, os.WriteFile(path, []byte(`{"name":"sdk-055","height":7}`), 0600))
	require.ErrorContains(t, ValidateBoundary(log.NewNopLogger(), db, home, nil), "height+1")
	require.NoError(t, os.Remove(path))
	require.ErrorContains(t, ValidateBoundary(log.NewNopLogger(), db, home, nil), "upgrade info")
	require.Equal(t, before, snapshot(t, db))
}
