package amino

import (
	"encoding/binary"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"cosmossdk.io/log/v2"
	dbm "github.com/cosmos/cosmos-db"
	"github.com/cosmos/cosmos-sdk/store/v2/rootmulti"
	storetypes "github.com/cosmos/cosmos-sdk/store/v2/types"
	upgradetypes "github.com/cosmos/cosmos-sdk/x/upgrade/types"
	"github.com/cosmos/gogoproto/proto"
	"github.com/stretchr/testify/require"
)

func TestCommittedBoundary(t *testing.T) {
	for _, tc := range []struct {
		name                           string
		height, planHeight, doneHeight int64
		planName                       string
		disk, skip, fresh, corrupt     bool
		wantErr                        string
	}{
		{"early", 18, 20, 0, UpgradeName, true, false, false, false, "not activated"},
		{"boundary", 19, 20, 0, UpgradeName, true, false, false, false, ""},
		{"no local halt file", 19, 20, 0, UpgradeName, false, false, false, false, "upgrade info"},
		{"skip prohibited", 19, 20, 0, UpgradeName, true, true, false, false, "non-skipped"},
		{"wrong plan", 19, 20, 0, "v1.0.2", true, false, false, false, "not activated"},
		{"missed boundary", 20, 20, 0, UpgradeName, true, false, false, false, "not activated"},
		{"local file alone", 19, 0, 0, "", true, false, false, false, "no committed"},
		{"completed restart", 22, 0, 20, "", false, false, false, false, ""},
		{"invalid future completion", 19, 0, 20, "", false, false, false, false, "completion height"},
		{"new chain restart", 22, 0, 0, "", false, false, true, false, ""},
		{"invalid marker", 22, 0, 0, "", false, false, true, true, "genesis marker"},
		{"mismatched local height", 19, 20, 0, UpgradeName, true, false, false, true, "does not match"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db := dbm.NewMemDB()
			defer db.Close()
			key := storetypes.NewKVStoreKey("upgrade")
			multi := rootmulti.NewStore(db, log.NewNopLogger())
			multi.MountStoreWithDB(key, storetypes.StoreTypeIAVL, nil)
			require.NoError(t, multi.LoadLatestVersion())
			require.NoError(t, multi.SetInitialVersion(tc.height))
			cache := multi.CacheMultiStore()
			store := cache.GetKVStore(key)
			store.Set([]byte("fixture"), []byte("unchanged"))
			if tc.planHeight > 0 {
				raw, err := proto.Marshal(&upgradetypes.Plan{Name: tc.planName, Height: tc.planHeight})
				require.NoError(t, err)
				store.Set(upgradetypes.PlanKey(), raw)
			}
			if tc.doneHeight > 0 {
				k := make([]byte, 9+len(UpgradeName))
				k[0] = upgradetypes.DoneByte
				binary.BigEndian.PutUint64(k[1:9], uint64(tc.doneHeight))
				copy(k[9:], UpgradeName)
				store.Set(k, []byte{1})
			}
			if tc.fresh {
				v := byte(1)
				if tc.corrupt {
					v = 2
				}
				store.Set([]byte(genesisKey), []byte{v})
			}
			cache.Write()
			multi.Commit()
			home := t.TempDir()
			require.NoError(t, os.MkdirAll(filepath.Join(home, "data"), 0700))
			if tc.disk {
				h := int64(20)
				if tc.corrupt {
					h++
				}
				raw, err := json.Marshal(upgradetypes.Plan{Name: UpgradeName, Height: h})
				require.NoError(t, err)
				require.NoError(t, os.WriteFile(filepath.Join(home, "data", "upgrade-info.json"), raw, 0600))
			}
			capture := func() map[string]string {
				it, err := db.Iterator(nil, nil)
				require.NoError(t, err)
				defer it.Close()
				r := map[string]string{}
				for ; it.Valid(); it.Next() {
					r[string(it.Key())] = string(it.Value())
				}
				return r
			}
			before := capture()
			err := ValidateBoundary(log.NewNopLogger(), db, home, map[int64]bool{20: tc.skip})
			if tc.wantErr == "" {
				require.NoError(t, err)
			} else {
				require.ErrorContains(t, err, tc.wantErr)
			}
			require.Equal(t, before, capture(), "preflight must not write any DB keys")
		})
	}
}
