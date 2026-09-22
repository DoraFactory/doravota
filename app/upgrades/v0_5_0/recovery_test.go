package v0_5_0

import (
	"encoding/binary"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"cosmossdk.io/log"
	"cosmossdk.io/store/metrics"
	"cosmossdk.io/store/rootmulti"
	storetypes "cosmossdk.io/store/types"
	upgradetypes "cosmossdk.io/x/upgrade/types"
	tmtypes "github.com/cometbft/cometbft/types"
	dbm "github.com/cosmos/cosmos-db"
	govv5 "github.com/cosmos/cosmos-sdk/x/gov/migrations/v5"
	govv1 "github.com/cosmos/cosmos-sdk/x/gov/types/v1"
	"github.com/stretchr/testify/require"

	"github.com/DoraFactory/doravota/app/legacyics29"
)

func TestEmergencyActivationBoundary(t *testing.T) {
	for _, name := range []string{"fee state at H-1", "empty uses original", "wrong plan", "too early", "missing plan", "different on-chain plan", "already 0.5.0", "recovery restart"} {
		t.Run(name, func(t *testing.T) {
			db := dbm.NewMemDB()
			t.Cleanup(func() { require.NoError(t, db.Close()) })
			multi := rootmulti.NewStore(db, log.NewNopLogger(), metrics.NewNoOpMetrics())
			names := []string{"bank", "gov", "upgrade"}
			switch name {
			case "already 0.5.0":
			case "recovery restart":
				names = append(names, legacyics29.StoreKey)
			default:
				names = append(names, "feeibc")
			}
			keys := map[string]*storetypes.KVStoreKey{}
			for _, n := range names {
				keys[n] = storetypes.NewKVStoreKey(n)
				multi.MountStoreWithDB(keys[n], storetypes.StoreTypeIAVL, nil)
			}
			require.NoError(t, multi.LoadLatestVersion())
			require.NoError(t, multi.SetInitialVersion(9))
			if key := keys["feeibc"]; key != nil && name != "empty uses original" {
				multi.GetKVStore(key).Set([]byte("feeEnabled/transfer/channel-0"), []byte{1})
			}
			upgradeStore := multi.GetKVStore(keys["upgrade"])
			onChainPlan := upgradetypes.Plan{Name: "0.5.0", Height: 10}
			if name == "different on-chain plan" {
				onChainPlan.Height = 11
			}
			planRaw, err := onChainPlan.Marshal()
			require.NoError(t, err)
			upgradeStore.Set([]byte{upgradetypes.PlanByte}, planRaw)
			for n, v := range SourceVersionMap() {
				raw := make([]byte, 8)
				binary.BigEndian.PutUint64(raw, v)
				upgradeStore.Set(append([]byte{2}, []byte(n)...), raw)
			}
			cp := tmtypes.DefaultConsensusParams().ToProto()
			raw, err := cp.Marshal()
			require.NoError(t, err)
			upgradeStore.Set([]byte("Consensus"), raw)
			gp := govv1.DefaultParams()
			period := 24 * time.Hour
			gp.VotingPeriod = &period
			raw, err = gp.Marshal()
			require.NoError(t, err)
			multi.GetKVStore(keys["gov"]).Set(govv5.ParamsKey, raw)
			multi.Commit()
			home := t.TempDir()
			if name != "missing plan" && name != "recovery restart" {
				plan := upgradetypes.Plan{Name: "0.5.0", Height: 10}
				if name == "wrong plan" {
					plan.Name = "0.5.1"
				}
				if name == "too early" {
					plan.Height = 11
				}
				raw, err = json.Marshal(plan)
				require.NoError(t, err)
				require.NoError(t, os.MkdirAll(filepath.Join(home, "data"), 0700))
				require.NoError(t, os.WriteFile(filepath.Join(home, "data", upgradetypes.UpgradeInfoFilename), raw, 0600))
			}
			before := dumpDB(t, db)
			err = ValidateRecoveryBoundary(log.NewNopLogger(), db, home)
			if name == "fee state at H-1" || name == "recovery restart" {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
			}
			require.Equal(t, before, dumpDB(t, db), "activation checks must not rewrite old committed state")
		})
	}
}
