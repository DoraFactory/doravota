package wasmarchive

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"cosmossdk.io/log/v2"
	dbm "github.com/cosmos/cosmos-db"
	"github.com/cosmos/cosmos-sdk/store/v2/rootmulti"
	"github.com/cosmos/cosmos-sdk/store/v2/wrapper"
	"github.com/cosmos/cosmos-sdk/types/module"
	gov "github.com/cosmos/cosmos-sdk/x/gov/types/v1"
	upgrade "github.com/cosmos/cosmos-sdk/x/upgrade/types"
	"github.com/cosmos/gogoproto/proto"
	"github.com/cosmos/iavl"
	channel "github.com/cosmos/ibc-go/v11/modules/core/04-channel/types"
)

// UpgradeName is intentionally distinct from the already tested SDK upgrade.
// This candidate supports 1.0.0 -> retirement, never a direct 0.5.0 upgrade.
const UpgradeName = "wasm-retirement"

var retainedStores = []string{"acc", "authz", "bank", "consensus", "distribution", "evidence", "feegrant", "gov", "ibc", "icacontroller", "icahost", "mint", "slashing", "staking", "transfer", "upgrade", "wasm"}

func ValidateVersions(actual, expected module.VersionMap) error {
	for name, want := range expected {
		if got, ok := actual[name]; !ok || got != want {
			return fmt.Errorf("unsupported source module %s: got %d, present=%t, want %d", name, got, ok, want)
		}
	}
	optional := module.VersionMap{"capability": 1, "crisis": 2, "feeibc": 1}
	for name, version := range actual {
		if _, ok := expected[name]; ok {
			continue
		}
		if want, ok := optional[name]; !ok || want != version {
			return fmt.Errorf("unexpected source module %s/%d", name, version)
		}
	}
	return nil
}

// ValidateBoundary examines only committed state, before BaseApp can write.
// An upgrade-info file alone cannot authorize premature runtime removal.
func ValidateBoundary(logger log.Logger, db dbm.DB, home string, skips map[int64]bool) error {
	height := rootmulti.GetLatestVersion(db)
	if height == 0 {
		return nil
	}
	info, err := rootmulti.NewStore(db, logger).GetCommitInfo(height)
	if err != nil {
		return err
	}
	if info == nil || len(info.StoreInfos) != len(retainedStores) {
		return fmt.Errorf("unsupported committed store layout")
	}
	trees := map[string]*iavl.ImmutableTree{}
	for _, name := range retainedStores {
		found := false
		for _, s := range info.StoreInfos {
			if s.Name == name {
				found = true
				tree := iavl.NewMutableTree(wrapper.NewDBWrapper(dbm.NewPrefixDB(db, []byte("s/k:"+name+"/"))), 0, true, iavl.NewNopLogger(), iavl.AsyncPruningOption(false))
				defer tree.Close()
				immutable, e := tree.GetImmutable(s.CommitId.Version)
				if e != nil {
					return fmt.Errorf("read %s: %w", name, e)
				}
				if !bytes.Equal(immutable.Hash(), s.CommitId.Hash) {
					return fmt.Errorf("root mismatch for %s", name)
				}
				trees[name] = immutable
			}
		}
		if !found {
			return fmt.Errorf("required retained store %s missing", name)
		}
	}
	versions := module.VersionMap{}
	if err := scan(trees["upgrade"], []byte{2}, []byte{3}, func(k, v []byte) error {
		if len(k) < 2 || len(v) != 8 {
			return fmt.Errorf("invalid version entry")
		}
		versions[string(k[1:])] = binary.BigEndian.Uint64(v)
		return nil
	}); err != nil {
		return err
	}
	if versions[GenesisKey] == 1 {
		if _, present := versions[StoreKey]; present {
			return fmt.Errorf("conflicting live and archive versions")
		}
		return nil
	}
	expected := module.VersionMap{"06-solomachine": 0, "07-tendermint": 0, "auth": 7, "authz": 2, "bank": 4, "consensus": 1, "distribution": 3, "evidence": 1, "feegrant": 2, "genutil": 1, "gov": 5, "ibc": 8, "interchainaccounts": 3, "mint": 3, "slashing": 4, "staking": 6, "transfer": 6, "upgrade": 2, "vesting": 1, "wasm": 4}
	if err := ValidateVersions(versions, expected); err != nil {
		return err
	}
	raw, err := os.ReadFile(filepath.Join(home, "data", upgrade.UpgradeInfoFilename))
	if err != nil {
		return fmt.Errorf("coordinated %s upgrade required: %w", UpgradeName, err)
	}
	var plan upgrade.Plan
	if err = json.Unmarshal(raw, &plan); err != nil {
		return err
	}
	if plan.Name != UpgradeName || plan.Height != height+1 || skips[plan.Height] {
		return fmt.Errorf("require non-skipped %s at committed height+1", UpgradeName)
	}
	raw, err = trees["upgrade"].Get(upgrade.PlanKey())
	if err != nil {
		return err
	}
	var onchain upgrade.Plan
	if err = proto.Unmarshal(raw, &onchain); err != nil {
		return err
	}
	if onchain.Name != plan.Name || onchain.Height != plan.Height || onchain.Info != plan.Info {
		return fmt.Errorf("upgrade info differs from on-chain plan")
	}
	// Governance must finish outstanding business before runtime retirement. Raw
	// protobuf decoding does not require registering executable Wasm message types.
	if err = scan(trees["gov"], []byte{0}, []byte{1}, func(k, v []byte) error {
		var p gov.Proposal
		if e := proto.Unmarshal(v, &p); e != nil {
			return e
		}
		if p.Status == gov.StatusVotingPeriod || p.Status == gov.StatusDepositPeriod {
			if bytes.Contains(v, []byte("cosmwasm.wasm.")) {
				return fmt.Errorf("active Wasm governance proposal %d must settle before retirement", p.Id)
			}
		}
		return nil
	}); err != nil {
		return err
	}
	// Removing the Wasm route must not strand callbacks. General ICS20/ICA
	// channels remain wired and their storage is never migrated by this upgrade.
	return scan(trees["ibc"], []byte("channelEnds/ports/wasm."), []byte("channelEnds/ports/wasm/"), func(k, v []byte) error {
		var ch channel.Channel
		if e := proto.Unmarshal(v, &ch); e != nil {
			return e
		}
		if ch.State != channel.CLOSED {
			return fmt.Errorf("Wasm IBC channel must close before retirement: %s", k)
		}
		suffix := strings.TrimPrefix(string(k), "channelEnds/")
		prefix := []byte("commitments/" + suffix + "/sequences/")
		return scan(trees["ibc"], prefix, prefixEnd(prefix), func(k, v []byte) error { return fmt.Errorf("unsettled Wasm IBC packet %s", k) })
	})
}

func prefixEnd(p []byte) []byte {
	q := bytes.Clone(p)
	for i := len(q) - 1; i >= 0; i-- {
		q[i]++
		if q[i] != 0 {
			return q[:i+1]
		}
	}
	return nil
}
func scan(t *iavl.ImmutableTree, start, end []byte, f func([]byte, []byte) error) error {
	it, err := t.Iterator(start, end, true)
	if err != nil {
		return err
	}
	defer it.Close()
	for ; it.Valid(); it.Next() {
		if err = f(it.Key(), it.Value()); err != nil {
			return err
		}
	}
	return it.Error()
}
