// Package amino coordinates the v1.0.1 IBC Amino signing-rule change.
package amino

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"cosmossdk.io/log/v2"
	dbm "github.com/cosmos/cosmos-db"
	"github.com/cosmos/cosmos-sdk/store/v2/rootmulti"
	storetypes "github.com/cosmos/cosmos-sdk/store/v2/types"
	"github.com/cosmos/cosmos-sdk/store/v2/wrapper"
	sdk "github.com/cosmos/cosmos-sdk/types"
	upgradetypes "github.com/cosmos/cosmos-sdk/x/upgrade/types"
	"github.com/cosmos/gogoproto/proto"
	"github.com/cosmos/iavl"
)

const UpgradeName = "v1.0.1"

// Fresh chains start with the new rule. This application-namespaced metadata
// lives in the existing upgrade store and is NEVER written by the upgrade handler.
// Existing chains instead use the SDK's normal completed-upgrade record.
const genesisKey = "vota/amino-compat/genesis/v1.0.1"

func InitGenesis(ctx sdk.Context, key *storetypes.KVStoreKey) {
	ctx.KVStore(key).Set([]byte(genesisKey), []byte{1})
}

func IsActive(ctx sdk.Context, key *storetypes.KVStoreKey) (bool, error) {
	store := ctx.KVStore(key)
	if value := store.Get([]byte(genesisKey)); value != nil {
		if !bytes.Equal(value, []byte{1}) {
			return false, fmt.Errorf("invalid Amino genesis marker")
		}
		return true, nil
	}
	it := store.Iterator([]byte{upgradetypes.DoneByte}, []byte{upgradetypes.DoneByte + 1})
	defer it.Close()
	for ; it.Valid(); it.Next() {
		key := it.Key()
		if len(key) < 10 {
			return false, fmt.Errorf("invalid completed upgrade key")
		}
		if string(key[9:]) == UpgradeName {
			h := binary.BigEndian.Uint64(key[1:9])
			if h == 0 || h > uint64(ctx.BlockHeight()) {
				return false, fmt.Errorf("invalid %s completion height", UpgradeName)
			}
			return true, nil
		}
	}
	// The SDK cacheMergeIterator reports an error on normal exhaustion.
	// Match x/upgrade.GetDoneHeight: exhaustion means no completion record.
	return false, nil
}

// ValidateBoundary runs before BaseApp/StoreLoader construction. A local file
// cannot activate the rule: it must match a plan in the committed upgrade tree
// at exactly the last old-code block. No database keys are written here.
func ValidateBoundary(logger log.Logger, db dbm.DB, home string, skips map[int64]bool) error {
	height := rootmulti.GetLatestVersion(db)
	if height == 0 {
		return nil
	} // InitChain creates an explicit fresh-chain marker.
	info, err := rootmulti.NewStore(db, logger).GetCommitInfo(height)
	if err != nil {
		return err
	}
	if info == nil {
		return fmt.Errorf("missing committed state at %d", height)
	}
	for _, s := range info.StoreInfos {
		if s.Name != upgradetypes.StoreKey {
			continue
		}
		tree := iavl.NewMutableTree(wrapper.NewDBWrapper(dbm.NewPrefixDB(db, []byte("s/k:upgrade/"))), 0, true, iavl.NewNopLogger(), iavl.AsyncPruningOption(false))
		defer tree.Close()
		state, err := tree.GetImmutable(s.CommitId.Version)
		if err != nil {
			return err
		}
		if !bytes.Equal(state.Hash(), s.CommitId.Hash) {
			return fmt.Errorf("upgrade store root mismatch")
		}
		value, err := state.Get([]byte(genesisKey))
		if err != nil {
			return err
		}
		if value != nil {
			if !bytes.Equal(value, []byte{1}) {
				return fmt.Errorf("invalid Amino genesis marker")
			}
			return nil
		}
		it, err := state.Iterator([]byte{upgradetypes.DoneByte}, []byte{upgradetypes.DoneByte + 1}, true)
		if err != nil {
			return err
		}
		defer it.Close()
		for ; it.Valid(); it.Next() {
			key := it.Key()
			if len(key) < 10 {
				return fmt.Errorf("invalid completed upgrade key")
			}
			if string(key[9:]) == UpgradeName {
				h := binary.BigEndian.Uint64(key[1:9])
				if h == 0 || h > uint64(height) {
					return fmt.Errorf("invalid %s completion height", UpgradeName)
				}
				return nil
			}
		}
		if err := it.Error(); err != nil {
			return err
		}
		raw, err := state.Get(upgradetypes.PlanKey())
		if err != nil {
			return err
		}
		var plan upgradetypes.Plan
		if len(raw) == 0 {
			return fmt.Errorf("%s not activated: no committed upgrade plan; keep running v1.0.0", UpgradeName)
		}
		if err := proto.Unmarshal(raw, &plan); err != nil {
			return fmt.Errorf("decode committed upgrade plan: %w", err)
		}
		if plan.Name != UpgradeName || plan.Height <= 1 || height != plan.Height-1 || skips[plan.Height] {
			return fmt.Errorf("%s not activated: need non-skipped committed plan at height %d, got %s/%d; keep running the previous binary", UpgradeName, height+1, plan.Name, plan.Height)
		}
		local, err := os.ReadFile(filepath.Join(home, "data", upgradetypes.UpgradeInfoFilename))
		if err != nil {
			return fmt.Errorf("read halted upgrade info: %w", err)
		}
		var diskPlan upgradetypes.Plan
		if err := json.Unmarshal(local, &diskPlan); err != nil {
			return err
		}
		if diskPlan.Name != plan.Name || diskPlan.Height != plan.Height {
			return fmt.Errorf("local upgrade info does not match committed %s/%d", plan.Name, plan.Height)
		}
		return nil
	}
	return fmt.Errorf("missing committed upgrade store")
}
