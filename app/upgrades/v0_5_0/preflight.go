package v0_5_0

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"cosmossdk.io/log"
	"cosmossdk.io/store/metrics"
	"cosmossdk.io/store/rootmulti"
	storetypes "cosmossdk.io/store/types"
	"cosmossdk.io/store/wrapper"
	upgradetypes "cosmossdk.io/x/upgrade/types"
	tmproto "github.com/cometbft/cometbft/proto/tendermint/types"
	tmtypes "github.com/cometbft/cometbft/types"
	dbm "github.com/cosmos/cosmos-db"
	"github.com/cosmos/cosmos-sdk/types/module"
	authtypes "github.com/cosmos/cosmos-sdk/x/auth/types"
	govv5 "github.com/cosmos/cosmos-sdk/x/gov/migrations/v5"
	govv1 "github.com/cosmos/cosmos-sdk/x/gov/types/v1"
	"github.com/cosmos/iavl"
)

// SourceVersionMap is the 0.4.4 module schema, not its application version.
// Return a new map so callers cannot mutate the accepted schema globally.
func SourceVersionMap() module.VersionMap {
	return module.VersionMap{"auth": 4, "authz": 2, "bank": 4, "capability": 1, "consensus": 1,
		"distribution": 3, "evidence": 1, "feegrant": 2, "feeibc": 1, "genutil": 1, "gov": 4,
		"group": 2, "ibc": 4, "interchainaccounts": 2, "mint": 2, "params": 1, "slashing": 3,
		"staking": 4, "transfer": 3, "upgrade": 2, "vesting": 1, "wasm": 4}
}

func ValidateSourceVersionMap(actual module.VersionMap) error {
	expected := SourceVersionMap()
	// Old mainnet retains the removed crisis module's version entry. A fresh
	// 0.4.4 genesis does not have it. Only this known historical entry is allowed.
	expected["crisis"] = 2
	names := make([]string, 0, len(expected))
	for name := range expected {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		version, ok := actual[name]
		if name == "crisis" && !ok {
			continue
		}
		if !ok || version != expected[name] {
			return fmt.Errorf("unsupported source module %s: got %d (present=%t), expected %d", name, version, ok, expected[name])
		}
	}
	extras := make([]string, 0)
	for name := range actual {
		if _, ok := expected[name]; !ok {
			extras = append(extras, name)
		}
	}
	sort.Strings(extras)
	if len(extras) > 0 {
		return fmt.Errorf("unsupported source modules: %v", extras)
	}
	return nil
}

func ValidateLegacyConsensusParams(params tmproto.ConsensusParams) error {
	if params.Block == nil || params.Evidence == nil || params.Validator == nil {
		return fmt.Errorf("source consensus parameters are incomplete")
	}
	// Older protobuf records may omit the zero-valued version message.
	if params.Version == nil {
		params.Version = &tmproto.VersionParams{}
	}
	return tmtypes.ConsensusParamsFromProto(params).ValidateBasic()
}

// ValidateUpgradeBoundary runs before BaseApp loads/deletes any stores. It reads
// immutable IAVL roots from the last committed state; it never migrates a tree.
func ValidateUpgradeBoundary(logger log.Logger, db dbm.DB, home string) error {
	raw, err := os.ReadFile(filepath.Join(home, "data", upgradetypes.UpgradeInfoFilename))
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	var plan upgradetypes.Plan
	if err = json.Unmarshal(raw, &plan); err != nil {
		return err
	}
	if plan.Name != UpgradeName {
		return nil
	}
	height := rootmulti.GetLatestVersion(db)
	if height == 0 || height != plan.Height-1 {
		return nil
	}
	return validateSourceStores(logger, db, height)
}

func validateSourceStores(logger log.Logger, db dbm.DB, height int64) error {
	return validateSourceStoresForPlan(logger, db, height, false)
}

func validateSourceStoresForPlan(logger log.Logger, db dbm.DB, height int64, refundFees bool) error {
	multi := rootmulti.NewStore(db, logger, metrics.NewNoOpMetrics())
	info, err := multi.GetCommitInfo(height)
	if err != nil {
		return err
	}
	commits := map[string]storetypes.CommitID{}
	for _, entry := range info.StoreInfos {
		commits[entry.Name] = entry.CommitId
	}
	read := func(name string, check func(*iavl.ImmutableTree) error) error {
		commit, ok := commits[name]
		if !ok {
			return fmt.Errorf("required legacy store %s is missing", name)
		}
		prefix := dbm.NewPrefixDB(&emptyIAVLRootAwareDB{DB: db}, []byte(iavlStorePrefix+name+"/"))
		tree := iavl.NewMutableTree(wrapper.NewDBWrapper(prefix), 0, true, iavl.NewNopLogger(), iavl.AsyncPruningOption(false))
		defer tree.Close()
		immutable, err := tree.GetImmutable(commit.Version)
		if err != nil {
			return fmt.Errorf("read %s: %w", name, err)
		}
		if !bytes.Equal(immutable.Hash(), commit.Hash) {
			return fmt.Errorf("legacy %s root does not match committed hash", name)
		}
		return check(immutable)
	}
	feeState, feeBalance := false, false
	if err = read("feeibc", func(tree *iavl.ImmutableTree) error {
		feeState = tree.Size() != 0
		if !refundFees && tree.Size() != 0 {
			return fmt.Errorf("feeibc is not empty: refusing to delete legacy fee state")
		}
		return nil
	}); err != nil {
		return err
	}
	if err = read("bank", func(tree *iavl.ImmutableTree) error {
		// SDK 0.47 balance key: 0x02 || length-prefixed account || denomination.
		addr := authtypes.NewModuleAddress("feeibc")
		prefix := append([]byte{2, byte(len(addr))}, addr...)
		it, err := tree.Iterator(prefix, storetypes.PrefixEndBytes(prefix), true)
		if err != nil {
			return err
		}
		defer it.Close()
		feeBalance = it.Valid()
		if !refundFees && feeBalance {
			return fmt.Errorf("feeibc module has a balance entry: refusing fee store deletion")
		}
		return it.Error()
	}); err != nil {
		return err
	}
	if refundFees && !feeState && !feeBalance {
		return fmt.Errorf("no fee state or balance to recover; use the original 0.5.0 binary")
	}
	// Check the approved expedited policy against the real legacy governance
	// values before StoreLoader deletes anything. The new expedited policy values
	// participate in cross-field validation; never shorten the old voting period
	// or lower the old threshold/deposit just to make the new values fit.
	if err = read("gov", func(tree *iavl.ImmutableTree) error {
		raw, err := tree.Get(govv5.ParamsKey)
		if err != nil {
			return err
		}
		if len(raw) == 0 {
			return fmt.Errorf("legacy governance parameters are missing")
		}
		var params govv1.Params
		if err := params.Unmarshal(raw); err != nil {
			return fmt.Errorf("decode legacy governance parameters: %w", err)
		}
		defaults := govv1.DefaultParams()
		params.ExpeditedThreshold = defaults.ExpeditedThreshold
		_, err = ApprovedGovernanceParams(params)
		return err
	}); err != nil {
		return err
	}
	return read("upgrade", func(tree *iavl.ImmutableTree) error {
		if refundFees {
			raw, err := tree.Get([]byte{upgradetypes.PlanByte})
			if err != nil {
				return err
			}
			if len(raw) == 0 {
				return fmt.Errorf("on-chain recovery upgrade plan is missing")
			}
			var plan upgradetypes.Plan
			if err := plan.Unmarshal(raw); err != nil {
				return err
			}
			if plan.Name != UpgradeName || plan.Height != height+1 {
				return fmt.Errorf("on-chain plan does not match the 0.5.0 recovery boundary")
			}
		}
		it, err := tree.Iterator([]byte{2}, []byte{3}, true)
		if err != nil {
			return err
		}
		versions := module.VersionMap{}
		for ; it.Valid(); it.Next() {
			if len(it.Value()) != 8 {
				it.Close()
				return fmt.Errorf("malformed module version")
			}
			versions[string(it.Key()[1:])] = binary.BigEndian.Uint64(it.Value())
		}
		err = it.Error()
		it.Close()
		if err != nil {
			return err
		}
		if err = ValidateSourceVersionMap(versions); err != nil {
			return err
		}
		raw, err := tree.Get([]byte("Consensus"))
		if err != nil {
			return err
		}
		if len(raw) == 0 {
			return fmt.Errorf("legacy upgrade/Consensus record is missing")
		}
		var params tmproto.ConsensusParams
		if err = params.Unmarshal(raw); err != nil {
			return err
		}
		return ValidateLegacyConsensusParams(params)
	})
}
