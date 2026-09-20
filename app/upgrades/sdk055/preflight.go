// Package sdk055 implements the supported 0.5.0 -> SDK 0.55 state boundary.
package sdk055

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"

	"cosmossdk.io/log/v2"
	wasmtypes "github.com/CosmWasm/wasmd/x/wasm/types"
	bridge "github.com/DoraFactory/doravota/app/upgrades/v0_5_0"
	cmtproto "github.com/cometbft/cometbft/proto/tendermint/types"
	cmttypes "github.com/cometbft/cometbft/types"
	dbm "github.com/cosmos/cosmos-db"
	"github.com/cosmos/cosmos-sdk/store/v2/rootmulti"
	storetypes "github.com/cosmos/cosmos-sdk/store/v2/types"
	"github.com/cosmos/cosmos-sdk/store/v2/wrapper"
	"github.com/cosmos/cosmos-sdk/types/module"
	authtypes "github.com/cosmos/cosmos-sdk/x/auth/types"
	banktypes "github.com/cosmos/cosmos-sdk/x/bank/types"
	distrtypes "github.com/cosmos/cosmos-sdk/x/distribution/types"
	govtypes "github.com/cosmos/cosmos-sdk/x/gov/types/v1"
	minttypes "github.com/cosmos/cosmos-sdk/x/mint/types"
	slashingtypes "github.com/cosmos/cosmos-sdk/x/slashing/types"
	stakingtypes "github.com/cosmos/cosmos-sdk/x/staking/types"
	upgradetypes "github.com/cosmos/cosmos-sdk/x/upgrade/types"
	"github.com/cosmos/gogoproto/proto"
	"github.com/cosmos/iavl"
	controllertypes "github.com/cosmos/ibc-go/v11/modules/apps/27-interchain-accounts/controller/types"
	hosttypes "github.com/cosmos/ibc-go/v11/modules/apps/27-interchain-accounts/host/types"
	transfertypes "github.com/cosmos/ibc-go/v11/modules/apps/transfer/types"
	clienttypes "github.com/cosmos/ibc-go/v11/modules/core/02-client/types"
	connectiontypes "github.com/cosmos/ibc-go/v11/modules/core/03-connection/types"
)

// UpgradeName is a coordinated migration identifier, not a release version.
const UpgradeName = "sdk-055"

func StoreUpgrades() storetypes.StoreUpgrades {
	return storetypes.StoreUpgrades{Deleted: []string{"params", "group"}}
}

func SourceVersionMap() module.VersionMap {
	return module.VersionMap{"06-solomachine": 0, "07-tendermint": 0, "auth": 5, "authz": 2, "bank": 4,
		"consensus": 1, "distribution": 3, "evidence": 1, "feegrant": 2, "genutil": 1, "gov": 5,
		"group": 2, "ibc": 8, "interchainaccounts": 3, "mint": 2, "params": 1, "slashing": 4,
		"staking": 5, "transfer": 6, "upgrade": 2, "vesting": 1, "wasm": 4}
}

func ValidateSourceVersionMap(actual module.VersionMap) error {
	expected := SourceVersionMap()
	for name, version := range expected {
		if got, ok := actual[name]; !ok || got != version {
			return fmt.Errorf("unsupported source module %s: got %d (present=%t), want %d", name, got, ok, version)
		}
	}
	// Only these known retired entries may survive the 0.47 -> 0.53 bridge.
	optional := module.VersionMap{"capability": 1, "feeibc": 1, "crisis": 2}
	for name, version := range actual {
		if _, ok := expected[name]; ok {
			continue
		}
		if want, ok := optional[name]; !ok || version != want {
			return fmt.Errorf("unsupported source module %s version %d", name, version)
		}
	}
	return nil
}

var sourceStores = []string{"acc", "authz", "bank", "consensus", "distribution", "evidence", "feegrant", "gov", "group", "ibc", "icacontroller", "icahost", "mint", "params", "slashing", "staking", "transfer", "upgrade", "wasm"}

// ValidateBoundary reads committed roots before BaseApp or its StoreLoader can
// delete stores. A file alone never authorizes migration: it must match the
// committed on-chain plan, the halt height and the exact source state schema.
func ValidateBoundary(logger log.Logger, db dbm.DB, home string, skips map[int64]bool) error {
	height := rootmulti.GetLatestVersion(db)
	if height == 0 {
		return nil
	}
	info, err := rootmulti.NewStore(db, logger).GetCommitInfo(height)
	if err != nil {
		return err
	}
	if info == nil {
		return fmt.Errorf("missing commit metadata at height %d", height)
	}
	commits := map[string]storetypes.CommitID{}
	for _, s := range info.StoreInfos {
		commits[s.Name] = s.CommitId
	}
	_, hasParams := commits["params"]
	_, hasGroup := commits["group"]
	if !hasParams && !hasGroup {
		return nil
	} // new genesis or already committed upgrade
	raw, err := os.ReadFile(filepath.Join(home, "data", upgradetypes.UpgradeInfoFilename))
	if err != nil {
		return fmt.Errorf("legacy state requires coordinated %s upgrade info: %w", UpgradeName, err)
	}
	var plan upgradetypes.Plan
	if err = json.Unmarshal(raw, &plan); err != nil {
		return fmt.Errorf("decode upgrade info: %w", err)
	}
	if plan.Name != UpgradeName || plan.Height <= 1 || height != plan.Height-1 || skips[plan.Height] {
		return fmt.Errorf("legacy state requires non-skipped %s plan at committed height+1 (height=%d plan=%s/%d)", UpgradeName, height, plan.Name, plan.Height)
	}
	if len(commits) != len(sourceStores) {
		return fmt.Errorf("unexpected source store count: %d", len(commits))
	}
	// Retain the bridge's read-only handling of historical empty IAVL roots.
	readDB, _, err := bridge.WrapLegacyEmptyIAVLDB(logger, db, home)
	if err != nil {
		return err
	}
	trees := map[string]*iavl.ImmutableTree{}
	for _, name := range sourceStores {
		commit, ok := commits[name]
		if !ok {
			return fmt.Errorf("required source store %s is missing", name)
		}
		prefix := dbm.NewPrefixDB(readDB, []byte("s/k:"+name+"/"))
		tree := iavl.NewMutableTree(wrapper.NewDBWrapper(prefix), 0, true, iavl.NewNopLogger(), iavl.AsyncPruningOption(false))
		defer tree.Close()
		immutable, err := tree.GetImmutable(commit.Version)
		if err != nil {
			return fmt.Errorf("read %s root: %w", name, err)
		}
		if !bytes.Equal(immutable.Hash(), commit.Hash) {
			return fmt.Errorf("source %s root hash mismatch", name)
		}
		trees[name] = immutable
	}
	return validateState(trees, plan)
}

func scan(tree *iavl.ImmutableTree, start, end []byte, visit func([]byte, []byte) error) error {
	it, err := tree.Iterator(start, end, true)
	if err != nil {
		return err
	}
	defer it.Close()
	for ; it.Valid(); it.Next() {
		if err := visit(it.Key(), it.Value()); err != nil {
			return err
		}
	}
	return it.Error()
}

func validateState(trees map[string]*iavl.ImmutableTree, plan upgradetypes.Plan) error {
	read := func(store string, key []byte, msg proto.Message) error {
		raw, err := trees[store].Get(key)
		if err != nil {
			return err
		}
		if len(raw) == 0 {
			return fmt.Errorf("missing migrated parameter/state %s/%x", store, key)
		}
		if err := proto.Unmarshal(raw, msg); err != nil {
			return fmt.Errorf("decode %s/%x: %w", store, key, err)
		}
		return nil
	}
	var storedPlan upgradetypes.Plan
	if err := read("upgrade", upgradetypes.PlanKey(), &storedPlan); err != nil {
		return err
	}
	if storedPlan.Name != plan.Name || storedPlan.Height != plan.Height || storedPlan.Info != plan.Info {
		return fmt.Errorf("upgrade info does not match committed on-chain plan")
	}
	versions := module.VersionMap{}
	if err := scan(trees["upgrade"], []byte{2}, []byte{3}, func(k, v []byte) error {
		if len(k) < 2 || len(v) != 8 {
			return fmt.Errorf("malformed source module version")
		}
		versions[string(k[1:])] = binary.BigEndian.Uint64(v)
		return nil
	}); err != nil {
		return err
	}
	if err := ValidateSourceVersionMap(versions); err != nil {
		return err
	}
	if err := scan(trees["group"], nil, nil, func(k, v []byte) error {
		if (bytes.Equal(k, []byte{1, 1}) || bytes.Equal(k, []byte{0x21, 1}) || bytes.Equal(k, []byte{0x31, 1})) && len(v) == 8 && binary.BigEndian.Uint64(v) == 0 {
			return nil
		}
		return fmt.Errorf("group has business/history state at key %x; explicit disposition required before removal", k)
	}); err != nil {
		return err
	}

	var auth authtypes.Params
	var bank banktypes.Params
	var staking stakingtypes.Params
	var mint minttypes.Params
	var distribution distrtypes.Params
	var slashing slashingtypes.Params
	var gov govtypes.Params
	var wasm wasmtypes.Params
	var consensus cmtproto.ConsensusParams
	var client clienttypes.Params
	var connection connectiontypes.Params
	var transfer transfertypes.Params
	var host hosttypes.Params
	var controller controllertypes.Params
	for _, x := range []struct {
		store string
		key   []byte
		msg   proto.Message
	}{
		{"acc", []byte{0}, &auth}, {"bank", []byte{5}, &bank}, {"staking", []byte{0x51}, &staking},
		{"mint", []byte{1}, &mint}, {"distribution", []byte{9}, &distribution}, {"slashing", []byte{0}, &slashing},
		{"gov", []byte{0x30}, &gov}, {"wasm", []byte{0x10}, &wasm}, {"consensus", []byte("Consensus"), &consensus},
		{"ibc", []byte("clientParams"), &client}, {"ibc", []byte("connectionParams"), &connection},
		{"transfer", []byte("params"), &transfer}, {"icahost", []byte("params"), &host}, {"icacontroller", []byte("params"), &controller},
	} {
		if err := read(x.store, x.key, x.msg); err != nil {
			return err
		}
	}
	// These are the only legacy keys left by the audited 0.5.0 bridge. Unknown
	// keys are rejected rather than silently dropped. Compare against current
	// authoritative module values; never overwrite them with legacy/default data.
	expected := map[string]any{
		"ibc/AllowedClients": client.AllowedClients, "ibc/MaxExpectedTimePerBlock": fmt.Sprint(connection.MaxExpectedTimePerBlock),
		"transfer/SendEnabled": transfer.SendEnabled, "transfer/ReceiveEnabled": transfer.ReceiveEnabled,
		"icahost/HostEnabled": host.HostEnabled, "icahost/AllowMessages": host.AllowMessages,
		"icacontroller/ControllerEnabled": controller.ControllerEnabled,
	}
	if err := scan(trees["params"], nil, nil, func(k, v []byte) error {
		want, ok := expected[string(k)]
		if !ok {
			return fmt.Errorf("unreviewed legacy parameter %q", k)
		}
		var actual, normalized any
		if err := json.Unmarshal(v, &actual); err != nil {
			return fmt.Errorf("decode legacy parameter %q: %w", k, err)
		}
		raw, err := json.Marshal(want)
		if err != nil {
			return err
		}
		if err = json.Unmarshal(raw, &normalized); err != nil {
			return err
		}
		if !reflect.DeepEqual(actual, normalized) {
			return fmt.Errorf("legacy parameter %q differs from authoritative module value", k)
		}
		return nil
	}); err != nil {
		return err
	}
	if err := wasm.ValidateBasic(); err != nil {
		return fmt.Errorf("wasm parameters: %w", err)
	}
	if err := bridge.ValidateLegacyConsensusParams(consensus); err != nil {
		return err
	}
	// Check capacity before CometBFT's helpers can panic at the first new block.
	validators := int(staking.MaxValidators)
	n := 0
	if err := scan(trees["staking"], []byte{0x11}, []byte{0x12}, func(_, _ []byte) error { n++; return nil }); err != nil {
		return err
	}
	if n > validators {
		validators = n
	}
	capacity := consensus.Block.MaxBytes - cmttypes.MaxOverheadForBlock - cmttypes.MaxHeaderBytes - cmttypes.MaxCommitBytes(validators) - consensus.Evidence.MaxBytes
	if capacity <= 0 {
		return fmt.Errorf("insufficient CometBFT 0.40 block capacity: %d bytes for transactions", capacity)
	}
	// Reject unfinished proposals that would lose their executable route. Closed
	// historical proposals remain decodable via the retained message codecs.
	if err := scan(trees["gov"], []byte{0}, []byte{1}, func(_, v []byte) error {
		var proposal govtypes.Proposal
		if err := proto.Unmarshal(v, &proposal); err != nil {
			return fmt.Errorf("decode proposal: %w", err)
		}
		if proposal.Status != govtypes.StatusDepositPeriod && proposal.Status != govtypes.StatusVotingPeriod {
			return nil
		}
		for _, msg := range proposal.Messages {
			raw, err := proto.Marshal(msg)
			if err != nil {
				return err
			}
			if bytes.Contains(raw, []byte("/cosmos.params.v1beta1.ParameterChangeProposal")) || bytes.Contains(raw, []byte("/cosmos.group.v1.")) {
				return fmt.Errorf("unfinished proposal %d uses removed params/group messages", proposal.Id)
			}
		}
		return nil
	}); err != nil {
		return err
	}
	// A policy account or grant importing group types is not covered by an empty
	// group table. Refuse these references instead of making them unusable.
	for _, name := range []string{"acc", "authz"} {
		if err := scan(trees[name], nil, nil, func(k, v []byte) error {
			if bytes.Contains(v, []byte("/cosmos.group.v1.")) {
				return fmt.Errorf("group reference in %s/%x requires disposition", name, k)
			}
			return nil
		}); err != nil {
			return err
		}
	}
	return nil
}
