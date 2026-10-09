package wasmarchive

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"strings"

	"cosmossdk.io/log/v2"
	dbm "github.com/cosmos/cosmos-db"
	"github.com/cosmos/cosmos-sdk/store/v2/rootmulti"
	storetypes "github.com/cosmos/cosmos-sdk/store/v2/types"
	"github.com/cosmos/cosmos-sdk/store/v2/wrapper"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/cosmos/cosmos-sdk/types/module"
	"github.com/cosmos/gogoproto/proto"
	"github.com/cosmos/iavl"
	channel "github.com/cosmos/ibc-go/v11/modules/core/04-channel/types"
)

// UpgradeName is the direct 0.5.0 -> 1.0.0 SDK and archive upgrade.
const UpgradeName = "1.0.0"

var retainedStores = []string{"acc", "authz", "bank", "consensus", "distribution", "evidence", "feegrant", "gov", "ibc", "icacontroller", "icahost", "mint", "slashing", "staking", "transfer", "upgrade", "wasm"}

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
	if info != nil {
		for _, entry := range info.StoreInfos {
			if entry.Name == "params" || entry.Name == "group" {
				// The caller must first validate the complete 0.5.0 boundary.
				return nil
			}
		}
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
	return fmt.Errorf("source is not archived 1.0.0 state; use the direct 0.5.0 upgrade boundary")
}

// ValidateContext repeats the startup checks at the actual upgrade boundary,
// including when a database was populated through state sync after construction.
func ValidateContext(ctx sdk.Context, keys map[string]*storetypes.KVStoreKey) error {
	return ValidateStoredChannels(func(name string, start, end []byte, f func([]byte, []byte) error) error {
		it := ctx.KVStore(keys[name]).Iterator(start, end)
		defer it.Close()
		for ; it.Valid(); it.Next() {
			if err := f(it.Key(), it.Value()); err != nil {
				return err
			}
		}
		// SDK cache iterators report invalid after normal exhaustion.
		return nil
	})
}

func ValidateStoredChannels(visit func(string, []byte, []byte, func([]byte, []byte) error) error) error {
	// Governance text and authz grants are user-controlled. They must never
	// become chain-wide activation vetoes. Legacy wire types remain decodable;
	// retired operations fail through the normal message router.
	// Removing the Wasm route must not strand callbacks. General ICS20/ICA
	// channels remain wired; the SDK upgrade separately migrates send sequences.
	return visit("ibc", []byte("channelEnds/ports/wasm."), []byte("channelEnds/ports/wasm/"), func(k, v []byte) error {
		var ch channel.Channel
		if e := proto.Unmarshal(v, &ch); e != nil {
			return e
		}
		if ch.State != channel.CLOSED {
			return fmt.Errorf("Wasm IBC channel must close before retirement: %s", k)
		}
		suffix := strings.TrimPrefix(string(k), "channelEnds/")
		prefix := []byte("commitments/" + suffix + "/sequences/")
		return visit("ibc", prefix, prefixEnd(prefix), func(k, v []byte) error { return fmt.Errorf("unsettled Wasm IBC packet %s", k) })
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
