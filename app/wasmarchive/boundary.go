package wasmarchive

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"strings"

	"cosmossdk.io/log/v2"
	dbm "github.com/cosmos/cosmos-db"
	"github.com/cosmos/cosmos-sdk/store/v2/rootmulti"
	"github.com/cosmos/cosmos-sdk/store/v2/wrapper"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/cosmos/cosmos-sdk/types/module"
	"github.com/cosmos/iavl"
	channelkeeper "github.com/cosmos/ibc-go/v11/modules/core/04-channel/keeper"
	channel "github.com/cosmos/ibc-go/v11/modules/core/04-channel/types"
)

// UpgradeName is the direct 0.5.0 -> v1.0.0 SDK and archive upgrade.
const UpgradeName = "v1.0.0"

var retainedStores = []string{"acc", "authz", "bank", "consensus", "distribution", "evidence", "feegrant", "gov", "ibc", "icacontroller", "icahost", "mint", "slashing", "staking", "transfer", "upgrade", "wasm"}

// ValidateBoundary examines only committed state, before BaseApp can write.
// An upgrade-info file alone cannot authorize premature runtime removal.
func ValidateBoundary(logger log.Logger, db dbm.DB, home string, skips map[int64]bool) error {
	return ValidateBoundaryWithModules(logger, db, home, skips, nil)
}

// ValidateBoundaryWithModules permits only explicitly known post-retirement
// stores, with their committed module versions and roots verified together.
func ValidateBoundaryWithModules(logger log.Logger, db dbm.DB, home string, skips map[int64]bool, additions map[string]uint64) error {
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
	if info == nil {
		return fmt.Errorf("missing committed store layout")
	}
	stores := append([]string(nil), retainedStores...)
	presentAdditions := map[string]bool{}
	for _, entry := range info.StoreInfos {
		if _, known := additions[entry.Name]; known {
			stores = append(stores, entry.Name)
			presentAdditions[entry.Name] = true
		}
	}
	if len(info.StoreInfos) != len(stores) {
		return fmt.Errorf("unsupported committed store layout")
	}
	trees := map[string]*iavl.ImmutableTree{}
	for _, name := range stores {
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
	for name, expected := range additions {
		version, registered := versions[name]
		if presentAdditions[name] != registered || (registered && version != expected) {
			return fmt.Errorf("inconsistent committed module/store version for %s", name)
		}
	}
	if versions[GenesisKey] == 1 {
		if _, present := versions[StoreKey]; present {
			return fmt.Errorf("conflicting live and archive versions")
		}
		return nil
	}
	return fmt.Errorf("source is not archived v1.0.0 state; use the direct 0.5.0 upgrade boundary")
}

// RetireChannels closes local Wasm channels without invoking removed contracts.
// Packet records are retained as evidence; this performs no settlement or refund.
// Collect first so writes cannot invalidate the channel iterator.
func RetireChannels(ctx sdk.Context, keeper *channelkeeper.Keeper) {
	var retired []channel.IdentifiedChannel
	keeper.IterateChannels(ctx, func(ch channel.IdentifiedChannel) bool {
		if strings.HasPrefix(ch.PortId, "wasm.") && ch.State != channel.CLOSED {
			retired = append(retired, ch)
		}
		return false
	})
	for _, ch := range retired {
		oldState := ch.State.String()
		keeper.SetChannel(ctx, ch.PortId, ch.ChannelId, channel.Channel{
			State: channel.CLOSED, Ordering: ch.Ordering, Counterparty: ch.Counterparty,
			ConnectionHops: ch.ConnectionHops, Version: ch.Version,
		})
		ctx.EventManager().EmitEvent(sdk.NewEvent("wasm_channel_retired",
			sdk.NewAttribute("port_id", ch.PortId), sdk.NewAttribute("channel_id", ch.ChannelId),
			sdk.NewAttribute("previous_state", oldState)))
	}
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
