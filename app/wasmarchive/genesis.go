package wasmarchive

import (
	"bytes"
	"encoding/json"
	"fmt"

	storetypes "github.com/cosmos/cosmos-sdk/store/v2/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
)

// GenesisEntry encodes arbitrary original key/value bytes as base64 in JSON.
// The explicit archive namespace never restores a live Wasm module.
type GenesisEntry struct {
	Key   []byte `json:"key"`
	Value []byte `json:"value"`
}
type Genesis struct {
	Entries []GenesisEntry `json:"entries"`
}

func InitGenesis(ctx sdk.Context, key *storetypes.KVStoreKey, raw json.RawMessage) error {
	if len(raw) == 0 {
		return nil
	}
	var g Genesis
	if err := json.Unmarshal(raw, &g); err != nil {
		return fmt.Errorf("wasm archive genesis: %w", err)
	}
	// Validate all entries first; duplicate/unsorted keys cannot silently overwrite.
	var previous []byte
	for _, e := range g.Entries {
		if len(e.Key) == 0 || e.Value == nil || (previous != nil && bytes.Compare(previous, e.Key) >= 0) {
			return fmt.Errorf("wasm archive genesis requires sorted unique non-empty keys and non-null values")
		}
		previous = e.Key
	}
	store := ctx.KVStore(key)
	for _, e := range g.Entries {
		store.Set(e.Key, e.Value)
	}
	return nil
}

func ExportGenesis(ctx sdk.Context, key *storetypes.KVStoreKey) (json.RawMessage, error) {
	g := Genesis{Entries: []GenesisEntry{}}
	it := ctx.KVStore(key).Iterator(nil, nil)
	defer it.Close()
	for ; it.Valid(); it.Next() {
		g.Entries = append(g.Entries, GenesisEntry{Key: bytes.Clone(it.Key()), Value: bytes.Clone(it.Value())})
	}
	return json.Marshal(g)
}
