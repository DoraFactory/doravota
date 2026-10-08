package wasmarchive

import (
	"bytes"
	"encoding/json"
	"io"
	"testing"

	"cosmossdk.io/log/v2"
	tmproto "github.com/cometbft/cometbft/proto/tendermint/types"
	dbm "github.com/cosmos/cosmos-db"
	"github.com/cosmos/cosmos-sdk/store/v2/rootmulti"
	"github.com/cosmos/cosmos-sdk/store/v2/snapshots"
	snapshottypes "github.com/cosmos/cosmos-sdk/store/v2/snapshots/types"
	storetypes "github.com/cosmos/cosmos-sdk/store/v2/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/stretchr/testify/require"
)

func fixture(t *testing.T) (*rootmulti.Store, *storetypes.KVStoreKey, sdk.Context) {
	t.Helper()
	db := dbm.NewMemDB()
	t.Cleanup(func() { db.Close() })
	m := rootmulti.NewStore(db, log.NewNopLogger())
	k := storetypes.NewKVStoreKey(StoreKey)
	m.MountStoreWithDB(k, storetypes.StoreTypeIAVL, nil)
	require.NoError(t, m.LoadLatestVersion())
	return m, k, sdk.NewContext(m, tmproto.Header{}, false, log.NewNopLogger())
}
func TestArchiveQueryGenesisHistorySnapshot(t *testing.T) {
	m, k, ctx := fixture(t)
	raw := json.RawMessage(`{"entries":[{"key":"AwAB","value":"djE="},{"key":"AwAC","value":""},{"key":"BA==","value":"AAH/"}]}`)
	require.NoError(t, InitGenesis(ctx, k, raw))
	m.Commit()
	// A pre-retirement modification proves height queries return old values,
	// rather than reading latest state while labeling it with an old height.
	ctx.KVStore(k).Set([]byte{3, 0, 1}, []byte("v2"))
	m.Commit()
	latest := ctx.WithBlockHeight(2)
	server := NewServer(k)
	got, err := server.Get(latest, &GetRequest{Key: []byte{3, 0, 1}})
	require.NoError(t, err)
	require.Equal(t, "v2", string(got.Value))
	old, err := m.CacheMultiStoreWithVersion(1)
	require.NoError(t, err)
	got, err = server.Get(ctx.WithMultiStore(old).WithBlockHeight(1), &GetRequest{Key: []byte{3, 0, 1}})
	require.NoError(t, err)
	require.Equal(t, "v1", string(got.Value))
	require.EqualValues(t, 1, got.Height)
	page, err := server.Scan(latest, &ScanRequest{Prefix: []byte{3}, Limit: 1})
	require.NoError(t, err)
	require.Len(t, page.Entries, 1)
	require.Equal(t, []byte{3, 0, 2}, page.NextKey)
	next, err := server.Scan(latest, &ScanRequest{Prefix: []byte{3}, StartKey: page.NextKey, Limit: 1})
	require.NoError(t, err)
	require.Len(t, next.Entries, 1)
	require.Empty(t, next.NextKey)
	missing, err := server.Get(latest, &GetRequest{Key: []byte{9}})
	require.NoError(t, err)
	require.False(t, missing.Found)
	empty, err := server.Get(latest, &GetRequest{Key: []byte{3, 0, 2}})
	require.NoError(t, err)
	require.True(t, empty.Found)
	exported, err := ExportGenesis(latest, k)
	require.NoError(t, err)
	_, otherKey, other := fixture(t)
	require.NoError(t, InitGenesis(other, otherKey, exported))
	roundtrip, err := ExportGenesis(other, otherKey)
	require.NoError(t, err)
	require.JSONEq(t, string(exported), string(roundtrip))
	// The ordinary SDK state snapshot carries the frozen store without Wasm's
	// former VM snapshot extension (this verifies KV state, not .wasm files).
	chunks := make(chan io.ReadCloser, 16)
	errs := make(chan error, 1)
	go func() {
		w := snapshots.NewStreamWriter(chunks)
		err := m.Snapshot(2, w)
		closeErr := w.Close()
		if err == nil {
			err = closeErr
		}
		errs <- err
	}()
	reader, err := snapshots.NewStreamReader(chunks)
	require.NoError(t, err)
	target, tk, tc := fixture(t)
	_, err = target.Restore(2, snapshottypes.CurrentFormat, reader)
	require.NoError(t, err)
	require.NoError(t, <-errs)
	require.Equal(t, m.LastCommitID(), target.LastCommitID())
	restored, err := ExportGenesis(tc, tk)
	require.NoError(t, err)
	require.JSONEq(t, string(exported), string(restored))
}
func TestArchiveBoundsAndReadOnly(t *testing.T) {
	m, k, ctx := fixture(t)
	ctx.KVStore(k).Set([]byte{3, 1}, []byte("value"))
	m.Commit()
	s := NewServer(k)
	before, err := ExportGenesis(ctx, k)
	require.NoError(t, err)
	for _, r := range []*ScanRequest{nil, {Limit: 1001}, {Prefix: []byte{3}, StartKey: []byte{4}}, {Prefix: bytes.Repeat([]byte{1}, maxKeyBytes+1)}} {
		_, err := s.Scan(ctx, r)
		require.Error(t, err)
	}
	_, err = s.Get(ctx, &GetRequest{})
	require.Error(t, err)
	for i := 0; i < 3; i++ {
		_, err = s.Scan(ctx, &ScanRequest{})
		require.NoError(t, err)
		m.Commit()
	}
	after, err := ExportGenesis(ctx, k)
	require.NoError(t, err)
	require.Equal(t, before, after)
	for _, raw := range []string{`{"entries":[{"key":"AQ==","value":null}]}`, `{"entries":[{"key":"AQ==","value":"AQ=="},{"key":"AQ==","value":"Ag=="}]}`} {
		require.Error(t, InitGenesis(ctx, k, json.RawMessage(raw)))
	}
	after, err = ExportGenesis(ctx, k)
	require.NoError(t, err)
	require.Equal(t, before, after)
}

func TestArchivedMetadata(t *testing.T) {
	m, err := DecodeMetadata([]byte{8, 156, 1, 18, 3, 'b', 'o', 'b', 26, 3, 's', 'u', 'e'}, "contract")
	require.NoError(t, err)
	require.Equal(t, "156", m["code_id"])
	require.Equal(t, "bob", m["creator"])
	require.Equal(t, "sue", m["admin"])
	_, err = DecodeMetadata([]byte{18, 255}, "contract")
	require.Error(t, err)
}
