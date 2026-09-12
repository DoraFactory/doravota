// store-compare streams committed key/value differences without exporting whole modules.
package main

import (
	"bytes"
	"compress/gzip"
	"cosmossdk.io/log"
	"cosmossdk.io/store/metrics"
	"cosmossdk.io/store/rootmulti"
	st "cosmossdk.io/store/types"
	"cosmossdk.io/store/wrapper"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	bridge "github.com/DoraFactory/doravota/app/upgrades/sdk_v053_bridge"
	dbm "github.com/cosmos/cosmos-db"
	"github.com/cosmos/iavl"
	"os"
	"path/filepath"
	"strconv"
)

func must(e error) {
	if e != nil {
		panic(e)
	}
}
func open(home string, h int64) (dbm.DB, map[string]st.CommitID) {
	if _, e := os.Stat(filepath.Join(home, "data/application.db")); e != nil {
		panic(e)
	}
	db, e := dbm.NewDB("application", dbm.GoLevelDBBackend, filepath.Join(home, "data"))
	must(e)
	view, _, e := bridge.WrapLegacyEmptyIAVLDB(log.NewNopLogger(), db, home)
	must(e)
	r := rootmulti.NewStore(view, log.NewNopLogger(), metrics.NewNoOpMetrics())
	info, e := r.GetCommitInfo(h)
	must(e)
	m := map[string]st.CommitID{}
	for _, x := range info.StoreInfos {
		m[x.Name] = x.CommitId
	}
	return view, m
}
func tree(db dbm.DB, name string, c st.CommitID) (*iavl.MutableTree, *iavl.ImmutableTree) {
	p := dbm.NewPrefixDB(db, []byte("s/k:"+name+"/"))
	t := iavl.NewMutableTree(wrapper.NewDBWrapper(p), 0, true, iavl.NewNopLogger(), iavl.AsyncPruningOption(false))
	x, e := t.GetImmutable(c.Version)
	must(e)
	if !bytes.Equal(x.Hash(), c.Hash) {
		panic("root mismatch " + name)
	}
	return t, x
}
func value(v []byte) map[string]interface{} {
	s := sha256.Sum256(v)
	m := map[string]interface{}{"length": len(v), "sha256": fmt.Sprintf("%X", s)}
	if len(v) <= 65536 {
		m["base64"] = base64.StdEncoding.EncodeToString(v)
	}
	return m
}
func main() {
	if len(os.Args) != 6 {
		panic("usage: store-compare old-home old-height new-home new-height output-prefix")
	}
	h, e := strconv.ParseInt(os.Args[2], 10, 64)
	must(e)
	h2, e := strconv.ParseInt(os.Args[4], 10, 64)
	must(e)
	a, am := open(os.Args[1], h)
	defer a.Close()
	b, bm := open(os.Args[3], h2)
	defer b.Close()
	out, e := os.Create(os.Args[5] + ".diff.jsonl.gz")
	must(e)
	z := gzip.NewWriter(out)
	enc := json.NewEncoder(z)
	summary := map[string]interface{}{}
	for name, c := range am {
		next, present := bm[name]
		t, x := tree(a, name, c)
		if !present {
			summary[name] = map[string]interface{}{"removed": true, "old_entries": x.Size()}
			t.Close()
			continue
		}
		u, y := tree(b, name, next)
		if bytes.Equal(c.Hash, next.Hash) {
			summary[name] = map[string]interface{}{"root_equal": true, "entries": x.Size()}
			t.Close()
			u.Close()
			continue
		}
		it, e := x.Iterator(nil, nil, true)
		must(e)
		jt, e := y.Iterator(nil, nil, true)
		must(e)
		added, removed, modified := 0, 0, 0
		for it.Valid() || jt.Valid() {
			cmp := 0
			if !it.Valid() {
				cmp = 1
			} else if !jt.Valid() {
				cmp = -1
			} else {
				cmp = bytes.Compare(it.Key(), jt.Key())
			}
			var record map[string]interface{}
			if cmp < 0 {
				removed++
				record = map[string]interface{}{"store": name, "key": base64.StdEncoding.EncodeToString(it.Key()), "old": value(it.Value())}
				it.Next()
			} else if cmp > 0 {
				added++
				record = map[string]interface{}{"store": name, "key": base64.StdEncoding.EncodeToString(jt.Key()), "new": value(jt.Value())}
				jt.Next()
			} else {
				if !bytes.Equal(it.Value(), jt.Value()) {
					modified++
					record = map[string]interface{}{"store": name, "key": base64.StdEncoding.EncodeToString(it.Key()), "old": value(it.Value()), "new": value(jt.Value())}
				}
				it.Next()
				jt.Next()
			}
			if record != nil {
				must(enc.Encode(record))
			}
		}
		must(it.Error())
		must(jt.Error())
		must(it.Close())
		must(jt.Close())
		summary[name] = map[string]interface{}{"old_entries": x.Size(), "new_entries": y.Size(), "added": added, "removed": removed, "modified": modified}
		t.Close()
		u.Close()
		fmt.Println(name, summary[name])
	}
	for name := range bm {
		if _, ok := am[name]; !ok {
			summary[name] = map[string]interface{}{"new_store": true}
		}
	}
	must(z.Close())
	must(out.Close())
	raw, e := json.MarshalIndent(map[string]interface{}{"old_height": h, "new_height": h2, "stores": summary}, "", "  ")
	must(e)
	must(os.WriteFile(os.Args[5]+".summary.json", raw, 0644))
	fmt.Println(string(raw))
}
