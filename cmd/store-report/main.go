// store-report reads committed multistore metadata from a stopped node copy.
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"

	"cosmossdk.io/log"
	"cosmossdk.io/store/metrics"
	"cosmossdk.io/store/rootmulti"
	dbm "github.com/cosmos/cosmos-db"
)

func main() {
	if len(os.Args) != 3 {
		panic("usage: store-report data-directory height-or-0-for-latest")
	}
	h, err := strconv.ParseInt(os.Args[2], 10, 64)
	if err != nil {
		panic(err)
	}
	if h < 0 {
		panic("height must be non-negative")
	}
	// NewDB can create a database; reject a wrong input path before opening it.
	if _, err := os.Stat(filepath.Join(os.Args[1], "application.db", "CURRENT")); err != nil {
		panic(err)
	}
	db, err := dbm.NewDB("application", dbm.GoLevelDBBackend, os.Args[1])
	if err != nil {
		panic(err)
	}
	defer db.Close()
	if h == 0 {
		h = rootmulti.GetLatestVersion(db)
	}
	s := rootmulti.NewStore(db, log.NewNopLogger(), metrics.NewNoOpMetrics())
	info, err := s.GetCommitInfo(h)
	if err != nil {
		panic(err)
	}
	records := map[string]interface{}{}
	for _, v := range info.StoreInfos {
		records[v.Name] = map[string]interface{}{"version": v.CommitId.Version, "hash": fmt.Sprintf("%X", v.CommitId.Hash)}
	}
	out, err := json.MarshalIndent(map[string]interface{}{"height": h, "stores": records}, "", "  ")
	if err != nil {
		panic(err)
	}
	fmt.Println(string(out))
}
