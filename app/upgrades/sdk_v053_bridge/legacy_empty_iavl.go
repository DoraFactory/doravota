package sdk_v053_bridge

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"cosmossdk.io/log"
	"cosmossdk.io/store/metrics"
	"cosmossdk.io/store/rootmulti"
	upgradetypes "cosmossdk.io/x/upgrade/types"
	dbm "github.com/cosmos/cosmos-db"
)

const iavlStorePrefix = "s/k:"

var emptyIAVLHash = sha256.Sum256(nil)

// WrapLegacyEmptyIAVLDB returns a database view that preserves the distinction
// between an existing empty IAVL root and a missing key.
//
// IAVL v0.20 stored an empty root as r<height> -> empty. cosmos-db's Get/Has
// methods collapse an empty value and a missing key to nil/false, while IAVL v1
// needs to distinguish them when loading the legacy tree. The wrapper only
// performs an exact iterator lookup for IAVL root keys whose normal lookup
// returned nil; every other database operation remains unchanged.
//
// Before enabling the view at the bridge boundary, this function validates
// that every committed empty substore has exactly the expected empty legacy
// root. No application state is written or rewritten.
func WrapLegacyEmptyIAVLDB(logger log.Logger, db dbm.DB, homeDir string) (dbm.DB, []string, error) {
	upgradeInfoPath := filepath.Join(homeDir, "data", upgradetypes.UpgradeInfoFilename)
	bz, err := os.ReadFile(upgradeInfoPath)
	if os.IsNotExist(err) {
		return db, nil, nil
	}
	if err != nil {
		return nil, nil, fmt.Errorf("read bridge upgrade info: %w", err)
	}

	var plan upgradetypes.Plan
	if err := json.Unmarshal(bz, &plan); err != nil {
		return nil, nil, fmt.Errorf("decode bridge upgrade info: %w", err)
	}
	if plan.Name != UpgradeName {
		return db, nil, nil
	}

	latestVersion := rootmulti.GetLatestVersion(db)
	if latestVersion < plan.Height-1 {
		return db, nil, nil
	}

	stores, err := validateLegacyEmptyIAVLStoresAtHeight(logger, db, plan.Height)
	if err != nil {
		return nil, nil, err
	}
	// Keep the view enabled after the bridge as well. IAVL v1 also persists
	// current-format empty roots as empty database values, so the same
	// cosmos-db ambiguity must be handled on every later restart.
	return &emptyIAVLRootAwareDB{DB: db}, stores, nil
}

func validateLegacyEmptyIAVLStoresAtHeight(logger log.Logger, db dbm.DB, upgradeHeight int64) ([]string, error) {
	latestVersion := rootmulti.GetLatestVersion(db)
	if latestVersion == 0 || upgradeHeight != latestVersion+1 {
		return nil, nil
	}

	rootStore := rootmulti.NewStore(db, logger, metrics.NewNoOpMetrics())
	commitInfo, err := rootStore.GetCommitInfo(latestVersion)
	if err != nil {
		return nil, fmt.Errorf("read multistore commit info at height %d: %w", latestVersion, err)
	}

	stores := make([]string, 0)
	for _, storeInfo := range commitInfo.StoreInfos {
		commitID := storeInfo.CommitId
		if commitID.Version != latestVersion || !bytes.Equal(commitID.Hash, emptyIAVLHash[:]) {
			continue
		}

		storeDB := dbm.NewPrefixDB(db, []byte(iavlStorePrefix+storeInfo.Name+"/"))
		exists, value, err := rawDBEntry(storeDB, legacyIAVLRootKey(latestVersion))
		if err != nil {
			return nil, fmt.Errorf("inspect legacy root for IAVL store %q: %w", storeInfo.Name, err)
		}
		if !exists || len(value) != 0 {
			return nil, fmt.Errorf(
				"refusing legacy-empty compatibility for IAVL store %q at height %d: expected an existing empty legacy root (exists=%t value-length=%d)",
				storeInfo.Name,
				latestVersion,
				exists,
				len(value),
			)
		}
		stores = append(stores, storeInfo.Name)
	}

	return stores, nil
}

type emptyIAVLRootAwareDB struct {
	dbm.DB
}

func (db *emptyIAVLRootAwareDB) Get(key []byte) ([]byte, error) {
	value, err := db.DB.Get(key)
	if err != nil || value != nil || !isIAVLRootKey(key) {
		return value, err
	}
	exists, rawValue, err := rawDBEntry(db.DB, key)
	if err != nil || !exists {
		return nil, err
	}
	if rawValue == nil {
		return []byte{}, nil
	}
	return rawValue, nil
}

func (db *emptyIAVLRootAwareDB) Has(key []byte) (bool, error) {
	if !isIAVLRootKey(key) {
		return db.DB.Has(key)
	}
	exists, _, err := rawDBEntry(db.DB, key)
	return exists, err
}

func isIAVLRootKey(key []byte) bool {
	separator := bytes.LastIndexByte(key, '/')
	if separator < 0 || !bytes.HasPrefix(key, []byte(iavlStorePrefix)) {
		return false
	}
	suffix := key[separator+1:]
	if len(suffix) == 9 && suffix[0] == 'r' {
		return true
	}
	if len(suffix) != 13 || suffix[0] != 's' {
		return false
	}
	return binary.BigEndian.Uint32(suffix[9:]) == 1
}

func legacyIAVLRootKey(version int64) []byte {
	key := make([]byte, 9)
	key[0] = 'r'
	binary.BigEndian.PutUint64(key[1:], uint64(version))
	return key
}

// rawDBEntry distinguishes an existing empty value from a missing key. The
// cosmos-db Get/Has convenience methods collapse both cases to nil/false.
func rawDBEntry(db dbm.DB, key []byte) (bool, []byte, error) {
	end := append(append([]byte(nil), key...), 0)
	iterator, err := db.Iterator(key, end)
	if err != nil {
		return false, nil, err
	}
	defer iterator.Close()
	if !iterator.Valid() || !bytes.Equal(iterator.Key(), key) {
		return false, nil, iterator.Error()
	}
	value := append([]byte(nil), iterator.Value()...)
	return true, value, iterator.Error()
}
