package v1_0_0

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"cosmossdk.io/log/v2"
	dbm "github.com/cosmos/cosmos-db"
	"github.com/cosmos/cosmos-sdk/store/v2/rootmulti"
	upgradetypes "github.com/cosmos/cosmos-sdk/x/upgrade/types"
	"github.com/cosmos/iavl"
)

const iavlStorePrefix = "s/k:"

var emptyIAVLHash = sha256.Sum256(nil)

// WrapEmptyIAVLDB preserves the distinction between an existing empty IAVL
// root and a missing key. cosmos-db's Get/Has methods collapse both cases,
// while IAVL needs the distinction when restarting a chain with an empty
// module store. The wrapper performs an exact iterator lookup only for IAVL
// root keys; all other operations are delegated unchanged.
//
// This compatibility view is enabled only for a node that has reached the
// scheduled v1.0.0 upgrade. Before enabling it, every committed empty substore
// at the current height is checked for an actual empty legacy or current root.
// The view is read-compatible and does not rewrite application state.
func WrapEmptyIAVLDB(logger log.Logger, db dbm.DB, homeDir string) (dbm.DB, []string, error) {
	upgradeInfoPath := filepath.Join(homeDir, "data", upgradetypes.UpgradeInfoFilename)
	bz, err := os.ReadFile(upgradeInfoPath)
	if os.IsNotExist(err) {
		return db, nil, nil
	}
	if err != nil {
		return nil, nil, fmt.Errorf("read v1.0.0 upgrade info: %w", err)
	}

	var plan upgradetypes.Plan
	if err := json.Unmarshal(bz, &plan); err != nil {
		return nil, nil, fmt.Errorf("decode v1.0.0 upgrade info: %w", err)
	}
	if plan.Name != UpgradeName {
		return db, nil, nil
	}

	latestVersion := rootmulti.GetLatestVersion(db)
	if latestVersion < plan.Height-1 {
		return db, nil, nil
	}

	stores, err := validateEmptyIAVLStoresAtHeight(logger, db, latestVersion)
	if err != nil {
		return nil, nil, err
	}
	return &emptyIAVLRootAwareDB{DB: db}, stores, nil
}

func validateEmptyIAVLStoresAtHeight(logger log.Logger, db dbm.DB, height int64) ([]string, error) {
	rootStore := rootmulti.NewStore(db, logger)
	commitInfo, err := rootStore.GetCommitInfo(height)
	if err != nil {
		return nil, fmt.Errorf("read multistore commit info at height %d: %w", height, err)
	}

	stores := make([]string, 0)
	for _, storeInfo := range commitInfo.StoreInfos {
		commitID := storeInfo.CommitId
		if commitID.Version != height || !bytes.Equal(commitID.Hash, emptyIAVLHash[:]) {
			continue
		}

		storeDB := dbm.NewPrefixDB(db, []byte(iavlStorePrefix+storeInfo.Name+"/"))
		legacyExists, legacyValue, err := rawDBEntry(storeDB, legacyIAVLRootKey(height))
		if err != nil {
			return nil, fmt.Errorf("inspect legacy root for IAVL store %q: %w", storeInfo.Name, err)
		}
		currentExists, currentValue, err := rawDBEntry(storeDB, currentIAVLRootKey(height))
		if err != nil {
			return nil, fmt.Errorf("inspect current root for IAVL store %q: %w", storeInfo.Name, err)
		}
		legacyEmpty := legacyExists && len(legacyValue) == 0
		currentEmpty := currentExists && len(currentValue) == 0
		if !legacyEmpty && !currentEmpty {
			return nil, fmt.Errorf(
				"refusing empty-root compatibility for IAVL store %q at height %d: no committed empty root found",
				storeInfo.Name,
				height,
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

func currentIAVLRootKey(version int64) []byte {
	return append([]byte{'s'}, iavl.GetRootKey(version)...)
}

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
