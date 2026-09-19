package app

import (
	"fmt"

	"cosmossdk.io/log/v2"
	dbm "github.com/cosmos/cosmos-db"
	"github.com/cosmos/cosmos-sdk/store/v2/rootmulti"
)

// validateSDK055DependencyBoundary keeps this dependency-only candidate from
// opening legacy state before the coordinated migration is implemented. It
// reads commit metadata before BaseApp/StoreLoader can modify any stores.
// Replace this guard with the reviewed source preflight and store migration
// when the separately named SDK 0.55 upgrade handler is introduced.
func validateSDK055DependencyBoundary(logger log.Logger, db dbm.DB) error {
	height := rootmulti.GetLatestVersion(db)
	if height == 0 {
		return nil
	}
	info, err := rootmulti.NewStore(db, logger).GetCommitInfo(height)
	if err != nil {
		return fmt.Errorf("read source commit metadata: %w", err)
	}
	if info == nil {
		return fmt.Errorf("missing commit metadata at height %d", height)
	}
	for _, store := range info.StoreInfos {
		if store.Name == "params" {
			return fmt.Errorf("SDK 0.55 dependency candidate cannot open legacy params state at height %d: coordinated upgrade handler and store migration are not implemented yet", height)
		}
	}
	return nil
}
