package v0_5_0

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"cosmossdk.io/log"
	"cosmossdk.io/store/metrics"
	"cosmossdk.io/store/rootmulti"
	upgradetypes "cosmossdk.io/x/upgrade/types"
	dbm "github.com/cosmos/cosmos-db"

	"github.com/DoraFactory/doravota/app/legacyics29"
)

// RecoveryVersion identifies the emergency artifact, NOT the on-chain plan.
// UpgradeName and the Cosmovisor upgrade directory must remain "0.5.0".
const RecoveryVersion = "0.5.0-fee-recovery.1"

// ValidateRecoveryBoundary prevents this binary from being used as a routine
// 0.5.0 replacement. Recovery starts only at H-1 of the existing 0.5.0 plan,
// with fee state/balance present and the complete supported old module schema.
// Once recovery is committed, the compatibility store identifies this state
// lineage; subsequent restarts must continue using a compatible binary.
func ValidateRecoveryBoundary(logger log.Logger, db dbm.DB, home string) error {
	height := rootmulti.GetLatestVersion(db)
	if height == 0 {
		return nil
	} // Fresh genesis/dev context has no old state to recover.
	multi := rootmulti.NewStore(db, logger, metrics.NewNoOpMetrics())
	info, err := multi.GetCommitInfo(height)
	if err != nil {
		return err
	}
	hasCompatibility, hasOldFees := false, false
	for _, entry := range info.StoreInfos {
		if entry.Name == legacyics29.StoreKey {
			hasCompatibility = true
		}
		if entry.Name == "feeibc" {
			hasOldFees = true
		}
	}
	if hasCompatibility {
		if hasOldFees {
			return fmt.Errorf("inconsistent recovery state: both feeibc and legacyics29 are committed")
		}
		return nil
	}
	raw, err := os.ReadFile(filepath.Join(home, "data", upgradetypes.UpgradeInfoFilename))
	if err != nil {
		return fmt.Errorf("fee recovery requires the original 0.5.0 upgrade-info.json: %w", err)
	}
	var plan upgradetypes.Plan
	if err := json.Unmarshal(raw, &plan); err != nil {
		return err
	}
	if plan.Name != UpgradeName || plan.Height < 2 || height != plan.Height-1 {
		return fmt.Errorf("fee recovery requires committed height H-1 of plan 0.5.0: plan=%q H=%d committed=%d", plan.Name, plan.Height, height)
	}
	if !hasOldFees {
		return fmt.Errorf("legacy feeibc store is missing; this is not the supported recovery source")
	}
	if err := validateSourceStoresForPlan(logger, db, height, true); err != nil {
		return err
	}
	logger.Info("fee recovery boundary accepted; funds will be reconciled by the upgrade handler", "binary", RecoveryVersion, "plan", UpgradeName, "height", plan.Height)
	return nil
}
