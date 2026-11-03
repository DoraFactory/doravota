package app

import (
	"fmt"
	"time"

	"github.com/cosmos/cosmos-sdk/store/v2/rootmulti"
	sdk "github.com/cosmos/cosmos-sdk/types"
)

// SDK v0.55.0 BaseApp.Init creates CheckTx state with a height-zero header even
// after loading a nonzero store version. Until the first Commit, auth treats
// every signer as genesis account number zero and height/time-dependent Ante
// rules see the wrong height/time. The SDK exposes no check-state header setter.
//
// Capture committed metadata once, during loading (before serving requests),
// then repair ONLY the still-empty admission/simulation context before Ante.
// Do not substitute next-block height, wall-clock time, or a synthetic commit.
// Finalize/Prepare/Process and true genesis never use this compatibility path.
// Remove this workaround when the pinned SDK initializes loaded CheckTx state.
type startupCheckContext struct {
	height int64
	time   time.Time
}

func (s startupCheckContext) restore(ctx sdk.Context) sdk.Context {
	if s.height <= 0 || ctx.BlockHeight() != 0 {
		return ctx
	}
	switch ctx.ExecMode() {
	case sdk.ExecModeCheck, sdk.ExecModeReCheck, sdk.ExecModeSimulate:
	default:
		return ctx
	}
	// Update both SDK header views. Preserve the configured chain ID and all
	// other context fields; commit metadata is not a complete block header, so
	// do not invent header hashes or replace its AppHash with the new state root.
	info := ctx.HeaderInfo()
	info.Height, info.Time = s.height, s.time
	return ctx.WithBlockHeight(s.height).WithBlockTime(s.time).WithHeaderInfo(info)
}

func (app *App) loadStartupCheckContext() error {
	height := app.LastBlockHeight()
	if height == 0 {
		app.startupCheckContext = startupCheckContext{}
		return nil
	}
	store, ok := app.CommitMultiStore().(*rootmulti.Store)
	if !ok {
		return fmt.Errorf("restore startup CheckTx context: unsupported commit store %T", app.CommitMultiStore())
	}
	info, err := store.GetCommitInfo(height)
	if err != nil {
		return fmt.Errorf("restore startup CheckTx context at %d: %w", height, err)
	}
	if info.Version != height {
		return fmt.Errorf("restore startup CheckTx context: commit metadata version %d != %d", info.Version, height)
	}
	app.startupCheckContext = startupCheckContext{height: height, time: info.Timestamp}
	return nil
}

// LoadLatestVersion restores admission metadata after the SDK has loaded and
// initialized its stores. Like BaseApp loading, this is startup-only, not a
// method to call concurrently with ABCI requests.
func (app *App) LoadLatestVersion() error {
	if err := app.BaseApp.LoadLatestVersion(); err != nil {
		return err
	}
	return app.loadStartupCheckContext()
}

// LoadVersion covers explicit-height loading/export through App.LoadHeight.
func (app *App) LoadVersion(height int64) error {
	if err := app.BaseApp.LoadVersion(height); err != nil {
		return err
	}
	return app.loadStartupCheckContext()
}
