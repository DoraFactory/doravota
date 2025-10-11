package sponsor_test

import (
    "testing"

    abci "github.com/cometbft/cometbft/abci/types"
    "github.com/cosmos/cosmos-sdk/codec"
    codectypes "github.com/cosmos/cosmos-sdk/codec/types"
    "github.com/stretchr/testify/require"

    sponsor "github.com/DoraFactory/doravota/x/sponsor-contract-tx"
    "github.com/DoraFactory/doravota/x/sponsor-contract-tx/types"
)

// Test that EndBlock respects GcFailedAttemptsPerBlock parameter
func TestModuleEndBlock_GCRespectsParam(t *testing.T) {
    k, ctx := setupKeeper(t)

    // Build a codec for AppModule (EndBlock doesn't use it functionally)
    reg := codectypes.NewInterfaceRegistry()
    cdc := codec.NewProtoCodec(reg)

    // Create AppModule with our keeper; bankKeeper not used in EndBlock
    am := sponsor.NewAppModule(cdc, k, nil)

    // Prepare params with small window for GC determination
    p := types.DefaultParams()
    p.AbuseTrackingEnabled = true
    p.GlobalWindowBlocks = 5

    // Height 100
    ctx = ctx.WithBlockHeight(100)

    // Inject three records: A expired; B not expired; C still blocked
    recA := types.FailedAttempts{Count: 0, WindowStartHeight: 10, UntilHeight: 90}
    recB := types.FailedAttempts{Count: 1, WindowStartHeight: 98, UntilHeight: 95}
    recC := types.FailedAttempts{Count: 0, WindowStartHeight: 95, UntilHeight: 120}
    k.SetFailedAttempts(ctx, "contractA", "userA", recA)
    k.SetFailedAttempts(ctx, "contractB", "userB", recB)
    k.SetFailedAttempts(ctx, "contractC", "userC", recC)

    // Case 1: GC disabled (limit=0) -> nothing deleted
    p.GcFailedAttemptsPerBlock = 0
    require.NoError(t, k.SetParams(ctx, p))
    am.EndBlock(ctx, abci.RequestEndBlock{})
    _, found := k.GetFailedAttempts(ctx, "contractA", "userA")
    require.True(t, found)

    // Case 2: GC enabled -> expired A should be deleted; B and C remain
    p.GcFailedAttemptsPerBlock = 10
    require.NoError(t, k.SetParams(ctx, p))
    am.EndBlock(ctx, abci.RequestEndBlock{})

    _, foundA := k.GetFailedAttempts(ctx, "contractA", "userA")
    _, foundB := k.GetFailedAttempts(ctx, "contractB", "userB")
    _, foundC := k.GetFailedAttempts(ctx, "contractC", "userC")
    require.False(t, foundA)
    require.True(t, foundB)
    require.True(t, foundC)
}

