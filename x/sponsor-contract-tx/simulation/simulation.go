package simulation

import (
	sdkmath "cosmossdk.io/math"
	"encoding/binary"
	"fmt"
	"math/rand"

	"github.com/cosmos/cosmos-sdk/baseapp"
	"github.com/cosmos/cosmos-sdk/codec"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/cosmos/cosmos-sdk/types/kv"
	"github.com/cosmos/cosmos-sdk/types/module"
	simtypes "github.com/cosmos/cosmos-sdk/types/simulation"

	"github.com/DoraFactory/doravota/x/sponsor-contract-tx/keeper"
	"github.com/DoraFactory/doravota/x/sponsor-contract-tx/types"
)

// AppModuleSimulation defines the simulation module interface
type AppModuleSimulation struct {
	keeper keeper.Keeper
	ak     types.AccountKeeper
	bk     types.BankKeeper
	wk     types.WasmKeeperInterface
}

// NewAppModuleSimulation creates a new simulation module
func NewAppModuleSimulation(k keeper.Keeper, ak types.AccountKeeper, bk types.BankKeeper, wk types.WasmKeeperInterface) *AppModuleSimulation {
	return &AppModuleSimulation{
		keeper: k,
		ak:     ak,
		bk:     bk,
		wk:     wk,
	}
}

// GenerateGenesisState creates a randomized GenState of the sponsor module
func (AppModuleSimulation) GenerateGenesisState(simState *module.SimulationState) {
	RandomizedGenState(simState)
}

// ProposalContents returns all possible proposals for the sponsor module
func (AppModuleSimulation) ProposalContents(_ module.SimulationState) []simtypes.WeightedProposalContent {
	// The sponsor module currently doesn't have governance proposals
	// This could be extended to include parameter change proposals
	return nil
}

// RandomizedParams creates randomized param changes for the simulator
func (AppModuleSimulation) RandomizedParams(r *rand.Rand) []simtypes.LegacyParamChange {
	return ParamChanges(r)
}

// RegisterStoreDecoder registers a decoder for sponsor module's types
func (am AppModuleSimulation) RegisterStoreDecoder(sdr simtypes.StoreDecoderRegistry) {
	sdr[types.StoreKey] = NewDecodeStore(am.keeper.Cdc())
}

// WeightedOperations returns the all the sponsor module operations with their respective weights
func (am AppModuleSimulation) WeightedOperations(appParams simtypes.AppParams, cdc codec.JSONCodec) []simtypes.WeightedOperation {
	return WeightedOperations(appParams, cdc, am.keeper, am.ak, am.bk, am.wk)
}

// NewDecodeStore returns a decoder function closure over the sponsor module's types
func NewDecodeStore(cdc codec.BinaryCodec) func(kvA, kvB kv.Pair) string {
	return func(kvA, kvB kv.Pair) string {
		return fmt.Sprintf(
			"A: %s\nB: %s\n",
			decodeStorePair(cdc, kvA),
			decodeStorePair(cdc, kvB),
		)
	}
}

func decodeStorePair(cdc codec.BinaryCodec, pair kv.Pair) string {
	if len(pair.Key) == 0 {
		return fmt.Sprintf("empty-key value=%X", pair.Value)
	}

	switch pair.Key[0] {
	case types.SponsorKeyPrefix[0]:
		var sponsor types.ContractSponsor
		if err := cdc.Unmarshal(pair.Value, &sponsor); err != nil {
			return fmt.Sprintf("sponsor key=%X invalid=%v value=%X", pair.Key, err, pair.Value)
		}
		return fmt.Sprintf("sponsor key=%X value=%+v", pair.Key, sponsor)

	case types.ParamsKey[0]:
		var params types.Params
		if err := cdc.Unmarshal(pair.Value, &params); err != nil {
			return fmt.Sprintf("params invalid=%v value=%X", err, pair.Value)
		}
		return fmt.Sprintf("params value=%+v", params)

	case types.UserGrantUsageKeyPrefix[0]:
		var usage types.UserGrantUsage
		if err := cdc.Unmarshal(pair.Value, &usage); err != nil {
			return fmt.Sprintf("usage key=%X invalid=%v value=%X", pair.Key, err, pair.Value)
		}
		return fmt.Sprintf("usage key=%X value=%+v", pair.Key, usage)

	case types.PolicyTicketKeyPrefix[0]:
		var ticket types.PolicyTicket
		if err := cdc.Unmarshal(pair.Value, &ticket); err != nil {
			return fmt.Sprintf("ticket key=%X invalid=%v value=%X", pair.Key, err, pair.Value)
		}
		return fmt.Sprintf("ticket key=%X value=%+v", pair.Key, ticket)

	case types.ExpiryIndexKeyPrefix[0]:
		height, ticketKey, ok := types.ParseExpiryIndexKey(pair.Key[1:])
		if !ok {
			return fmt.Sprintf("expiry-index invalid-key=%X", pair.Key)
		}
		return fmt.Sprintf("expiry-index height=%d ticket=%q", height, ticketKey)

	case types.SponsorGenerationKeyPrefix[0]:
		if len(pair.Value) != 8 {
			return fmt.Sprintf("generation key=%X invalid-value=%X", pair.Key, pair.Value)
		}
		return fmt.Sprintf(
			"generation contract=%q value=%d",
			pair.Key[1:],
			binary.BigEndian.Uint64(pair.Value),
		)
	default:
		return fmt.Sprintf("unknown key=%X value=%X", pair.Key, pair.Value)
	}
}

// SimulationManager encapsulates all simulation functionality
type SimulationManager struct {
	keeper keeper.Keeper
	ak     types.AccountKeeper
	bk     types.BankKeeper
	wk     types.WasmKeeperInterface
}

// NewSimulationManager creates a new simulation manager
func NewSimulationManager(k keeper.Keeper, ak types.AccountKeeper, bk types.BankKeeper, wk types.WasmKeeperInterface) *SimulationManager {
	return &SimulationManager{
		keeper: k,
		ak:     ak,
		bk:     bk,
		wk:     wk,
	}
}

// RunSimulation executes a full simulation test
func (sm *SimulationManager) RunSimulation(
	app *baseapp.BaseApp,
	ctx sdk.Context,
	accounts []simtypes.Account,
	config simtypes.Config,
) error {
	// Initialize random genesis state
	r := rand.New(rand.NewSource(config.Seed))
	genesisState := RandomGenesisState(r, accounts)

	// Validate genesis state
	if err := ValidateGenesisState(genesisState); err != nil {
		return fmt.Errorf("invalid genesis state: %w", err)
	}

	// Initialize module state
	if err := sm.keeper.SetParams(ctx, *genesisState.Params); err != nil {
		return fmt.Errorf("failed to set sponsor params: %w", err)
	}
	for _, sponsor := range genesisState.Sponsors {
		if sponsor != nil {
			if err := sm.keeper.SetSponsor(ctx, *sponsor); err != nil {
				return fmt.Errorf("failed to set sponsor: %w", err)
			}
		}
	}

	// Run initial invariant checks
	if msg, broken := AllInvariants(sm.keeper, sm.ak, sm.bk)(ctx); broken {
		return fmt.Errorf("initial invariant broken: %s", msg)
	}

	// Get simulation operations
	operations := WeightedOperations(
		make(simtypes.AppParams),
		nil, // codec would be passed here
		sm.keeper,
		sm.ak,
		sm.bk,
		sm.wk,
	)

	// Execute operations
	for i := 0; i < config.NumBlocks*config.BlockSize; i++ {
		if len(operations) == 0 {
			continue
		}

		// Select random operation
		op := operations[r.Intn(len(operations))]

		// Execute operation
		operationMsg, futureOps, err := op.Op()(r, app, ctx, accounts, config.ChainID)
		if err != nil {
			return fmt.Errorf("operation %d failed: %w", i, err)
		}

		// Log successful operations
		if operationMsg.OK {
			app.Logger().Info("Simulation operation executed",
				"index", i,
				"route", operationMsg.Route,
				"comment", operationMsg.Comment,
			)
		}

		// Process future operations
		for _, futureOp := range futureOps {
			app.Logger().Info("Future operation scheduled",
				"block_height", futureOp.BlockHeight,
			)
		}

		// Run invariants periodically
		if i%100 == 0 {
			if msg, broken := AllInvariants(sm.keeper, sm.ak, sm.bk)(ctx); broken {
				return fmt.Errorf("invariant broken at operation %d: %s", i, msg)
			}
		}
	}

	// Final invariant check
	if msg, broken := AllInvariants(sm.keeper, sm.ak, sm.bk)(ctx); broken {
		return fmt.Errorf("final invariant broken: %s", msg)
	}

	return nil
}

// TestInvariantsWithRandomData tests invariants with randomly generated data
func (sm *SimulationManager) TestInvariantsWithRandomData(
	ctx sdk.Context,
	r *rand.Rand,
	accounts []simtypes.Account,
	iterations int,
) error {
	for i := 0; i < iterations; i++ {
		// Generate random data
		genesisState := RandomGenesisState(r, accounts)

		// Note: In full implementation, would clear previous state
		// For now, we'll work with existing state

		// Set new state
		if err := sm.keeper.SetParams(ctx, *genesisState.Params); err != nil {
			return fmt.Errorf("failed to set sponsor params in iteration %d: %w", i, err)
		}
		for _, sponsor := range genesisState.Sponsors {
			if sponsor != nil {
				if err := sm.keeper.SetSponsor(ctx, *sponsor); err != nil {
					return fmt.Errorf("failed to set sponsor in iteration %d: %w", i, err)
				}
			}
		}

		// Add some random user grant usage
		for j := 0; j < r.Intn(10); j++ {
			if len(genesisState.Sponsors) == 0 {
				continue
			}

			sponsor := genesisState.Sponsors[r.Intn(len(genesisState.Sponsors))]
			if sponsor == nil || !sponsor.IsSponsored {
				continue
			}

			user := accounts[r.Intn(len(accounts))]
			lastUsedTime := ctx.BlockTime().Unix()
			if lastUsedTime < 0 {
				lastUsedTime = 0
			}
			usage := types.UserGrantUsage{
				UserAddress:     user.Address.String(),
				ContractAddress: sponsor.ContractAddress,
				TotalGrantUsed: []*sdk.Coin{
					{
						Denom:  types.SponsorshipDenom,
						Amount: sdkmath.NewInt(int64(r.Intn(100000) + 1000)),
					},
				},
				LastUsedTime: lastUsedTime,
			}
			if err := sm.keeper.SetActiveUserGrantUsage(ctx, usage); err != nil {
				return fmt.Errorf("failed to set user grant usage in iteration %d: %w", i, err)
			}
		}

		// Test all invariants
		if msg, broken := AllInvariants(sm.keeper, sm.ak, sm.bk)(ctx); broken {
			return fmt.Errorf("invariant broken in iteration %d: %s", i, msg)
		}
	}

	return nil
}

// ValidateSimulationResults validates the results of a simulation run
func ValidateSimulationResults(
	initialState *types.GenesisState,
	finalState *types.GenesisState,
	operationResults []simtypes.OperationMsg,
) error {
	// Validate that no operations resulted in unexpected errors
	var failedOps int
	for _, result := range operationResults {
		if !result.OK {
			failedOps++
		}
	}

	// Some failures are expected due to invalid random inputs
	if failedOps > len(operationResults)/2 {
		return fmt.Errorf("too many failed operations: %d/%d", failedOps, len(operationResults))
	}

	// Validate final state
	if err := ValidateGenesisState(finalState); err != nil {
		return fmt.Errorf("invalid final state: %w", err)
	}

	return nil
}
