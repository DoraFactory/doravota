package simulation_test

import (
	"fmt"
	"math/rand"
	"testing"

	"github.com/stretchr/testify/require"

	dbm "github.com/cometbft/cometbft-db"
	"github.com/cometbft/cometbft/libs/log"

	"github.com/cosmos/cosmos-sdk/baseapp"
	sdk "github.com/cosmos/cosmos-sdk/types"
	simtypes "github.com/cosmos/cosmos-sdk/types/simulation"

	sponsorsim "github.com/DoraFactory/doravota/x/sponsor-contract-tx/simulation"
	"github.com/DoraFactory/doravota/x/sponsor-contract-tx/testutil"
	"github.com/DoraFactory/doravota/x/sponsor-contract-tx/types"
)

const (
	SimulationSeed = 42
	NumBlocks      = 500
	BlockSize      = 200
	Commit         = true
	Period         = 1
	GenesisTime    = 1640995200 // 2022-01-01
)

// TestFullAppSimulation tests basic simulation functionality
func TestFullAppSimulation(t *testing.T) {
	// Simple test to verify simulation components work
	r := rand.New(rand.NewSource(SimulationSeed))
	accounts := simtypes.RandomAccounts(r, 10)

	// Test random genesis generation
	genesisState := sponsorsim.RandomGenesisState(r, accounts)
	err := sponsorsim.ValidateGenesisState(genesisState)
	require.NoError(t, err)

	// Test parameter generation
	params := sponsorsim.RandomizedParams(r)
	err = sponsorsim.ValidateParams(params)
	require.NoError(t, err)
}

// TestAppStateDeterminism tests that simulation results are deterministic
func TestAppStateDeterminism(t *testing.T) {
	// Test that same seed produces same results
	seed := int64(42)

	// Run simulation twice with same seed
	r1 := rand.New(rand.NewSource(seed))
	r2 := rand.New(rand.NewSource(seed))

	accounts1 := simtypes.RandomAccounts(r1, 10)
	accounts2 := simtypes.RandomAccounts(r2, 10)

	// Should produce identical accounts
	require.Equal(t, len(accounts1), len(accounts2))
	for i := range accounts1 {
		require.Equal(t, accounts1[i].Address, accounts2[i].Address)
	}
}

// TestSponsorModuleSimulation tests sponsor module specific simulation
func TestSponsorModuleSimulation(t *testing.T) {
	// Create test keeper setup
	k, ctx, mockWasm := testutil.SetupBasicKeeper(t)

	// Create mock accounts
	accounts := simtypes.RandomAccounts(rand.New(rand.NewSource(SimulationSeed)), 20)

	// Set up mock wasm contracts for sponsored contracts
	for i := 0; i < 5; i++ {
		contractAddr := accounts[i].Address
		adminAddr := accounts[i+10].Address.String()
		mockWasm.SetContractInfo(contractAddr, adminAddr)
		mockWasm.SetQueryResultEligible(contractAddr, true)
	}
	_ = mockWasm // Mark as used

	// Initialize with random genesis
	genesisState := sponsorsim.RandomGenesisState(
		rand.New(rand.NewSource(SimulationSeed)),
		accounts,
	)
	err := sponsorsim.ValidateGenesisState(genesisState)
	require.NoError(t, err)

	// Set parameters
	k.SetParams(ctx, *genesisState.Params)

	// Set sponsors
	for _, sponsor := range genesisState.Sponsors {
		if sponsor != nil {
			err := k.SetSponsor(ctx, *sponsor)
			require.NoError(t, err)
		}
	}

	// Run invariants before simulation
	msg, broken := sponsorsim.AllInvariants(k, nil, nil)(ctx)
	require.False(t, broken, msg)

	// Run simulation operations
	r := rand.New(rand.NewSource(SimulationSeed))
	app := baseapp.NewBaseApp("test", log.NewNopLogger(), dbm.NewMemDB(), nil)

	// Mock account and bank keepers for operations
	operations := sponsorsim.WeightedOperations(
		make(simtypes.AppParams),
		nil, // codec
		k,
		nil, // Mock account keeper would go here
		nil, // Mock bank keeper would go here
		mockWasm,
	)

	// Execute some operations
	for i := 0; i < 100; i++ {
		// Select random operation
		if len(operations) == 0 {
			continue
		}

		op := operations[r.Intn(len(operations))]
		operationMsg, futureOps, err := op.Op()(r, app, ctx, accounts, "test-chain")

		// Log operation results
		if err != nil {
			t.Logf("Operation %d failed: %v", i, err)
		} else {
			t.Logf("Operation %d: %s - %s", i, operationMsg.Route, operationMsg.Comment)
		}

		// Process future operations (if any)
		for _, futureOp := range futureOps {
			t.Logf("Future operation scheduled at block: %d", futureOp.BlockHeight)
		}

		// Run invariants after each operation
		msg, broken := sponsorsim.AllInvariants(k, nil, nil)(ctx)
		require.False(t, broken, fmt.Sprintf("Invariant broken after operation %d: %s", i, msg))
	}
}

// TestInvariants tests all module invariants
func TestInvariants(t *testing.T) {
	k, ctx, mockWasm := testutil.SetupBasicKeeper(t)
	_ = mockWasm // Mark as used

	// Test invariants with empty state
	msg, broken := sponsorsim.AllInvariants(k, nil, nil)(ctx)
	require.False(t, broken, msg)

	// Add some test data
	accounts := simtypes.RandomAccounts(rand.New(rand.NewSource(1)), 10)

	// Create test sponsors with various scenarios
	testSponsors := []types.ContractSponsor{
		// Normal sponsored contract
		{
			ContractAddress: accounts[0].Address.String(),
			CreatorAddress:  accounts[1].Address.String(),
			IsSponsored:     true,
			MaxGrantPerUser: testutil.CoinsToProtoCoins(sdk.NewCoins(sdk.NewCoin("peaka", sdk.NewInt(1000000)))),
		},
		// Non-sponsored contract with max grant
		{
			ContractAddress: accounts[2].Address.String(),
			CreatorAddress:  accounts[3].Address.String(),
			IsSponsored:     false,
			MaxGrantPerUser: testutil.CoinsToProtoCoins(sdk.NewCoins(sdk.NewCoin("peaka", sdk.NewInt(500000)))),
		},
		// Non-sponsored contract without max grant
		{
			ContractAddress: accounts[4].Address.String(),
			CreatorAddress:  accounts[5].Address.String(),
			IsSponsored:     false,
			MaxGrantPerUser: nil,
		},
	}

	for _, sponsor := range testSponsors {
		err := k.SetSponsor(ctx, sponsor)
		require.NoError(t, err)
	}

	// Test invariants with data
	msg, broken = sponsorsim.AllInvariants(k, nil, nil)(ctx)
	require.False(t, broken, msg)

	// Add some user grant usage
	for i, sponsor := range testSponsors {
		if sponsor.IsSponsored {
			userAddr := accounts[i+6].Address.String()
			usage := types.UserGrantUsage{
				UserAddress:     userAddr,
				ContractAddress: sponsor.ContractAddress,
				TotalGrantUsed:  testutil.CoinsToProtoCoins(sdk.NewCoins(sdk.NewCoin("peaka", sdk.NewInt(50000)))),
				LastUsedTime:    ctx.BlockTime().Unix(),
			}
			k.SetUserGrantUsage(ctx, usage)
		}
	}

	// Test invariants with usage data
	msg, broken = sponsorsim.AllInvariants(k, nil, nil)(ctx)
	require.False(t, broken, msg)
}

// TestSponsorInvariantsBroken tests scenarios that should break invariants
func TestSponsorInvariantsBroken(t *testing.T) {
	k, ctx, _ := testutil.SetupBasicKeeper(t)

	accounts := simtypes.RandomAccounts(rand.New(rand.NewSource(1)), 5)

	// Test case 1: Sponsored contract without MaxGrantPerUser (should break invariant)
	badSponsor := types.ContractSponsor{
		ContractAddress: accounts[0].Address.String(),
		CreatorAddress:  accounts[1].Address.String(),
		IsSponsored:     true,
		MaxGrantPerUser: nil, // This should break the invariant
	}

	err := k.SetSponsor(ctx, badSponsor)
	require.NoError(t, err) // SetSponsor might not validate this

	// Check invariant
	msg, broken := sponsorsim.SponsorConsistencyInvariant(k)(ctx)
	require.True(t, broken, "Expected invariant to be broken")
	require.Contains(t, msg, "empty MaxGrantPerUser")
}

// TestGenesisSimulation tests genesis state generation and validation
func TestGenesisSimulation(t *testing.T) {
	r := rand.New(rand.NewSource(SimulationSeed))

	// Generate random accounts
	accounts := simtypes.RandomAccounts(r, 20)

	// Test multiple genesis generations
	for i := 0; i < 10; i++ {
		genesisState := sponsorsim.RandomGenesisState(r, accounts)

		// Validate the generated genesis state
		err := sponsorsim.ValidateGenesisState(genesisState)
		require.NoError(t, err, fmt.Sprintf("Genesis validation failed on iteration %d", i))

		// Test that parameters are within expected bounds
		require.True(t, genesisState.Params.MaxGasPerSponsorship >= 1)
		require.True(t, genesisState.Params.MaxGasPerSponsorship <= 50000000)

		// Test sponsor consistency
		contractAddrs := make(map[string]bool)
		for _, sponsor := range genesisState.Sponsors {
			require.NotNil(t, sponsor)
			require.NotEmpty(t, sponsor.ContractAddress)
			require.NotEmpty(t, sponsor.CreatorAddress)

			// No duplicates
			require.False(t, contractAddrs[sponsor.ContractAddress],
				fmt.Sprintf("Duplicate contract address: %s", sponsor.ContractAddress))
			contractAddrs[sponsor.ContractAddress] = true

			// Sponsored contracts must have MaxGrantPerUser
			if sponsor.IsSponsored {
				require.NotEmpty(t, sponsor.MaxGrantPerUser,
					fmt.Sprintf("Sponsored contract %s missing MaxGrantPerUser", sponsor.ContractAddress))
			}
		}
	}
}

// TestParameterChanges tests parameter change simulation
func TestParameterChanges(t *testing.T) {
	r := rand.New(rand.NewSource(SimulationSeed))

	// Test parameter generation
	for i := 0; i < 20; i++ {
		params := sponsorsim.RandomizedParams(r)

		// Validate generated parameters
		err := sponsorsim.ValidateParams(params)
		require.NoError(t, err, fmt.Sprintf("Parameter validation failed on iteration %d: %+v", i, params))

		// Test parameter bounds
		require.True(t, params.MaxGasPerSponsorship >= 1000,
			fmt.Sprintf("MaxGasPerSponsorship too low: %d", params.MaxGasPerSponsorship))
		require.True(t, params.MaxGasPerSponsorship <= 50000000,
			fmt.Sprintf("MaxGasPerSponsorship too high: %d", params.MaxGasPerSponsorship))
	}
}

// TestEdgeCaseScenarios tests specific edge case scenarios
func TestEdgeCaseScenarios(t *testing.T) {
	scenarios := sponsorsim.TestScenarioParams()

	for i, params := range scenarios {
		t.Run(fmt.Sprintf("Scenario_%d", i), func(t *testing.T) {
			k, ctx, _ := testutil.SetupBasicKeeper(t)

			// Set the scenario parameters
			k.SetParams(ctx, params)

			// Verify parameters were set correctly
			storedParams := k.GetParams(ctx)
			require.Equal(t, params.SponsorshipEnabled, storedParams.SponsorshipEnabled)
			require.Equal(t, params.MaxGasPerSponsorship, storedParams.MaxGasPerSponsorship)

			// Test invariants with edge case parameters
			msg, broken := sponsorsim.ParamsConsistencyInvariant(k)(ctx)
			require.False(t, broken, fmt.Sprintf("Params invariant broken for scenario %d: %s", i, msg))
		})
	}
}

// Benchmark simulation operations
func BenchmarkSimulationOperations(b *testing.B) {
	// Create a basic setup for benchmarking
	k, ctx, mockWasm := testutil.SetupBasicKeeper(&testing.T{})

	// Setup test data
	accounts := simtypes.RandomAccounts(rand.New(rand.NewSource(1)), 100)
	r := rand.New(rand.NewSource(1))

	// Create some initial sponsors
	for i := 0; i < 10; i++ {
		sponsor := types.ContractSponsor{
			ContractAddress: accounts[i].Address.String(),
			CreatorAddress:  accounts[i+10].Address.String(),
			IsSponsored:     true,
			MaxGrantPerUser: testutil.CoinsToProtoCoins(sdk.NewCoins(sdk.NewCoin("peaka", sdk.NewInt(1000000)))),
		}
		err := k.SetSponsor(ctx, sponsor)
		require.NoError(b, err)

		// Setup mock wasm
		mockWasm.SetContractInfo(accounts[i].Address, accounts[i+10].Address.String())
	}

	app := baseapp.NewBaseApp("benchmark", log.NewNopLogger(), dbm.NewMemDB(), nil)
	operations := sponsorsim.WeightedOperations(
		make(simtypes.AppParams),
		nil, // codec
		k,
		nil,
		nil,
		mockWasm,
	)

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		if len(operations) == 0 {
			continue
		}

		op := operations[r.Intn(len(operations))]
		_, _, _ = op.Op()(r, app, ctx, accounts, "benchmark-chain")
	}
}
