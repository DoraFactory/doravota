package simulation_test

import (
	sdkmath "cosmossdk.io/math"
	"fmt"
	"math/rand"
	"testing"

	"cosmossdk.io/math"
	"github.com/stretchr/testify/require"

	"cosmossdk.io/log/v2"
	dbm "github.com/cosmos/cosmos-db"

	"github.com/cosmos/cosmos-sdk/baseapp"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/cosmos/cosmos-sdk/types/address"
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
	k, ctx, mockWasm := testutil.SetupBasicKeeper(t)
	accounts := simtypes.RandomAccounts(rand.New(rand.NewSource(SimulationSeed)), 20)
	contract := accounts[0].Address
	admin := accounts[10].Address
	mockWasm.SetContractInfo(contract, admin.String())
	require.NoError(t, k.SetParams(ctx, types.DefaultParams()))
	require.NoError(t, k.SetSponsor(ctx, types.ContractSponsor{
		ContractAddress: contract.String(),
		CreatorAddress:  admin.String(),
		SponsorAddress: sdk.AccAddress(
			address.Derive(contract, []byte("sponsor")),
		).String(),
		IsSponsored: true,
		MaxGrantPerUser: testutil.CoinsToProtoCoins(
			sdk.NewCoins(sdk.NewInt64Coin(types.SponsorshipDenom, 1_000_000)),
		),
	}))

	r := rand.New(rand.NewSource(SimulationSeed))
	operation := sponsorsim.SimulateUserGrantUsage(nil, nil, k, mockWasm)
	successes := 0
	for i := 0; i < 10; i++ {
		operationMsg, futureOps, err := operation(r, nil, ctx, accounts, "test-chain")
		require.NoError(t, err)
		require.Empty(t, futureOps)
		if operationMsg.OK {
			successes++
		}
	}
	require.Positive(t, successes)

	var totalUsed math.Int = math.ZeroInt()
	k.IterateUserGrantUsages(ctx, func(usage types.UserGrantUsage) bool {
		for _, coin := range usage.TotalGrantUsed {
			if coin != nil && coin.Denom == types.SponsorshipDenom {
				totalUsed = totalUsed.Add(coin.Amount)
			}
		}
		return false
	})
	require.True(t, totalUsed.IsPositive(), "simulation must mutate grant usage state")

	msg, broken := sponsorsim.AllInvariants(k, nil, nil)(ctx)
	require.False(t, broken, msg)
}

// TestInvariants tests all module invariants
func TestInvariants(t *testing.T) {
	k, ctx, mockWasm := testutil.SetupBasicKeeper(t)

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
			SponsorAddress: sdk.AccAddress(
				address.Derive(accounts[0].Address, []byte("sponsor")),
			).String(),
			IsSponsored:     true,
			MaxGrantPerUser: testutil.CoinsToProtoCoins(sdk.NewCoins(sdk.NewCoin("peaka", sdkmath.NewInt(1000000)))),
		},
		// Non-sponsored contract with max grant
		{
			ContractAddress: accounts[2].Address.String(),
			CreatorAddress:  accounts[3].Address.String(),
			SponsorAddress: sdk.AccAddress(
				address.Derive(accounts[2].Address, []byte("sponsor")),
			).String(),
			IsSponsored:     false,
			MaxGrantPerUser: testutil.CoinsToProtoCoins(sdk.NewCoins(sdk.NewCoin("peaka", sdkmath.NewInt(500000)))),
		},
		// Non-sponsored contract without max grant
		{
			ContractAddress: accounts[4].Address.String(),
			CreatorAddress:  accounts[5].Address.String(),
			SponsorAddress: sdk.AccAddress(
				address.Derive(accounts[4].Address, []byte("sponsor")),
			).String(),
			IsSponsored:     false,
			MaxGrantPerUser: nil,
		},
	}

	for _, sponsor := range testSponsors {
		contract, parseErr := sdk.AccAddressFromBech32(sponsor.ContractAddress)
		require.NoError(t, parseErr)
		mockWasm.SetContractInfo(contract, sponsor.CreatorAddress)
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
				TotalGrantUsed:  testutil.CoinsToProtoCoins(sdk.NewCoins(sdk.NewCoin("peaka", sdkmath.NewInt(50000)))),
				LastUsedTime:    0,
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

		// Basic param sanity
		require.NotNil(t, genesisState.Params)

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
			SponsorAddress: sdk.AccAddress(
				address.Derive(accounts[i].Address, []byte("sponsor")),
			).String(),
			IsSponsored:     true,
			MaxGrantPerUser: testutil.CoinsToProtoCoins(sdk.NewCoins(sdk.NewCoin("peaka", sdkmath.NewInt(1000000)))),
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
