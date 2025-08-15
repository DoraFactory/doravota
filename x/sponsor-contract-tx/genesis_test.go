package sponsor_test

import (
	"testing"

	"github.com/stretchr/testify/suite"
	sdk "github.com/cosmos/cosmos-sdk/types"
	codectypes "github.com/cosmos/cosmos-sdk/codec/types"
	"github.com/cosmos/cosmos-sdk/codec"
	"github.com/cosmos/cosmos-sdk/store"
	storetypes "github.com/cosmos/cosmos-sdk/store/types"
	dbm "github.com/cometbft/cometbft-db"
	tmproto "github.com/cometbft/cometbft/proto/tendermint/types"
	"github.com/cometbft/cometbft/libs/log"

	"github.com/DoraFactory/doravota/x/sponsor-contract-tx"
	"github.com/DoraFactory/doravota/x/sponsor-contract-tx/keeper"
	"github.com/DoraFactory/doravota/x/sponsor-contract-tx/types"
)

// setupKeeper creates a test keeper for genesis tests
func setupKeeper(t *testing.T) (keeper.Keeper, sdk.Context) {
	// Create codec
	registry := codectypes.NewInterfaceRegistry()
	cdc := codec.NewProtoCodec(registry)

	// Create store
	storeKey := sdk.NewKVStoreKey(types.StoreKey)

	// Create an in-memory database for testing
	db := dbm.NewMemDB()
	ms := store.NewCommitMultiStore(db)
	ms.MountStoreWithDB(storeKey, storetypes.StoreTypeIAVL, nil)

	// Load the stores
	err := ms.LoadLatestVersion()
	if err != nil {
		t.Fatalf("Failed to load store: %v", err)
	}

	// Create keeper
	k := keeper.NewKeeper(cdc, storeKey, nil) // Mock wasm keeper not needed for genesis tests

	// Create context
	ctx := sdk.NewContext(
		ms,
		tmproto.Header{},
		false,
		log.NewNopLogger(),
	)

	return *k, ctx
}

// GenesisTestSuite tests genesis import/export functionality
type GenesisTestSuite struct {
	suite.Suite

	ctx    sdk.Context
	keeper keeper.Keeper

	// Test data
	contractAddr1 string
	contractAddr2 string
	admin         sdk.AccAddress
	user1         sdk.AccAddress
	user2         sdk.AccAddress
}

func (suite *GenesisTestSuite) SetupTest() {
	// Set up keeper and context
	suite.keeper, suite.ctx = setupKeeper(suite.T())

	// Set up test data
	suite.contractAddr1 = "dora1contract1____________"
	suite.contractAddr2 = "dora1contract2____________"  
	suite.admin = sdk.AccAddress("admin_______________")
	suite.user1 = sdk.AccAddress("user1_______________")
	suite.user2 = sdk.AccAddress("user2_______________")
}

// TestDefaultGenesis tests that the default genesis state is valid
func (suite *GenesisTestSuite) TestDefaultGenesis() {
	genesis := types.DefaultGenesisState()

	// Test default values
	suite.Require().NotNil(genesis.Params, "Default should have params")
	suite.Require().True(genesis.Params.SponsorshipEnabled, "Default should enable sponsorship")
	suite.Require().Equal(uint64(1000000), genesis.Params.MaxGasPerSponsorship, "Default max gas should be 1M")
	suite.Require().Empty(genesis.Sponsors, "Default should have no sponsors")

	// Validate default genesis using the validation function
	err := types.ValidateGenesis(*genesis)
	suite.Require().NoError(err, "Default genesis should be valid")
}

// TestValidateGenesis tests genesis state validation
func (suite *GenesisTestSuite) TestValidateGenesis() {
	testCases := []struct {
		name      string
		genesis   *types.GenesisState
		expectErr bool
	}{
		{
			name:      "default genesis",
			genesis:   types.DefaultGenesisState(),
			expectErr: false,
		},
		{
			name: "valid genesis with sponsors",
			genesis: func() *types.GenesisState {
				params := types.DefaultParams()
				return &types.GenesisState{
					Params: &params,
					Sponsors: []*types.ContractSponsor{
						{
							ContractAddress: suite.contractAddr1,
							CreatorAddress:  suite.admin.String(),
							IsSponsored:     true,
							MaxGrantPerUser: []*sdk.Coin{
								{Denom: "peaka", Amount: sdk.NewInt(1000)},
							},
						},
					},
				}
			}(),
			expectErr: false,
		},
		{
			name: "invalid params - zero max gas",
			genesis: &types.GenesisState{
				Params: &types.Params{
					SponsorshipEnabled:    false,
					MaxGasPerSponsorship: 0, // Invalid
				},
				Sponsors: []*types.ContractSponsor{},
			},
			expectErr: true,
		},
		{
			name: "duplicate sponsors",
			genesis: func() *types.GenesisState {
				params := types.DefaultParams()
				return &types.GenesisState{
					Params: &params,
					Sponsors: []*types.ContractSponsor{
						{
							ContractAddress: suite.contractAddr1,
							CreatorAddress:  suite.admin.String(),
							IsSponsored:     true,
							MaxGrantPerUser: []*sdk.Coin{
								{Denom: "peaka", Amount: sdk.NewInt(1000)},
							},
						},
						{
							ContractAddress: suite.contractAddr1, // Duplicate
							CreatorAddress:  suite.admin.String(),
							IsSponsored:     false,
							MaxGrantPerUser: []*sdk.Coin{},
						},
					},
				}
			}(),
			expectErr: true,
		},
		{
			name: "sponsor with empty contract address",
			genesis: func() *types.GenesisState {
				params := types.DefaultParams()
				return &types.GenesisState{
					Params: &params,
					Sponsors: []*types.ContractSponsor{
						{
							ContractAddress: "", // Invalid
							CreatorAddress:  suite.admin.String(),
							IsSponsored:     true,
							MaxGrantPerUser: []*sdk.Coin{},
						},
					},
				}
			}(),
			expectErr: true,
		},
		{
			name: "sponsor with invalid contract address",
			genesis: func() *types.GenesisState {
				params := types.DefaultParams()
				return &types.GenesisState{
					Params: &params,
					Sponsors: []*types.ContractSponsor{
						{
							ContractAddress: "invalid-address", // Invalid bech32
							CreatorAddress:  suite.admin.String(),
							IsSponsored:     true,
							MaxGrantPerUser: []*sdk.Coin{},
						},
					},
				}
			}(),
			expectErr: false, // Note: ValidateGenesis doesn't validate bech32 format
		},
		{
			name: "sponsor with empty creator address",
			genesis: func() *types.GenesisState {
				params := types.DefaultParams()
				return &types.GenesisState{
					Params: &params,
					Sponsors: []*types.ContractSponsor{
						{
							ContractAddress: suite.contractAddr1,
							CreatorAddress:  "", // Empty, but this is valid in genesis
							IsSponsored:     true,
							MaxGrantPerUser: []*sdk.Coin{},
						},
					},
				}
			}(),
			expectErr: false, // Note: ValidateGenesis allows empty creator address
		},
	}

	for _, tc := range testCases {
		suite.Run(tc.name, func() {
			err := types.ValidateGenesis(*tc.genesis)
			if tc.expectErr {
				suite.Require().Error(err, "Genesis validation should fail for %s", tc.name)
			} else {
				suite.Require().NoError(err, "Genesis validation should pass for %s", tc.name)
			}
		})
	}
}

// TestInitExportGenesis tests genesis initialization and export
func (suite *GenesisTestSuite) TestInitExportGenesis() {
	// Create a genesis state with test data
	originalGenesis := &types.GenesisState{
		Params: &types.Params{
			SponsorshipEnabled:    true,
			MaxGasPerSponsorship: 1500000,
		},
		Sponsors: []*types.ContractSponsor{
			{
				ContractAddress: suite.contractAddr1,
				CreatorAddress:  suite.admin.String(),
				IsSponsored:     true,
				MaxGrantPerUser: []*sdk.Coin{
					{Denom: "peaka", Amount: sdk.NewInt(5000)},
				},
			},
			{
				ContractAddress: suite.contractAddr2,
				CreatorAddress:  suite.admin.String(),
				IsSponsored:     false,
				MaxGrantPerUser: []*sdk.Coin{},
			},
		},
	}

	// Initialize genesis
	sponsor.InitGenesis(suite.ctx, suite.keeper, *originalGenesis)

	// Verify parameters were set
	params := suite.keeper.GetParams(suite.ctx)
	suite.Require().True(params.SponsorshipEnabled)
	suite.Require().Equal(uint64(1500000), params.MaxGasPerSponsorship)

	// Verify sponsors were created
	sponsor1, found := suite.keeper.GetSponsor(suite.ctx, suite.contractAddr1)
	suite.Require().True(found, "Sponsor 1 should exist")
	suite.Require().Equal(suite.contractAddr1, sponsor1.ContractAddress)
	suite.Require().True(sponsor1.IsSponsored)
	suite.Require().Len(sponsor1.MaxGrantPerUser, 1)

	sponsor2, found := suite.keeper.GetSponsor(suite.ctx, suite.contractAddr2)
	suite.Require().True(found, "Sponsor 2 should exist")
	suite.Require().Equal(suite.contractAddr2, sponsor2.ContractAddress)
	suite.Require().False(sponsor2.IsSponsored)

	// Verify that user grant usage tracking works correctly
	// (UserGrantUsage is not part of genesis, it's managed through keeper methods)
	usage1 := suite.keeper.GetUserGrantUsage(suite.ctx, suite.user1.String(), suite.contractAddr1)
	suite.Require().Equal(suite.user1.String(), usage1.UserAddress)
	suite.Require().Equal(suite.contractAddr1, usage1.ContractAddress)
	suite.Require().Empty(usage1.TotalGrantUsed) // Should be empty initially
	suite.Require().Equal(int64(0), usage1.LastUsedTime) // Should be 0 initially

	// Export genesis and compare
	exportedGenesis := sponsor.ExportGenesis(suite.ctx, suite.keeper)

	// Compare parameters
	suite.Require().Equal(originalGenesis.Params.SponsorshipEnabled, exportedGenesis.Params.SponsorshipEnabled)
	suite.Require().Equal(originalGenesis.Params.MaxGasPerSponsorship, exportedGenesis.Params.MaxGasPerSponsorship)

	// Compare sponsors count
	suite.Require().Len(exportedGenesis.Sponsors, len(originalGenesis.Sponsors))

	// Find and compare each sponsor
	exportedSponsorMap := make(map[string]*types.ContractSponsor)
	for _, sponsor := range exportedGenesis.Sponsors {
		exportedSponsorMap[sponsor.ContractAddress] = sponsor
	}

	for _, originalSponsor := range originalGenesis.Sponsors {
		exportedSponsor, found := exportedSponsorMap[originalSponsor.ContractAddress]
		suite.Require().True(found, "Sponsor should be exported: %s", originalSponsor.ContractAddress)
		suite.Require().Equal(originalSponsor.CreatorAddress, exportedSponsor.CreatorAddress)
		suite.Require().Equal(originalSponsor.IsSponsored, exportedSponsor.IsSponsored)
		suite.Require().Equal(len(originalSponsor.MaxGrantPerUser), len(exportedSponsor.MaxGrantPerUser))
	}

	// Note: UserGrantUsages are not part of the protobuf GenesisState
	// They are managed separately through keeper methods and not exported/imported in genesis
}

// TestGenesisRoundTrip tests that genesis init->export->init produces identical state
func (suite *GenesisTestSuite) TestGenesisRoundTrip() {
	// Create original genesis state
	originalGenesis := &types.GenesisState{
		Params: &types.Params{
			SponsorshipEnabled:    false,
			MaxGasPerSponsorship: 3000000,
		},
		Sponsors: []*types.ContractSponsor{
			{
				ContractAddress: suite.contractAddr1,
				CreatorAddress:  suite.admin.String(),
				IsSponsored:     true,
				MaxGrantPerUser: []*sdk.Coin{
					{Denom: "peaka", Amount: sdk.NewInt(10000)},
				},
			},
		},
	}

	// First init
	sponsor.InitGenesis(suite.ctx, suite.keeper, *originalGenesis)

	// First export  
	firstExport := sponsor.ExportGenesis(suite.ctx, suite.keeper)

	// Create new keeper and context for second round
	k2, ctx2 := setupKeeper(suite.T())

	// Second init with first export
	sponsor.InitGenesis(ctx2, k2, *firstExport)

	// Second export
	secondExport := sponsor.ExportGenesis(ctx2, k2)

	// Compare the two exports - they should be identical
	suite.Require().Equal(firstExport.Params.SponsorshipEnabled, secondExport.Params.SponsorshipEnabled)
	suite.Require().Equal(firstExport.Params.MaxGasPerSponsorship, secondExport.Params.MaxGasPerSponsorship)
	suite.Require().Len(secondExport.Sponsors, len(firstExport.Sponsors))

	// Compare sponsors in detail
	if len(firstExport.Sponsors) > 0 && len(secondExport.Sponsors) > 0 {
		suite.Require().Equal(firstExport.Sponsors[0].ContractAddress, secondExport.Sponsors[0].ContractAddress)
		suite.Require().Equal(firstExport.Sponsors[0].CreatorAddress, secondExport.Sponsors[0].CreatorAddress)
		suite.Require().Equal(firstExport.Sponsors[0].IsSponsored, secondExport.Sponsors[0].IsSponsored)
	}

	// Note: UserGrantUsages comparison not needed as they're not part of genesis
}

// TestEmptyGenesis tests initialization with minimal genesis state
func (suite *GenesisTestSuite) TestEmptyGenesis() {
	params := types.DefaultParams()
	emptyGenesis := &types.GenesisState{
		Params:   &params,
		Sponsors: []*types.ContractSponsor{},
	}

	// Should not panic
	sponsor.InitGenesis(suite.ctx, suite.keeper, *emptyGenesis)

	// Export should return empty lists
	exported := sponsor.ExportGenesis(suite.ctx, suite.keeper)
	suite.Require().Empty(exported.Sponsors)

	// Parameters should be set to defaults
	params = suite.keeper.GetParams(suite.ctx)
	defaultParams := types.DefaultParams()
	suite.Require().Equal(defaultParams.SponsorshipEnabled, params.SponsorshipEnabled)
	suite.Require().Equal(defaultParams.MaxGasPerSponsorship, params.MaxGasPerSponsorship)
}

// TestGenesisWithDuplicateValidation tests that duplicate detection works
func (suite *GenesisTestSuite) TestGenesisWithDuplicateValidation() {
	params := types.DefaultParams()
	duplicateGenesis := &types.GenesisState{
		Params: &params,
		Sponsors: []*types.ContractSponsor{
			{
				ContractAddress: suite.contractAddr1,
				CreatorAddress:  suite.admin.String(),
				IsSponsored:     true,
				MaxGrantPerUser: []*sdk.Coin{},
			},
			{
				ContractAddress: suite.contractAddr1, // Duplicate
				CreatorAddress:  suite.admin.String(),
				IsSponsored:     false,
				MaxGrantPerUser: []*sdk.Coin{},
			},
		},
	}

	err := types.ValidateGenesis(*duplicateGenesis)
	suite.Require().Error(err, "Should detect duplicate sponsors")
	suite.Require().Contains(err.Error(), "duplicate", "Error message should mention duplicates")
}

func TestGenesisTestSuite(t *testing.T) {
	suite.Run(t, new(GenesisTestSuite))
}