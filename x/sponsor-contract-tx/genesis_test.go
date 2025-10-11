package sponsor_test

import (
	"testing"

	dbm "github.com/cometbft/cometbft-db"
	"github.com/cometbft/cometbft/libs/log"
	tmproto "github.com/cometbft/cometbft/proto/tendermint/types"
	"github.com/cosmos/cosmos-sdk/codec"
	codectypes "github.com/cosmos/cosmos-sdk/codec/types"
	"github.com/cosmos/cosmos-sdk/store"
	storetypes "github.com/cosmos/cosmos-sdk/store/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/stretchr/testify/suite"

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
	k := keeper.NewKeeper(cdc, storeKey, nil, "cosmos10d07y265gmmuvt4z0w9aw880jnsr700j6zn9kn") // Mock wasm keeper not needed for genesis tests

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
	suite.Require().Equal(uint64(2500000), genesis.Params.MaxGasPerSponsorship, "Default max gas should be 2.5M")
	suite.Require().Empty(genesis.Sponsors, "Default should have no sponsors")

	// Validate default genesis using the validation function
	err := types.ValidateGenesis(*genesis)
	suite.Require().NoError(err, "Default genesis should be valid")
}

// TestValidateGenesis tests genesis state validation
func (suite *GenesisTestSuite) TestValidateGenesis() {
    // helper for valid bech32 acc address
    mkAddr := func(seed byte) string {
        b := make([]byte, 20)
        for i := range b { b[i] = seed }
        return sdk.AccAddress(b).String()
    }
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
					SponsorshipEnabled:   false,
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
        // FailedAttempts validation cases
        {
            name: "failed attempts entry is nil",
            genesis: func() *types.GenesisState {
                p := types.DefaultParams()
                return &types.GenesisState{
                    Params:          &p,
                    Sponsors:        []*types.ContractSponsor{},
                    UserGrantUsages: []*types.UserGrantUsage{},
                    FailedAttempts:  []*types.FailedAttemptsEntry{nil},
                }
            }(),
            expectErr: true,
        },
        {
            name: "failed attempts record is nil",
            genesis: func() *types.GenesisState {
                c := mkAddr(1); u := mkAddr(2)
                p := types.DefaultParams()
                return &types.GenesisState{
                    Params:          &p,
                    Sponsors:        []*types.ContractSponsor{},
                    UserGrantUsages: []*types.UserGrantUsage{},
                    FailedAttempts: []*types.FailedAttemptsEntry{
                        {ContractAddress: c, UserAddress: u, Record: nil},
                    },
                }
            }(),
            expectErr: true,
        },
        {
            name: "failed attempts invalid contract address",
            genesis: func() *types.GenesisState {
                u := mkAddr(2)
                p := types.DefaultParams()
                return &types.GenesisState{
                    Params:          &p,
                    FailedAttempts: []*types.FailedAttemptsEntry{
                        {ContractAddress: "invalid", UserAddress: u, Record: &types.FailedAttempts{}},
                    },
                }
            }(),
            expectErr: true,
        },
        {
            name: "failed attempts empty user address",
            genesis: func() *types.GenesisState {
                c := mkAddr(1)
                p := types.DefaultParams()
                return &types.GenesisState{
                    Params:          &p,
                    FailedAttempts: []*types.FailedAttemptsEntry{
                        {ContractAddress: c, UserAddress: "", Record: &types.FailedAttempts{}},
                    },
                }
            }(),
            expectErr: true,
        },
        {
            name: "failed attempts invalid user address",
            genesis: func() *types.GenesisState {
                c := mkAddr(1)
                p := types.DefaultParams()
                return &types.GenesisState{
                    Params:          &p,
                    FailedAttempts: []*types.FailedAttemptsEntry{
                        {ContractAddress: c, UserAddress: "invalid-user", Record: &types.FailedAttempts{}},
                    },
                }
            }(),
            expectErr: true,
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
			SponsorshipEnabled:   true,
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
		UserGrantUsages: []*types.UserGrantUsage{
			{
				UserAddress:     suite.user1.String(),
				ContractAddress: suite.contractAddr1,
				TotalGrantUsed: []*sdk.Coin{
					{Denom: "peaka", Amount: sdk.NewInt(750)},
				},
				LastUsedTime: 123456789,
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

	// Verify that user grant usage state was restored from genesis
	usage1 := suite.keeper.GetUserGrantUsage(suite.ctx, suite.user1.String(), suite.contractAddr1)
	suite.Require().Equal(suite.user1.String(), usage1.UserAddress)
	suite.Require().Equal(suite.contractAddr1, usage1.ContractAddress)
	suite.Require().Len(usage1.TotalGrantUsed, 1)
	suite.Require().Equal("peaka", usage1.TotalGrantUsed[0].Denom)
	suite.Require().True(usage1.TotalGrantUsed[0].Amount.Equal(sdk.NewInt(750)))
	suite.Require().Equal(int64(123456789), usage1.LastUsedTime)

	// Export genesis and compare
	exportedGenesis := sponsor.ExportGenesis(suite.ctx, suite.keeper)

	// Compare parameters
	suite.Require().Equal(originalGenesis.Params.SponsorshipEnabled, exportedGenesis.Params.SponsorshipEnabled)
	suite.Require().Equal(originalGenesis.Params.MaxGasPerSponsorship, exportedGenesis.Params.MaxGasPerSponsorship)

	// Compare sponsors count
	suite.Require().Len(exportedGenesis.Sponsors, len(originalGenesis.Sponsors))
	suite.Require().Len(exportedGenesis.UserGrantUsages, len(originalGenesis.UserGrantUsages))

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

	// Compare exported user grant usages
	exportedUsageMap := make(map[string]*types.UserGrantUsage)
	for _, usage := range exportedGenesis.UserGrantUsages {
		exportedUsageMap[usage.UserAddress+"/"+usage.ContractAddress] = usage
	}

	for _, originalUsage := range originalGenesis.UserGrantUsages {
		exportedUsage, found := exportedUsageMap[originalUsage.UserAddress+"/"+originalUsage.ContractAddress]
		suite.Require().True(found, "User grant usage should be exported: %s/%s", originalUsage.UserAddress, originalUsage.ContractAddress)
		suite.Require().Equal(originalUsage.LastUsedTime, exportedUsage.LastUsedTime)
		suite.Require().Equal(len(originalUsage.TotalGrantUsed), len(exportedUsage.TotalGrantUsed))
		for i := range originalUsage.TotalGrantUsed {
			suite.Require().Equal(originalUsage.TotalGrantUsed[i].Denom, exportedUsage.TotalGrantUsed[i].Denom)
			suite.Require().True(originalUsage.TotalGrantUsed[i].Amount.Equal(exportedUsage.TotalGrantUsed[i].Amount))
		}
	}
}

// TestGenesisRoundTrip tests that genesis init->export->init produces identical state
func (suite *GenesisTestSuite) TestGenesisRoundTrip() {
	// Create original genesis state
	originalGenesis := &types.GenesisState{
		Params: &types.Params{
			SponsorshipEnabled:   false,
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
		UserGrantUsages: []*types.UserGrantUsage{
			{
				UserAddress:     suite.user1.String(),
				ContractAddress: suite.contractAddr1,
				TotalGrantUsed: []*sdk.Coin{
					{Denom: "peaka", Amount: sdk.NewInt(250)},
				},
				LastUsedTime: 987654321,
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
	suite.Require().Len(secondExport.UserGrantUsages, len(firstExport.UserGrantUsages))

	// Compare sponsors in detail
	if len(firstExport.Sponsors) > 0 && len(secondExport.Sponsors) > 0 {
		suite.Require().Equal(firstExport.Sponsors[0].ContractAddress, secondExport.Sponsors[0].ContractAddress)
		suite.Require().Equal(firstExport.Sponsors[0].CreatorAddress, secondExport.Sponsors[0].CreatorAddress)
		suite.Require().Equal(firstExport.Sponsors[0].IsSponsored, secondExport.Sponsors[0].IsSponsored)
	}

	if len(firstExport.UserGrantUsages) > 0 && len(secondExport.UserGrantUsages) > 0 {
		suite.Require().Equal(firstExport.UserGrantUsages[0].UserAddress, secondExport.UserGrantUsages[0].UserAddress)
		suite.Require().Equal(firstExport.UserGrantUsages[0].ContractAddress, secondExport.UserGrantUsages[0].ContractAddress)
		suite.Require().Equal(firstExport.UserGrantUsages[0].LastUsedTime, secondExport.UserGrantUsages[0].LastUsedTime)
	}
}

// TestFailedAttemptsGenesisRoundTrip verifies failed-attempts (global cooldown) state survives Export -> Init
func (suite *GenesisTestSuite) TestFailedAttemptsGenesisRoundTrip() {
    // Helper to make valid bech32 addresses
    mkAddr := func(seed byte) string {
        b := make([]byte, 20)
        for i := range b { b[i] = seed }
        return sdk.AccAddress(b).String()
    }

    contract1 := mkAddr(1)
    user1 := mkAddr(2)
    contract2 := mkAddr(3)
    user2 := mkAddr(4)

    // Prepare original genesis with failed-attempts entries
    params := types.DefaultParams()
    original := &types.GenesisState{
        Params: &params,
        Sponsors: []*types.ContractSponsor{},
        UserGrantUsages: []*types.UserGrantUsage{},
        FailedAttempts: []*types.FailedAttemptsEntry{
            {
                ContractAddress: contract1,
                UserAddress:     user1,
                Record: &types.FailedAttempts{
                    Count:             0,
                    WindowStartHeight: 100,
                    UntilHeight:       150,
                },
            },
            {
                ContractAddress: contract2,
                UserAddress:     user2,
                Record: &types.FailedAttempts{
                    Count:             2,
                    WindowStartHeight: 200,
                    UntilHeight:       0,
                },
            },
        },
    }

    // Init with original
    sponsor.InitGenesis(suite.ctx, suite.keeper, *original)

    // Export current state
    exported := sponsor.ExportGenesis(suite.ctx, suite.keeper)
    // Basic presence
    suite.Require().Len(exported.FailedAttempts, 2)

    // Create new keeper and context; import exported
    k2, ctx2 := setupKeeper(suite.T())
    sponsor.InitGenesis(ctx2, k2, *exported)

    // Verify failed attempts restored
    rec1, found1 := k2.GetFailedAttempts(ctx2, contract1, user1)
    suite.Require().True(found1)
    suite.Require().Equal(int64(150), rec1.UntilHeight)
    suite.Require().Equal(int64(100), rec1.WindowStartHeight)

    rec2, found2 := k2.GetFailedAttempts(ctx2, contract2, user2)
    suite.Require().True(found2)
    suite.Require().Equal(uint32(2), rec2.Count)
    suite.Require().Equal(int64(0), rec2.UntilHeight)
}

// TestEmptyGenesis tests initialization with minimal genesis state
func (suite *GenesisTestSuite) TestEmptyGenesis() {
	params := types.DefaultParams()
	emptyGenesis := &types.GenesisState{
		Params:          &params,
		Sponsors:        []*types.ContractSponsor{},
		UserGrantUsages: []*types.UserGrantUsage{},
	}

	// Should not panic
	sponsor.InitGenesis(suite.ctx, suite.keeper, *emptyGenesis)

	// Export should return empty lists
	exported := sponsor.ExportGenesis(suite.ctx, suite.keeper)
	suite.Require().Empty(exported.Sponsors)
	suite.Require().Empty(exported.UserGrantUsages)

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
