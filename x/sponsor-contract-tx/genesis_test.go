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
    "github.com/cosmos/cosmos-sdk/types/address"
    wasmtypes "github.com/CosmWasm/wasmd/x/wasm/types"
    "github.com/stretchr/testify/require"
    "github.com/stretchr/testify/suite"

    sponsor "github.com/DoraFactory/doravota/x/sponsor-contract-tx"
    "github.com/DoraFactory/doravota/x/sponsor-contract-tx/keeper"
    "github.com/DoraFactory/doravota/x/sponsor-contract-tx/types"
)

// mockWasmKeeper is a simple WasmKeeperInterface mock for genesis tests
type mockWasmKeeper struct {
    allowAll bool
    exists   map[string]bool
}

func (m *mockWasmKeeper) GetContractInfo(ctx sdk.Context, contractAddress sdk.AccAddress) *wasmtypes.ContractInfo {
    if m == nil {
        return nil
    }
    if m.allowAll {
        return &wasmtypes.ContractInfo{Creator: "creator"}
    }
    if m.exists != nil && m.exists[contractAddress.String()] {
        return &wasmtypes.ContractInfo{Creator: "creator"}
    }
    return nil
}

func (m *mockWasmKeeper) QuerySmart(ctx sdk.Context, contractAddr sdk.AccAddress, req []byte) ([]byte, error) {
    return nil, nil
}

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

    // Create keeper with mock wasm keeper (allow all contracts)
    mw := &mockWasmKeeper{allowAll: true}
    k := keeper.NewKeeper(cdc, storeKey, mw, "cosmos10d07y265gmmuvt4z0w9aw880jnsr700j6zn9kn")

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
    mk := func(seed byte) sdk.AccAddress {
        b := make([]byte, 20)
        for i := range b { b[i] = seed }
        return sdk.AccAddress(b)
    }
    suite.contractAddr1 = mk(1).String()
    suite.contractAddr2 = mk(2).String()
    suite.admin = mk(3)
    suite.user1 = mk(4)
    suite.user2 = mk(5)
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
                // derive sponsor address
                ca, _ := sdk.AccAddressFromBech32(suite.contractAddr1)
                sponsorAddr := sdk.AccAddress(address.Derive(ca, []byte("sponsor"))).String()
                return &types.GenesisState{
                    Params: &params,
                    Sponsors: []*types.ContractSponsor{
                        {
                            ContractAddress: suite.contractAddr1,
                            CreatorAddress:  suite.admin.String(),
                            SponsorAddress:  sponsorAddr,
                            IsSponsored:     true,
                            MaxGrantPerUser: []*sdk.Coin{{Denom: "peaka", Amount: sdk.NewInt(1000)}},
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
                            SponsorAddress:  suite.admin.String(),
                            IsSponsored:     true,
                            MaxGrantPerUser: []*sdk.Coin{},
                        },
                    },
                }
            }(),
            expectErr: true,
        },
        {
            name: "sponsor with empty creator address",
            genesis: func() *types.GenesisState {
                params := types.DefaultParams()
                ca, _ := sdk.AccAddressFromBech32(suite.contractAddr1)
                sponsorAddr := sdk.AccAddress(address.Derive(ca, []byte("sponsor"))).String()
                return &types.GenesisState{
                    Params: &params,
                    Sponsors: []*types.ContractSponsor{
                        {
                            ContractAddress: suite.contractAddr1,
                            CreatorAddress:  "", // now invalid
                            SponsorAddress:  sponsorAddr,
                            IsSponsored:     true,
                            MaxGrantPerUser: []*sdk.Coin{{Denom: "peaka", Amount: sdk.NewInt(1)}},
                        },
                    },
                }
            }(),
            expectErr: true,
        },
        {
            name: "sponsor address not derived from contract",
            genesis: func() *types.GenesisState {
                params := types.DefaultParams()
                // wrong sponsor address
                wrong := suite.user1.String()
                return &types.GenesisState{
                    Params: &params,
                    Sponsors: []*types.ContractSponsor{{
                        ContractAddress: suite.contractAddr1,
                        CreatorAddress:  suite.admin.String(),
                        SponsorAddress:  wrong,
                        IsSponsored:     true,
                        MaxGrantPerUser: []*sdk.Coin{{Denom: "peaka", Amount: sdk.NewInt(1)}},
                    }},
                }
            }(),
            expectErr: true,
        },
        {
            name: "is sponsored but max_grant_per_user empty",
            genesis: func() *types.GenesisState {
                params := types.DefaultParams()
                ca, _ := sdk.AccAddressFromBech32(suite.contractAddr1)
                sponsorAddr := sdk.AccAddress(address.Derive(ca, []byte("sponsor"))).String()
                return &types.GenesisState{
                    Params: &params,
                    Sponsors: []*types.ContractSponsor{{
                        ContractAddress: suite.contractAddr1,
                        CreatorAddress:  suite.admin.String(),
                        SponsorAddress:  sponsorAddr,
                        IsSponsored:     true,
                        MaxGrantPerUser: []*sdk.Coin{}, // invalid now
                    }},
                }
            }(),
            expectErr: true,
        },
        {
            name: "user grant usage references unknown sponsor",
            genesis: func() *types.GenesisState {
                params := types.DefaultParams()
                return &types.GenesisState{
                    Params: &params,
                    Sponsors: []*types.ContractSponsor{},
                    UserGrantUsages: []*types.UserGrantUsage{{
                        UserAddress:     suite.user1.String(),
                        ContractAddress: suite.contractAddr1,
                        TotalGrantUsed:  []*sdk.Coin{{Denom: "peaka", Amount: sdk.NewInt(1)}},
                    }},
                }
            }(),
            expectErr: true,
        },
        {
            name: "user grant usage exceeds sponsor limit",
            genesis: func() *types.GenesisState {
                params := types.DefaultParams()
                ca, _ := sdk.AccAddressFromBech32(suite.contractAddr1)
                sponsorAddr := sdk.AccAddress(address.Derive(ca, []byte("sponsor"))).String()
                return &types.GenesisState{
                    Params: &params,
                    Sponsors: []*types.ContractSponsor{{
                        ContractAddress: suite.contractAddr1,
                        CreatorAddress:  suite.admin.String(),
                        SponsorAddress:  sponsorAddr,
                        IsSponsored:     true,
                        MaxGrantPerUser: []*sdk.Coin{{Denom: "peaka", Amount: sdk.NewInt(10)}},
                    }},
                    UserGrantUsages: []*types.UserGrantUsage{{
                        UserAddress:     suite.user1.String(),
                        ContractAddress: suite.contractAddr1,
                        TotalGrantUsed:  []*sdk.Coin{{Denom: "peaka", Amount: sdk.NewInt(11)}},
                    }},
                }
            }(),
            expectErr: true,
        },
        {
            name: "sponsor timestamps invalid (created_at > updated_at)",
            genesis: func() *types.GenesisState {
                params := types.DefaultParams()
                ca, _ := sdk.AccAddressFromBech32(suite.contractAddr1)
                sponsorAddr := sdk.AccAddress(address.Derive(ca, []byte("sponsor"))).String()
                return &types.GenesisState{
                    Params: &params,
                    Sponsors: []*types.ContractSponsor{{
                        ContractAddress: suite.contractAddr1,
                        CreatorAddress:  suite.admin.String(),
                        SponsorAddress:  sponsorAddr,
                        IsSponsored:     true,
                        CreatedAt:       100,
                        UpdatedAt:       50,
                        MaxGrantPerUser: []*sdk.Coin{{Denom: "peaka", Amount: sdk.NewInt(1)}},
                    }},
                }
            }(),
            expectErr: true,
        },
        {
            name: "user grant usage negative time",
            genesis: func() *types.GenesisState {
                params := types.DefaultParams()
                ca, _ := sdk.AccAddressFromBech32(suite.contractAddr1)
                sponsorAddr := sdk.AccAddress(address.Derive(ca, []byte("sponsor"))).String()
                return &types.GenesisState{
                    Params: &params,
                    Sponsors: []*types.ContractSponsor{{
                        ContractAddress: suite.contractAddr1,
                        CreatorAddress:  suite.admin.String(),
                        SponsorAddress:  sponsorAddr,
                        IsSponsored:     true,
                        MaxGrantPerUser: []*sdk.Coin{{Denom: "peaka", Amount: sdk.NewInt(10)}},
                    }},
                    UserGrantUsages: []*types.UserGrantUsage{{
                        UserAddress:     suite.user1.String(),
                        ContractAddress: suite.contractAddr1,
                        TotalGrantUsed:  []*sdk.Coin{{Denom: "peaka", Amount: sdk.NewInt(1)}},
                        LastUsedTime:    -1,
                    }},
                }
            }(),
            expectErr: true,
        },
        {
            name: "user grant usage negative amount",
            genesis: func() *types.GenesisState {
                params := types.DefaultParams()
                ca, _ := sdk.AccAddressFromBech32(suite.contractAddr1)
                sponsorAddr := sdk.AccAddress(address.Derive(ca, []byte("sponsor"))).String()
                return &types.GenesisState{
                    Params: &params,
                    Sponsors: []*types.ContractSponsor{{
                        ContractAddress: suite.contractAddr1,
                        CreatorAddress:  suite.admin.String(),
                        SponsorAddress:  sponsorAddr,
                        IsSponsored:     true,
                        MaxGrantPerUser: []*sdk.Coin{{Denom: "peaka", Amount: sdk.NewInt(10)}},
                    }},
                    UserGrantUsages: []*types.UserGrantUsage{{
                        UserAddress:     suite.user1.String(),
                        ContractAddress: suite.contractAddr1,
                        TotalGrantUsed:  []*sdk.Coin{{Denom: "peaka", Amount: sdk.NewInt(-1)}},
                    }},
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
    // derive sponsor addresses
    ca1, _ := sdk.AccAddressFromBech32(suite.contractAddr1)
    ca2, _ := sdk.AccAddressFromBech32(suite.contractAddr2)
    sp1 := sdk.AccAddress(address.Derive(ca1, []byte("sponsor"))).String()
    sp2 := sdk.AccAddress(address.Derive(ca2, []byte("sponsor"))).String()
    originalGenesis := &types.GenesisState{
        Params: &types.Params{
            SponsorshipEnabled:   true,
            MaxGasPerSponsorship: 1500000,
        },
        Sponsors: []*types.ContractSponsor{
            {
                ContractAddress: suite.contractAddr1,
                CreatorAddress:  suite.admin.String(),
                SponsorAddress:  sp1,
                IsSponsored:     true,
                MaxGrantPerUser: []*sdk.Coin{
                    {Denom: "peaka", Amount: sdk.NewInt(5000)},
                },
            },
            {
                ContractAddress: suite.contractAddr2,
                CreatorAddress:  suite.admin.String(),
                SponsorAddress:  sp2,
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
    // derive sponsor address
    ca1, _ := sdk.AccAddressFromBech32(suite.contractAddr1)
    sp1 := sdk.AccAddress(address.Derive(ca1, []byte("sponsor"))).String()
    originalGenesis := &types.GenesisState{
        Params: &types.Params{
            SponsorshipEnabled:   false,
            MaxGasPerSponsorship: 3000000,
        },
        Sponsors: []*types.ContractSponsor{
            {
                ContractAddress: suite.contractAddr1,
                CreatorAddress:  suite.admin.String(),
                SponsorAddress:  sp1,
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
    // derive correct sponsor address from contract for validity
    ca, _ := sdk.AccAddressFromBech32(suite.contractAddr1)
    sp := sdk.AccAddress(address.Derive(ca, []byte("sponsor"))).String()
    duplicateGenesis := &types.GenesisState{
        Params: &params,
        Sponsors: []*types.ContractSponsor{
            {
                ContractAddress: suite.contractAddr1,
                CreatorAddress:  suite.admin.String(),
                SponsorAddress:  sp,
                IsSponsored:     true,
                MaxGrantPerUser: []*sdk.Coin{{Denom: "peaka", Amount: sdk.NewInt(1)}},
            },
            {
                ContractAddress: suite.contractAddr1, // Duplicate
                CreatorAddress:  suite.admin.String(),
                SponsorAddress:  sp,
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

// TestInitGenesis_ContractMustExistAndSponsorDerived validates InitGenesis panics when contract doesn't exist or sponsor mismatch
func (suite *GenesisTestSuite) TestInitGenesis_ContractMustExistAndSponsorDerived() {
    // Build a fresh keeper with selective wasm mock
    registry := codectypes.NewInterfaceRegistry()
    cdc := codec.NewProtoCodec(registry)
    storeKey := sdk.NewKVStoreKey(types.StoreKey)
    db := dbm.NewMemDB()
    ms := store.NewCommitMultiStore(db)
    ms.MountStoreWithDB(storeKey, storetypes.StoreTypeIAVL, nil)
    require.NoError(suite.T(), ms.LoadLatestVersion())

    // Deny all contracts exist
    denyMock := &mockWasmKeeper{allowAll: false, exists: map[string]bool{}}
    kDeny := keeper.NewKeeper(cdc, storeKey, denyMock, "cosmos10d07y265gmmuvt4z0w9aw880jnsr700j6zn9kn")
    ctxDeny := sdk.NewContext(ms, tmproto.Header{}, false, log.NewNopLogger())

    ca, _ := sdk.AccAddressFromBech32(suite.contractAddr1)
    sp := sdk.AccAddress(address.Derive(ca, []byte("sponsor"))).String()
    pBad := types.DefaultParams()
    badGenesis := &types.GenesisState{
        Params: &pBad,
        Sponsors: []*types.ContractSponsor{{
            ContractAddress: suite.contractAddr1,
            CreatorAddress:  suite.admin.String(),
            SponsorAddress:  sp,
            IsSponsored:     true,
            MaxGrantPerUser: []*sdk.Coin{{Denom: "peaka", Amount: sdk.NewInt(1)}},
        }},
    }
    suite.Require().Panics(func() { sponsor.InitGenesis(ctxDeny, *kDeny, *badGenesis) }, "should panic when contract does not exist")

    // Allow all contracts exist but provide wrong sponsor address
    allowMock := &mockWasmKeeper{allowAll: true}
    kAllow := keeper.NewKeeper(cdc, storeKey, allowMock, "cosmos10d07y265gmmuvt4z0w9aw880jnsr700j6zn9kn")
    ctxAllow := sdk.NewContext(ms, tmproto.Header{}, false, log.NewNopLogger())
    pWrong := types.DefaultParams()
    wrongGenesis := &types.GenesisState{
        Params: &pWrong,
        Sponsors: []*types.ContractSponsor{{
            ContractAddress: suite.contractAddr1,
            CreatorAddress:  suite.admin.String(),
            SponsorAddress:  suite.user1.String(), // wrong derived address
            IsSponsored:     true,
            MaxGrantPerUser: []*sdk.Coin{{Denom: "peaka", Amount: sdk.NewInt(1)}},
        }},
    }
    suite.Require().Panics(func() { sponsor.InitGenesis(ctxAllow, *kAllow, *wrongGenesis) }, "should panic when sponsor address mismatches derivation")
}

// TestExportGenesis_RoundTrip_Normalizes ensures MaxGrantPerUser is normalized on import/export
func (suite *GenesisTestSuite) TestExportGenesis_RoundTrip_Normalizes() {
    // Build a genesis with duplicate denom entries
    params := types.DefaultParams()
    ca, _ := sdk.AccAddressFromBech32(suite.contractAddr1)
    sp := sdk.AccAddress(address.Derive(ca, []byte("sponsor"))).String()
    genesis := &types.GenesisState{
        Params: &params,
        Sponsors: []*types.ContractSponsor{{
            ContractAddress: suite.contractAddr1,
            CreatorAddress:  suite.admin.String(),
            SponsorAddress:  sp,
            IsSponsored:     true,
            MaxGrantPerUser: []*sdk.Coin{
                {Denom: "peaka", Amount: sdk.NewInt(1)},
                {Denom: "peaka", Amount: sdk.NewInt(2)},
            },
        }},
    }

    // Initialize and export
    sponsor.InitGenesis(suite.ctx, suite.keeper, *genesis)
    exported := sponsor.ExportGenesis(suite.ctx, suite.keeper)

    suite.Require().Len(exported.Sponsors, 1)
    out := exported.Sponsors[0].MaxGrantPerUser
    suite.Require().Len(out, 1)
    suite.Require().Equal("peaka", out[0].Denom)
    suite.Require().Equal(sdk.NewInt(3), out[0].Amount)
}
