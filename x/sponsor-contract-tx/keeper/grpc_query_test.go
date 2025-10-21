package keeper

import (
	"fmt"
	"testing"

	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/cosmos/cosmos-sdk/types/query"
	"github.com/stretchr/testify/suite"

	"github.com/DoraFactory/doravota/x/sponsor-contract-tx/types"
)

// GRPCQueryTestSuite tests the gRPC query server implementation
type GRPCQueryTestSuite struct {
	suite.Suite

	keeper      Keeper
	ctx         sdk.Context
	queryServer types.QueryServer

	// Test data
	contractAddr sdk.AccAddress
	admin        sdk.AccAddress
	user         sdk.AccAddress
	maxGrant     sdk.Coins
}

func (suite *GRPCQueryTestSuite) SetupTest() {
	// Use the working setupKeeper function
	suite.keeper, suite.ctx, _ = setupKeeper(suite.T())

	// Test store access immediately after setup
	params := suite.keeper.GetParams(suite.ctx)
	suite.T().Logf("Direct keeper.GetParams works in SetupTest: %+v", params)

	// Create query server (unused in SetupTest)
	// queryServer = NewQueryServer(suite.keeper)

	// Set up test data
	suite.contractAddr = sdk.AccAddress("contract____________")
	suite.admin = sdk.AccAddress("admin_______________")
	suite.user = sdk.AccAddress("user________________")
	suite.maxGrant = sdk.NewCoins(sdk.NewCoin("peaka", sdk.NewInt(1000)))
}

// Helper function to convert sdk.Coins to []*sdk.Coin for protobuf
func coinsToProtoCoins(coins sdk.Coins) []*sdk.Coin {
	result := make([]*sdk.Coin, len(coins))
	for i, coin := range coins {
		result[i] = &sdk.Coin{
			Denom:  coin.Denom,
			Amount: coin.Amount,
		}
	}
	return result
}

// TestQuerySponsor tests the Sponsor gRPC query
func (suite *GRPCQueryTestSuite) TestQuerySponsor() {
	// Get fresh keeper and context for this test method
	keeper, freshCtx, _ := setupKeeper(suite.T())
	queryServer := NewQueryServer(keeper)
	ctx := sdk.WrapSDKContext(freshCtx)

	testCases := []struct {
		name        string
		request     *types.QuerySponsorRequest
		preRun      func()
		expectError bool
		postCheck   func(*types.QuerySponsorResponse)
	}{
		{
			name:        "nil request",
			request:     nil,
			expectError: true,
			postCheck:   nil,
		},
		{
			name: "empty contract address",
			request: &types.QuerySponsorRequest{
				ContractAddress: "",
			},
			expectError: true,
			postCheck:   nil,
		},
		{
			name: "invalid contract address format",
			request: &types.QuerySponsorRequest{
				ContractAddress: "invalid-address",
			},
			expectError: true,
			postCheck:   nil,
		},
		{
			name: "non-existent sponsor",
			request: &types.QuerySponsorRequest{
				ContractAddress: suite.contractAddr.String(),
			},
			preRun:      func() {}, // No setup needed - sponsor doesn't exist
			expectError: false,
			postCheck: func(resp *types.QuerySponsorResponse) {
				suite.Require().Nil(resp.Sponsor, "Should return nil for non-existent sponsor")
			},
		},
		{
			name: "existing sponsor",
			request: &types.QuerySponsorRequest{
				ContractAddress: suite.contractAddr.String(),
			},
			preRun: func() {
				// Create a sponsor
				sponsor := types.ContractSponsor{
					ContractAddress: suite.contractAddr.String(),
					CreatorAddress:  suite.admin.String(),
					IsSponsored:     true,
					MaxGrantPerUser: coinsToProtoCoins(suite.maxGrant),
				}
				err := keeper.SetSponsor(freshCtx, sponsor)
				suite.Require().NoError(err)
			},
			expectError: false,
			postCheck: func(resp *types.QuerySponsorResponse) {
				suite.Require().NotNil(resp.Sponsor, "Should return sponsor data")
				suite.Require().Equal(suite.contractAddr.String(), resp.Sponsor.ContractAddress)
				suite.Require().Equal(suite.admin.String(), resp.Sponsor.CreatorAddress)
				suite.Require().True(resp.Sponsor.IsSponsored)
				suite.Require().Equal(len(suite.maxGrant), len(resp.Sponsor.MaxGrantPerUser))
			},
		},
	}

	for _, tc := range testCases {
		suite.Run(tc.name, func() {
			// Reset state for each test
			suite.SetupTest()

			if tc.preRun != nil {
				tc.preRun()
			}

			resp, err := queryServer.Sponsor(ctx, tc.request)

			if tc.expectError {
				suite.Require().Error(err)
				suite.Require().Nil(resp)
			} else {
				suite.Require().NoError(err)
				suite.Require().NotNil(resp)

				if tc.postCheck != nil {
					tc.postCheck(resp)
				}
			}
		})
	}
}

// TestQueryAllSponsors tests the AllSponsors gRPC query
func (suite *GRPCQueryTestSuite) TestQueryAllSponsors() {
	// Get fresh keeper and context for this test method
	keeper, freshCtx, _ := setupKeeper(suite.T())
	queryServer := NewQueryServer(keeper)
	ctx := sdk.WrapSDKContext(freshCtx)

	testCases := []struct {
		name        string
		request     *types.QueryAllSponsorsRequest
		preRun      func()
		expectError bool
		postCheck   func(*types.QueryAllSponsorsResponse)
	}{
		{
			name:        "nil request",
			request:     nil,
			expectError: true,
			postCheck:   nil,
		},
		{
			name: "empty sponsors list",
			request: &types.QueryAllSponsorsRequest{
				Pagination: nil,
			},
			preRun:      func() {}, // No sponsors created
			expectError: false,
			postCheck: func(resp *types.QueryAllSponsorsResponse) {
				suite.Require().Empty(resp.Sponsors, "Should return empty list")
				suite.Require().NotNil(resp.Pagination, "Pagination should not be nil")
			},
		},
		{
			name: "multiple sponsors",
			request: &types.QueryAllSponsorsRequest{
				Pagination: nil,
			},
			preRun: func() {
				// Create multiple sponsors
				contracts := []string{
					"dora1contract1____________",
					"dora1contract2____________",
					"dora1contract3____________",
				}

				for i, contractAddr := range contracts {
					sponsor := types.ContractSponsor{
						ContractAddress: contractAddr,
						CreatorAddress:  "dora1admin_____________",
						IsSponsored:     i%2 == 0, // Alternate sponsored status
						MaxGrantPerUser: coinsToProtoCoins(sdk.NewCoins(sdk.NewCoin("peaka", sdk.NewInt(1000)))),
					}
					err := keeper.SetSponsor(freshCtx, sponsor)
					suite.Require().NoError(err)
				}
			},
			expectError: false,
			postCheck: func(resp *types.QueryAllSponsorsResponse) {
				suite.Require().Len(resp.Sponsors, 3, "Should return 3 sponsors")
				suite.Require().NotNil(resp.Pagination, "Pagination should not be nil")

				// Check that all sponsors are returned
				contractAddrs := make([]string, len(resp.Sponsors))
				for i, sponsor := range resp.Sponsors {
					contractAddrs[i] = sponsor.ContractAddress
				}
				suite.Require().Contains(contractAddrs, "dora1contract1____________")
			},
		},
		{
			name: "pagination limit",
			request: &types.QueryAllSponsorsRequest{
				Pagination: &query.PageRequest{
					Limit: 2,
				},
			},
			preRun: func() {
				// Create 5 sponsors
				for i := 0; i < 5; i++ {
					contractAddr := fmt.Sprintf("dora1contract%d_____________", i)
					sponsor := types.ContractSponsor{
						ContractAddress: contractAddr,
						CreatorAddress:  suite.admin.String(),
						IsSponsored:     true,
						MaxGrantPerUser: coinsToProtoCoins(suite.maxGrant),
					}
					err := keeper.SetSponsor(freshCtx, sponsor)
					suite.Require().NoError(err)
				}
			},
			expectError: false,
			postCheck: func(resp *types.QueryAllSponsorsResponse) {
				suite.Require().LessOrEqual(len(resp.Sponsors), 2, "Should respect pagination limit")
				suite.Require().NotNil(resp.Pagination, "Pagination should not be nil")
			},
		},
	}

	for _, tc := range testCases {
		suite.Run(tc.name, func() {
			suite.SetupTest()

			if tc.preRun != nil {
				tc.preRun()
			}

			resp, err := queryServer.AllSponsors(ctx, tc.request)

			if tc.expectError {
				suite.Require().Error(err)
				suite.Require().Nil(resp)
			} else {
				suite.Require().NoError(err)
				suite.Require().NotNil(resp)

				if tc.postCheck != nil {
					tc.postCheck(resp)
				}
			}
		})
	}
}

// TestQueryParams tests the Params gRPC query
func (suite *GRPCQueryTestSuite) TestQueryParams() {
	// Get fresh keeper and context for this test method
	keeper, freshCtx, _ := setupKeeper(suite.T())
	queryServer := NewQueryServer(keeper)
	ctx := sdk.WrapSDKContext(freshCtx)

	testCases := []struct {
		name        string
		request     *types.QueryParamsRequest
		preRun      func()
		expectError bool
		postCheck   func(*types.QueryParamsResponse)
	}{
		{
			name:        "nil request",
			request:     nil,
			expectError: true,
			postCheck:   nil,
		},
		{
			name:    "default params",
			request: &types.QueryParamsRequest{},
			preRun: func() {
				// Set default params
				params := types.DefaultParams()
				keeper.SetParams(freshCtx, params)
			},
			expectError: false,
			postCheck: func(resp *types.QueryParamsResponse) {
				suite.Require().NotNil(resp.Params, "Params should not be nil")
				suite.Require().True(resp.Params.SponsorshipEnabled, "Default should have sponsorship enabled")
				suite.Require().Equal(uint64(2500000), resp.Params.MaxGasPerSponsorship, "Should have default max gas")
			},
		},
		{
			name:    "custom params",
			request: &types.QueryParamsRequest{},
			preRun: func() {
				// Set custom params
				params := types.Params{
					SponsorshipEnabled:   false,
					MaxGasPerSponsorship: 1000000,
				}
				keeper.SetParams(freshCtx, params)
			},
			expectError: false,
			postCheck: func(resp *types.QueryParamsResponse) {
				suite.Require().NotNil(resp.Params, "Params should not be nil")
				suite.Require().False(resp.Params.SponsorshipEnabled, "Should reflect custom setting")
				suite.Require().Equal(uint64(1000000), resp.Params.MaxGasPerSponsorship, "Should reflect custom gas limit")
			},
		},
	}

	for _, tc := range testCases {
		suite.Run(tc.name, func() {
			suite.SetupTest()

			if tc.preRun != nil {
				tc.preRun()
			}

			resp, err := queryServer.Params(ctx, tc.request)

			if tc.expectError {
				suite.Require().Error(err)
				suite.Require().Nil(resp)
			} else {
				suite.Require().NoError(err)
				suite.Require().NotNil(resp)

				if tc.postCheck != nil {
					tc.postCheck(resp)
				}
			}
		})
	}
}

// TestQueryUserGrantUsage tests the UserGrantUsage gRPC query
func (suite *GRPCQueryTestSuite) TestQueryUserGrantUsage() {
	// Get fresh keeper and context for this test method
	keeper, freshCtx, _ := setupKeeper(suite.T())
	queryServer := NewQueryServer(keeper)
	ctx := sdk.WrapSDKContext(freshCtx)

	testCases := []struct {
		name        string
		request     *types.QueryUserGrantUsageRequest
		preRun      func()
		expectError bool
		postCheck   func(*types.QueryUserGrantUsageResponse)
	}{
		{
			name:        "nil request",
			request:     nil,
			expectError: true,
			postCheck:   nil,
		},
		{
			name: "empty user address",
			request: &types.QueryUserGrantUsageRequest{
				UserAddress:     "",
				ContractAddress: suite.contractAddr.String(),
			},
			expectError: true,
			postCheck:   nil,
		},
		{
			name: "empty contract address",
			request: &types.QueryUserGrantUsageRequest{
				UserAddress:     suite.user.String(),
				ContractAddress: "",
			},
			expectError: true,
			postCheck:   nil,
		},
		{
			name: "invalid user address",
			request: &types.QueryUserGrantUsageRequest{
				UserAddress:     "invalid-address",
				ContractAddress: suite.contractAddr.String(),
			},
			expectError: true,
			postCheck:   nil,
		},
		{
			name: "invalid contract address",
			request: &types.QueryUserGrantUsageRequest{
				UserAddress:     suite.user.String(),
				ContractAddress: "invalid-address",
			},
			expectError: true,
			postCheck:   nil,
		},
		{
			name: "new user usage (no prior usage)",
			request: &types.QueryUserGrantUsageRequest{
				UserAddress:     suite.user.String(),
				ContractAddress: suite.contractAddr.String(),
			},
			preRun:      func() {}, // No prior usage setup
			expectError: false,
			postCheck: func(resp *types.QueryUserGrantUsageResponse) {
				suite.Require().NotNil(resp.Usage, "Usage should not be nil")
				suite.Require().Equal(suite.user.String(), resp.Usage.UserAddress)
				suite.Require().Equal(suite.contractAddr.String(), resp.Usage.ContractAddress)
				suite.Require().Empty(resp.Usage.TotalGrantUsed, "Should have no prior usage")
				suite.Require().Equal(int64(0), resp.Usage.LastUsedTime, "Should have zero last used time")
			},
		},
		{
			name: "existing user usage",
			request: &types.QueryUserGrantUsageRequest{
				UserAddress:     suite.user.String(),
				ContractAddress: suite.contractAddr.String(),
			},
			preRun: func() {
				// Create some usage
				consumedAmount := suite.maxGrant
				err := keeper.UpdateUserGrantUsage(freshCtx, suite.user.String(), suite.contractAddr.String(), consumedAmount)
				suite.Require().NoError(err)
			},
			expectError: false,
			postCheck: func(resp *types.QueryUserGrantUsageResponse) {
				suite.Require().NotNil(resp.Usage, "Usage should not be nil")
				suite.Require().Equal(suite.user.String(), resp.Usage.UserAddress)
				suite.Require().Equal(suite.contractAddr.String(), resp.Usage.ContractAddress)
				suite.Require().NotEmpty(resp.Usage.TotalGrantUsed, "Should have usage data")
				suite.Require().NotEqual(resp.Usage.LastUsedTime, int64(0), "Should have updated last used time")
			},
		},
	}

	for _, tc := range testCases {
		suite.Run(tc.name, func() {
			suite.SetupTest()

			if tc.preRun != nil {
				tc.preRun()
			}

			resp, err := queryServer.UserGrantUsage(ctx, tc.request)

			if tc.expectError {
				suite.Require().Error(err)
				suite.Require().Nil(resp)
			} else {
				suite.Require().NoError(err)
				suite.Require().NotNil(resp)

				if tc.postCheck != nil {
					tc.postCheck(resp)
				}
			}
		})
	}
}


// TestQueryServerInterface tests that QueryServer implements the required interface
func (suite *GRPCQueryTestSuite) TestQueryServerInterface() {
	// Get fresh keeper and context for this test method
	keeper, freshCtx, _ := setupKeeper(suite.T())
	queryServer := NewQueryServer(keeper)

	// Ensure the query server implements the required interface
	var _ types.QueryServer = queryServer

	// Test that all methods are callable
	ctx := sdk.WrapSDKContext(freshCtx)

	// Test Sponsor method signature
	_, err := queryServer.Sponsor(ctx, &types.QuerySponsorRequest{
		ContractAddress: suite.contractAddr.String(),
	})
	suite.Require().NoError(err)

	// Test AllSponsors method signature
	_, err = queryServer.AllSponsors(ctx, &types.QueryAllSponsorsRequest{})
	suite.Require().NoError(err)

	// Test Params method signature
	_, err = queryServer.Params(ctx, &types.QueryParamsRequest{})
	suite.Require().NoError(err)

	// Test UserGrantUsage method signature
	_, err = queryServer.UserGrantUsage(ctx, &types.QueryUserGrantUsageRequest{
		UserAddress:     suite.user.String(),
		ContractAddress: suite.contractAddr.String(),
	})
	suite.Require().NoError(err)
}

// TestQueryErrorHandling tests comprehensive error handling in queries
func (suite *GRPCQueryTestSuite) TestQueryErrorHandling() {
	// Get fresh keeper and context for this test method
	keeper, freshCtx, _ := setupKeeper(suite.T())
	queryServer := NewQueryServer(keeper)
	ctx := sdk.WrapSDKContext(freshCtx)

	// Test various error conditions
	errorTests := []struct {
		name        string
		queryFunc   func() error
		expectedErr string
	}{
		{
			name: "sponsor query with nil request",
			queryFunc: func() error {
				_, err := queryServer.Sponsor(ctx, nil)
				return err
			},
			expectedErr: "invalid request",
		},
		{
			name: "all sponsors query with nil request",
			queryFunc: func() error {
				_, err := queryServer.AllSponsors(ctx, nil)
				return err
			},
			expectedErr: "invalid request",
		},
		{
			name: "params query with nil request",
			queryFunc: func() error {
				_, err := queryServer.Params(ctx, nil)
				return err
			},
			expectedErr: "invalid request",
		},
		{
			name: "user grant usage query with nil request",
			queryFunc: func() error {
				_, err := queryServer.UserGrantUsage(ctx, nil)
				return err
			},
			expectedErr: "invalid request",
		},
	}

	for _, test := range errorTests {
		suite.Run(test.name, func() {
			err := test.queryFunc()
			suite.Require().Error(err, "Should return error for %s", test.name)
			suite.Require().Contains(err.Error(), test.expectedErr, "Should contain expected error message")
		})
	}
}

func TestGRPCQueryTestSuite(t *testing.T) {
	suite.Run(t, new(GRPCQueryTestSuite))
}
