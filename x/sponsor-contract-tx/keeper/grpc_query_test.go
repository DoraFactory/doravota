package keeper

import (
    "fmt"
    "testing"

    sdk "github.com/cosmos/cosmos-sdk/types"
    "github.com/cosmos/cosmos-sdk/types/query"
    "github.com/cosmos/cosmos-sdk/types/address"
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

func (suite *GRPCQueryTestSuite) TestQuerySponsorEffectiveTTL() {
    keeper, freshCtx, _ := setupKeeper(suite.T())
    queryServer := NewQueryServer(keeper)
    // Set params with default TTL 30 and cap 60
    params := types.DefaultParams()
    params.PolicyTicketTtlBlocks = 30
    params.MaxMethodTicketUsesPerIssue = 3
    // removed ttl max param
    suite.Require().NoError(keeper.SetParams(freshCtx, params))
    // Sponsor without override
    contract := sdk.AccAddress([]byte("contract_ttlq_______________")).String()
    suite.Require().NoError(keeper.SetSponsor(freshCtx, types.ContractSponsor{ContractAddress: contract, IsSponsored: true}))
    resp, err := queryServer.Sponsor(sdk.WrapSDKContext(freshCtx), &types.QuerySponsorRequest{ContractAddress: contract})
    suite.Require().NoError(err)
    suite.Require().Equal(uint32(30), resp.EffectiveTicketTtlBlocks)
    // Update module default TTL to 50 -> expect 50
    params.PolicyTicketTtlBlocks = 50
    suite.Require().NoError(keeper.SetParams(freshCtx, params))
    resp, err = queryServer.Sponsor(sdk.WrapSDKContext(freshCtx), &types.QuerySponsorRequest{ContractAddress: contract})
    suite.Require().NoError(err)
    suite.Require().Equal(uint32(50), resp.EffectiveTicketTtlBlocks)
}

func (suite *GRPCQueryTestSuite) TestQueryPolicyTicketAndNegativeProbeAndWindow() {
    keeper, freshCtx, _ := setupKeeper(suite.T())
    queryServer := NewQueryServer(keeper)
    ctx := sdk.WrapSDKContext(freshCtx)

    // Prepare data
    contract := sdk.AccAddress([]byte("contract_ticket______________")).String()
    user := sdk.AccAddress([]byte("user_ticket___________________")).String()
    // Ticket
    tkt := types.PolicyTicket{
        ContractAddress: contract,
        UserAddress:     user,
        Digest:          "abcd",
        ExpiryHeight:    100,
        Consumed:        false,
        IssuedHeight:    1,
        UsesRemaining:   1,
    }
    suite.Require().NoError(keeper.SetPolicyTicket(freshCtx, tkt))
    // Negative probe cache
    // negative probe removed
    // Probe window usage
    // probe window removed
    // Params for window
    // window params removed

    // PolicyTicket query
    respT, err := queryServer.PolicyTicket(ctx, &types.QueryPolicyTicketRequest{ContractAddress: contract, UserAddress: user, Digest: "abcd"})
    suite.Require().NoError(err)
    suite.Require().NotNil(respT.Ticket)
    suite.Require().Equal(uint64(100), respT.Ticket.ExpiryHeight)
    suite.Require().Equal(uint64(100-uint64(freshCtx.BlockHeight())), respT.TtlLeft)

    // Removed negative probe status and probe window usage queries
}

func (suite *GRPCQueryTestSuite) TestQueryPolicyTicketByMethod() {
    keeper, freshCtx, _ := setupKeeper(suite.T())
    queryServer := NewQueryServer(keeper)
    ctx := sdk.WrapSDKContext(freshCtx)

    contract := sdk.AccAddress([]byte("contract_by_method__________")).String()
    user := sdk.AccAddress([]byte("user_by_method______________")).String()
    method := "inc"
    // Insert ticket for method digest
    md := keeper.ComputeMethodDigest(contract, []string{method})
    tkt := types.PolicyTicket{ContractAddress: contract, UserAddress: user, Digest: md, ExpiryHeight: uint64(freshCtx.BlockHeight()+50), UsesRemaining: 1}
    suite.Require().NoError(keeper.SetPolicyTicket(freshCtx, tkt))

    // Success case
    resp, err := queryServer.PolicyTicketByMethod(ctx, &types.QueryPolicyTicketByMethodRequest{ContractAddress: contract, UserAddress: user, Method: method})
    suite.Require().NoError(err)
    suite.Require().NotNil(resp.Ticket)
    suite.Require().Equal(md, resp.Ticket.Digest)

    // Not found case (different method)
    resp2, err := queryServer.PolicyTicketByMethod(ctx, &types.QueryPolicyTicketByMethodRequest{ContractAddress: contract, UserAddress: user, Method: "dec"})
    suite.Require().NoError(err)
    suite.Require().Nil(resp2.Ticket)

    // Invalid inputs
    _, err = queryServer.PolicyTicketByMethod(ctx, &types.QueryPolicyTicketByMethodRequest{ContractAddress: "invalid", UserAddress: user, Method: method})
    suite.Require().Error(err)
    _, err = queryServer.PolicyTicketByMethod(ctx, &types.QueryPolicyTicketByMethodRequest{ContractAddress: contract, UserAddress: "invalid", Method: method})
    suite.Require().Error(err)
    _, err = queryServer.PolicyTicketByMethod(ctx, &types.QueryPolicyTicketByMethodRequest{ContractAddress: contract, UserAddress: user, Method: ""})
    suite.Require().Error(err)
}

// Dedicated tests for PolicyTickets pagination behavior
func (suite *GRPCQueryTestSuite) TestPolicyTicketsQuery_Pagination() {
    keeper, freshCtx, _ := setupKeeper(suite.T())
    q := NewQueryServer(keeper)
    ctx := sdk.WrapSDKContext(freshCtx)
    contract := sdk.AccAddress([]byte("contract_pag______________")).String()
    user := sdk.AccAddress([]byte("user_pag___________________")).String()
    // Insert 3 tickets
    for i := 0; i < 3; i++ {
        d := fmt.Sprintf("d%d", i+1)
        t := types.PolicyTicket{ContractAddress: contract, UserAddress: user, Digest: d, ExpiryHeight: uint64(freshCtx.BlockHeight()+100), UsesRemaining: 1}
        suite.Require().NoError(keeper.SetPolicyTicket(freshCtx, t))
    }
    // Page 1: limit 1
    resp1, err := q.PolicyTickets(ctx, &types.QueryPolicyTicketsRequest{ContractAddress: contract, Pagination: &query.PageRequest{Limit: 1}})
    suite.Require().NoError(err)
    suite.Require().Len(resp1.Tickets, 1)
    // Page 2 using page key
    resp2, err := q.PolicyTickets(ctx, &types.QueryPolicyTicketsRequest{ContractAddress: contract, Pagination: &query.PageRequest{Key: resp1.Pagination.NextKey, Limit: 1}})
    suite.Require().NoError(err)
    suite.Require().Len(resp2.Tickets, 1)
    suite.Require().NotEqual(resp1.Tickets[0].Digest, resp2.Tickets[0].Digest)
}

// Dedicated tests for PolicyTickets user filter behavior
func (suite *GRPCQueryTestSuite) TestPolicyTicketsQuery_UserFilter() {
    keeper, freshCtx, _ := setupKeeper(suite.T())
    q := NewQueryServer(keeper)
    ctx := sdk.WrapSDKContext(freshCtx)
    contract := sdk.AccAddress([]byte("contract_flt______________")).String()
    u1 := sdk.AccAddress([]byte("user_flt_1_________________")).String()
    u2 := sdk.AccAddress([]byte("user_flt_2_________________")).String()
    // Insert tickets for two users
    suite.Require().NoError(keeper.SetPolicyTicket(freshCtx, types.PolicyTicket{ContractAddress: contract, UserAddress: u1, Digest: "a", ExpiryHeight: 100, UsesRemaining: 1}))
    suite.Require().NoError(keeper.SetPolicyTicket(freshCtx, types.PolicyTicket{ContractAddress: contract, UserAddress: u1, Digest: "b", ExpiryHeight: 100, UsesRemaining: 1}))
    suite.Require().NoError(keeper.SetPolicyTicket(freshCtx, types.PolicyTicket{ContractAddress: contract, UserAddress: u2, Digest: "c", ExpiryHeight: 100, UsesRemaining: 1}))
    // Query for user1 only
    resp, err := q.PolicyTickets(ctx, &types.QueryPolicyTicketsRequest{ContractAddress: contract, UserAddress: u1})
    suite.Require().NoError(err)
    suite.Require().Len(resp.Tickets, 2)
    for _, t := range resp.Tickets {
        suite.Require().Equal(u1, t.UserAddress)
    }
}

// TestQueryPolicyTickets tests listing tickets with and without user filter, and pagination bounds
func (suite *GRPCQueryTestSuite) TestQueryPolicyTickets() {
    keeper, freshCtx, _ := setupKeeper(suite.T())
    queryServer := NewQueryServer(keeper)
    ctx := sdk.WrapSDKContext(freshCtx)

    // Prepare data under one contract
    contract := sdk.AccAddress([]byte("contract_list______________")).String()
    user1 := sdk.AccAddress([]byte("user_list_1________________")).String()
    user2 := sdk.AccAddress([]byte("user_list_2________________")).String()
    // Insert several tickets
    t1 := types.PolicyTicket{ContractAddress: contract, UserAddress: user1, Digest: "d1", ExpiryHeight: 100, UsesRemaining: 1}
    t2 := types.PolicyTicket{ContractAddress: contract, UserAddress: user1, Digest: "d2", ExpiryHeight: 100, UsesRemaining: 2}
    t3 := types.PolicyTicket{ContractAddress: contract, UserAddress: user2, Digest: "d3", ExpiryHeight: 100, UsesRemaining: 3}
    suite.Require().NoError(keeper.SetPolicyTicket(freshCtx, t1))
    suite.Require().NoError(keeper.SetPolicyTicket(freshCtx, t2))
    suite.Require().NoError(keeper.SetPolicyTicket(freshCtx, t3))

    // 1) List by contract only: expect at least 3 items
    respAll, err := queryServer.PolicyTickets(ctx, &types.QueryPolicyTicketsRequest{ContractAddress: contract})
    suite.Require().NoError(err)
    suite.Require().NotNil(respAll)
    suite.Require().GreaterOrEqual(len(respAll.Tickets), 3)

    // 2) List by contract + user1: expect exactly 2 items
    respU1, err := queryServer.PolicyTickets(ctx, &types.QueryPolicyTicketsRequest{ContractAddress: contract, UserAddress: user1})
    suite.Require().NoError(err)
    suite.Require().NotNil(respU1)
    suite.Require().Equal(2, len(respU1.Tickets))

    // 3) Pagination: limit 1 should return at most 1 item
    respPage, err := queryServer.PolicyTickets(ctx, &types.QueryPolicyTicketsRequest{ContractAddress: contract, Pagination: &query.PageRequest{Limit: 1}})
    suite.Require().NoError(err)
    suite.Require().NotNil(respPage)
    suite.Require().LessOrEqual(len(respPage.Tickets), 1)

    // 4) Invalid contract address -> error
    _, err = queryServer.PolicyTickets(ctx, &types.QueryPolicyTicketsRequest{ContractAddress: "invalid"})
    suite.Require().Error(err)

    // 5) Invalid user address -> error
    _, err = queryServer.PolicyTickets(ctx, &types.QueryPolicyTicketsRequest{ContractAddress: contract, UserAddress: "invalid"})
    suite.Require().Error(err)
}

// Removed compute-digest query test

// TestQueryParams tests the Params gRPC query
func (suite *GRPCQueryTestSuite) TestQueryParams() {
	// Get fresh keeper and context for this test method
	keeper, freshCtx, _ := setupKeeper(suite.T())
	queryServer := NewQueryServer(keeper)
    ctx := sdk.WrapSDKContext(freshCtx)
    // Set custom params then query via gRPC
    custom := types.DefaultParams()
    custom.SponsorshipEnabled = false
    custom.PolicyTicketTtlBlocks = 77
    custom.MaxExecMsgsPerTxForSponsor = 9
    custom.MaxPolicyExecMsgBytes = 8192
    custom.MaxMethodTicketUsesPerIssue = 5
    custom.TicketGcPerBlock = 123
    custom.MaxMethodNameBytes = 40
    custom.MaxMethodJsonDepth = 33
    suite.Require().NoError(keeper.SetParams(freshCtx, custom))
    resp, err := queryServer.Params(ctx, &types.QueryParamsRequest{})
    suite.Require().NoError(err)
    suite.Require().NotNil(resp)
    suite.Require().False(resp.Params.SponsorshipEnabled)
    suite.Require().Equal(uint32(77), resp.Params.PolicyTicketTtlBlocks)
    suite.Require().Equal(uint32(9), resp.Params.MaxExecMsgsPerTxForSponsor)
    suite.Require().Equal(uint32(8192), resp.Params.MaxPolicyExecMsgBytes)
    suite.Require().Equal(uint32(5), resp.Params.MaxMethodTicketUsesPerIssue)
    suite.Require().Equal(uint32(123), resp.Params.TicketGcPerBlock)
    suite.Require().Equal(uint32(40), resp.Params.MaxMethodNameBytes)
    suite.Require().Equal(uint32(33), resp.Params.MaxMethodJsonDepth)

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
                suite.Require().Equal(uint32(30), resp.Params.PolicyTicketTtlBlocks, "Should have default ticket TTL")
            },
		},
		{
			name:    "custom params",
			request: &types.QueryParamsRequest{},
            preRun: func() {
                // Set custom params
                params := types.Params{
                    SponsorshipEnabled:    false,
                    PolicyTicketTtlBlocks: 42,
                }
                keeper.SetParams(freshCtx, params)
            },
			expectError: false,
            postCheck: func(resp *types.QueryParamsResponse) {
                suite.Require().NotNil(resp.Params, "Params should not be nil")
                suite.Require().False(resp.Params.SponsorshipEnabled, "Should reflect custom setting")
                suite.Require().Equal(uint32(42), resp.Params.PolicyTicketTtlBlocks, "Should reflect custom TTL")
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

func (suite *GRPCQueryTestSuite) TestQuerySponsorBalance() {
    // Use setup with dependencies to have bank keeper
    keeper, freshCtx, _, accountKeeper, bankKeeper := setupKeeperWithDeps(suite.T())
    // create query server with deps
    queryServer := NewQueryServerWithDeps(keeper, bankKeeper)
    ctx := sdk.WrapSDKContext(freshCtx)

    // Prepare contract and sponsor
    contract := sdk.AccAddress([]byte("contract_bal________________")).String()
    admin := sdk.AccAddress([]byte("admin_bal___________________")).String()
    // Wire a sponsor record
    suite.Require().NoError(keeper.SetSponsor(freshCtx, types.ContractSponsor{ContractAddress: contract, CreatorAddress: admin, IsSponsored: true}))
    // Derive sponsor address and create account
    ca, _ := sdk.AccAddressFromBech32(contract)
    sponsorAddr := sdk.AccAddress(address.Derive(ca, []byte("sponsor")))
    // ensure account exists (optional)
    if accountKeeper.GetAccount(freshCtx, sponsorAddr) == nil {
        accountKeeper.SetAccount(freshCtx, accountKeeper.NewAccountWithAddress(freshCtx, sponsorAddr))
    }
    // Fund sponsor with 123 peaka spendable
    coins := sdk.NewCoins(sdk.NewCoin(types.SponsorshipDenom, sdk.NewInt(123)))
    suite.Require().NoError(bankKeeper.MintCoins(freshCtx, types.ModuleName, coins))
    suite.Require().NoError(bankKeeper.SendCoinsFromModuleToAccount(freshCtx, types.ModuleName, sponsorAddr, coins))

    // Query balance
    resp, err := queryServer.SponsorBalance(ctx, &types.QuerySponsorBalanceRequest{ContractAddress: contract})
    suite.Require().NoError(err)
    suite.Require().Equal(sponsorAddr.String(), resp.SponsorAddress)
    suite.Require().Equal(types.SponsorshipDenom, resp.Spendable.Denom)
    suite.Require().Equal("123", resp.Spendable.Amount.String())

    // Invalid contract
    _, err = queryServer.SponsorBalance(ctx, &types.QuerySponsorBalanceRequest{ContractAddress: "invalid"})
    suite.Require().Error(err)
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
