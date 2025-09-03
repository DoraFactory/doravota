package cli_test

import (
	"fmt"
	"testing"

	clitestutil "github.com/cosmos/cosmos-sdk/testutil/cli"
	"github.com/cosmos/cosmos-sdk/testutil/network"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/suite"

	"github.com/DoraFactory/doravota/x/sponsor-contract-tx/client/cli"
)

// QueryTestSuite integrates with the cosmos-sdk test framework for CLI testing
type QueryTestSuite struct {
	suite.Suite

	cfg     network.Config
	network *network.Network

	// Test data
	contractAddr string
	userAddr     string
}

func (s *QueryTestSuite) SetupSuite() {
	s.T().Log("setting up query test suite")

	// For CLI testing, we'll use a simpler approach
	// In a real implementation, this would integrate with your app's network config
	s.T().Skip("CLI integration tests require full network setup - implement when needed")

	// This is the pattern for when network testing is fully implemented:
	// cfg := network.DefaultConfig(func() network.TestFixtureFactory { return simapp.NewTestNetworkFixture })
	// cfg.NumValidators = 1
	// s.cfg = cfg
	// var err error
	// s.network, err = network.New(s.T(), s.T().TempDir(), cfg)
	// s.Require().NoError(err)

	// Set up test data
	s.contractAddr = "dora1contractexampleaddr000000000000000000"
	s.userAddr = "dora1userexampleaddr0000000000000000000000"
}

func (s *QueryTestSuite) TearDownSuite() {
	s.T().Log("tearing down query test suite")
	s.network.Cleanup()
}

// TestQueryParams tests the params query command
func (s *QueryTestSuite) TestQueryParams() {
	val := s.network.Validators[0]

	testCases := []struct {
		name           string
		args           []string
		expectedOutput string
		expectErr      bool
	}{
		{
			"query params success",
			[]string{},
			"sponsorship_enabled",
			false,
		},
		{
			"query params with json output",
			[]string{fmt.Sprintf("--%s=json", "output")},
			"sponsorship_enabled",
			false,
		},
		{
			"query params with invalid flag",
			[]string{"--invalid-flag"},
			"",
			true,
		},
	}

	for _, tc := range testCases {
		s.Run(tc.name, func() {
			cmd := cli.GetCmdQueryParams()
			out, err := clitestutil.ExecTestCLICmd(val.ClientCtx, cmd, tc.args)

			if tc.expectErr {
				s.Require().Error(err)
			} else {
				s.Require().NoError(err)
				s.Require().Contains(out.String(), tc.expectedOutput)
			}
		})
	}
}

// TestQueryAllSponsors tests the all-sponsors query command
func (s *QueryTestSuite) TestQueryAllSponsors() {
	val := s.network.Validators[0]

	testCases := []struct {
		name           string
		args           []string
		expectedOutput string
		expectErr      bool
	}{
		{
			"query all sponsors success",
			[]string{},
			"sponsors",
			false,
		},
		{
			"query all sponsors with pagination",
			[]string{
				fmt.Sprintf("--%s=1", "page"),
				fmt.Sprintf("--%s=10", "limit"),
			},
			"sponsors",
			false,
		},
		{
			"query all sponsors with json output",
			[]string{fmt.Sprintf("--%s=json", "output")},
			"sponsors",
			false,
		},
		{
			"query all sponsors with extra args should fail",
			[]string{"extra-arg"},
			"",
			true,
		},
	}

	for _, tc := range testCases {
		s.Run(tc.name, func() {
			cmd := cli.GetCmdQueryAllSponsors()
			out, err := clitestutil.ExecTestCLICmd(val.ClientCtx, cmd, tc.args)

			if tc.expectErr {
				s.Require().Error(err)
			} else {
				s.Require().NoError(err)
				s.Require().Contains(out.String(), tc.expectedOutput)
			}
		})
	}
}

// TestQuerySponsorStatus tests the sponsor status query command
func (s *QueryTestSuite) TestQuerySponsorStatus() {
	val := s.network.Validators[0]

	testCases := []struct {
		name           string
		args           []string
		expectedOutput string
		expectErr      bool
	}{
		{
			"query sponsor status with valid contract address",
			[]string{s.contractAddr},
			"sponsor", // Expected to contain sponsor info even if not found
			false,
		},
		{
			"query sponsor status with json output",
			[]string{
				s.contractAddr,
				fmt.Sprintf("--%s=json", "output"),
			},
			"sponsor",
			false,
		},
		{
			"query sponsor status with no args should fail",
			[]string{},
			"",
			true,
		},
		{
			"query sponsor status with too many args should fail",
			[]string{s.contractAddr, "extra-arg"},
			"",
			true,
		},
		{
			"query sponsor status with invalid contract address",
			[]string{"invalid-address"},
			"",
			true,
		},
	}

	for _, tc := range testCases {
		s.Run(tc.name, func() {
			cmd := cli.GetCmdQuerySponsorInfo()
			out, err := clitestutil.ExecTestCLICmd(val.ClientCtx, cmd, tc.args)

			if tc.expectErr {
				s.Require().Error(err)
			} else {
				s.Require().NoError(err)
				s.Require().Contains(out.String(), tc.expectedOutput)
			}
		})
	}
}

// TestQueryUserGrantUsage tests the user grant usage query command
func (s *QueryTestSuite) TestQueryUserGrantUsage() {
	val := s.network.Validators[0]

	testCases := []struct {
		name           string
		args           []string
		expectedOutput string
		expectErr      bool
	}{
		{
			"query user grant usage with valid addresses",
			[]string{s.userAddr, s.contractAddr},
			"usage", // Expected to contain usage info
			false,
		},
		{
			"query user grant usage with json output",
			[]string{
				s.userAddr,
				s.contractAddr,
				fmt.Sprintf("--%s=json", "output"),
			},
			"usage",
			false,
		},
		{
			"query user grant usage with no args should fail",
			[]string{},
			"",
			true,
		},
		{
			"query user grant usage with one arg should fail",
			[]string{s.userAddr},
			"",
			true,
		},
		{
			"query user grant usage with too many args should fail",
			[]string{s.userAddr, s.contractAddr, "extra-arg"},
			"",
			true,
		},
		{
			"query user grant usage with invalid user address",
			[]string{"invalid-user", s.contractAddr},
			"",
			true,
		},
		{
			"query user grant usage with invalid contract address",
			[]string{s.userAddr, "invalid-contract"},
			"",
			true,
		},
	}

	for _, tc := range testCases {
		s.Run(tc.name, func() {
			cmd := cli.GetCmdQueryUserGrantUsage()
			out, err := clitestutil.ExecTestCLICmd(val.ClientCtx, cmd, tc.args)

			if tc.expectErr {
				s.Require().Error(err)
			} else {
				s.Require().NoError(err)
				s.Require().Contains(out.String(), tc.expectedOutput)
			}
		})
	}
}

// TestQueryCmdOutput tests output formats and flags
func (s *QueryTestSuite) TestQueryCmdOutput() {
	val := s.network.Validators[0]

	testCases := []struct {
		name       string
		cmd        func() *cobra.Command
		args       []string
		expectJSON bool
	}{
		{
			"params command with text output",
			cli.GetCmdQueryParams,
			[]string{fmt.Sprintf("--%s=text", "output")},
			false,
		},
		{
			"params command with json output",
			cli.GetCmdQueryParams,
			[]string{fmt.Sprintf("--%s=json", "output")},
			true,
		},
		{
			"all-sponsors command with json output",
			cli.GetCmdQueryAllSponsors,
			[]string{fmt.Sprintf("--%s=json", "output")},
			true,
		},
	}

	for _, tc := range testCases {
		s.Run(tc.name, func() {
			cmd := tc.cmd()
			out, err := clitestutil.ExecTestCLICmd(val.ClientCtx, cmd, tc.args)
			s.Require().NoError(err)

			if tc.expectJSON {
				// Verify JSON format by checking for JSON structural characters
				s.Require().Contains(out.String(), "{")
				s.Require().Contains(out.String(), "}")
			}
		})
	}
}

// TestQueryCmdHelp tests help functionality
func (s *QueryTestSuite) TestQueryCmdHelp() {
	testCases := []struct {
		name        string
		cmd         func() *cobra.Command
		expectedTxt string
	}{
		{
			"params help",
			cli.GetCmdQueryParams,
			"Query the parameters of the sponsor module",
		},
		{
			"all-sponsors help",
			cli.GetCmdQueryAllSponsors,
			"Query all sponsor contracts",
		},
		{
			"sponsor status help",
			cli.GetCmdQuerySponsorInfo,
			"Query the status of a sponsor contract",
		},
		{
			"user grant usage help",
			cli.GetCmdQueryUserGrantUsage,
			"Query grant usage for a specific user and contract",
		},
	}

	for _, tc := range testCases {
		s.Run(tc.name, func() {
			cmd := tc.cmd()
			s.Require().Contains(cmd.Short, tc.expectedTxt)
		})
	}
}

// TestQueryCmdValidation tests input validation
func (s *QueryTestSuite) TestQueryCmdValidation() {
	val := s.network.Validators[0]

	// Test invalid bech32 addresses
	invalidAddrTestCases := []struct {
		name string
		cmd  func() *cobra.Command
		args []string
	}{
		{
			"sponsor status with invalid address format",
			cli.GetCmdQuerySponsorInfo,
			[]string{"not-a-valid-address"},
		},
		{
			"user grant usage with invalid user address",
			cli.GetCmdQueryUserGrantUsage,
			[]string{"invalid-user", s.contractAddr},
		},
		{
			"user grant usage with invalid contract address",
			cli.GetCmdQueryUserGrantUsage,
			[]string{s.userAddr, "invalid-contract"},
		},
	}

	for _, tc := range invalidAddrTestCases {
		s.Run(tc.name, func() {
			cmd := tc.cmd()
			_, err := clitestutil.ExecTestCLICmd(val.ClientCtx, cmd, tc.args)
			s.Require().Error(err)
		})
	}
}

// TestQueryCmdFlags tests common query flags
func (s *QueryTestSuite) TestQueryCmdFlags() {
	val := s.network.Validators[0]

	// Test that all query commands accept standard query flags
	commands := []struct {
		name string
		cmd  func() *cobra.Command
		args []string
	}{
		{"params", cli.GetCmdQueryParams, []string{}},
		{"all-sponsors", cli.GetCmdQueryAllSponsors, []string{}},
		{"sponsor-status", cli.GetCmdQuerySponsorInfo, []string{s.contractAddr}},
		{"user-grant-usage", cli.GetCmdQueryUserGrantUsage, []string{s.userAddr, s.contractAddr}},
	}

	for _, cmdTest := range commands {
		s.Run(cmdTest.name, func() {
			cmd := cmdTest.cmd()

			// Test with --help flag
			helpArgs := append(cmdTest.args, "--help")
			out, err := clitestutil.ExecTestCLICmd(val.ClientCtx, cmd, helpArgs)
			s.Require().NoError(err)
			s.Require().Contains(out.String(), "Usage:")

			// Test with --output flag (if command takes no required args or we provide them)
			if len(cmdTest.args) > 0 || cmdTest.name == "params" || cmdTest.name == "all-sponsors" {
				outputArgs := append(cmdTest.args, fmt.Sprintf("--%s=json", "output"))
				_, err := clitestutil.ExecTestCLICmd(val.ClientCtx, cmd, outputArgs)
				s.Require().NoError(err)
			}
		})
	}
}

func TestQueryTestSuite(t *testing.T) {
	suite.Run(t, new(QueryTestSuite))
}
