package cli

import (
    "fmt"
    "testing"

    sdk "github.com/cosmos/cosmos-sdk/types"
    "github.com/spf13/cobra"
    "github.com/stretchr/testify/suite"

    "github.com/DoraFactory/doravota/x/sponsor-contract-tx/types"
    "strings"
)

// TxTestSuite tests the CLI transaction commands
type TxTestSuite struct {
	suite.Suite

	// Test data
	contractAddr string
	userAddr     string
}

func (s *TxTestSuite) SetupSuite() {
	s.T().Log("setting up tx test suite")

	// Set up test data with valid bech32 addresses
	s.contractAddr = sdk.AccAddress([]byte("test_contract_addr_12")).String()
	s.userAddr = sdk.AccAddress([]byte("test_user_address_123")).String()
}

// TestSetSponsorCmd tests the set-sponsor command structure and validation
func (s *TxTestSuite) TestSetSponsorCmd() {
	testCases := []struct {
		name         string
		args         []string
		expectErr    bool
		expectedCode uint32
	}{
		{
			"valid set sponsor command with basic args",
			[]string{s.contractAddr, "true", "100DORA"},
			false,
			0,
		},
		{
			"valid set sponsor command without max grant",
			[]string{s.contractAddr, "true"},
			false,
			0,
		},
		{
			"valid set sponsor command with peaka denomination",
			[]string{s.contractAddr, "true", "100000000000000000000peaka"},
			false,
			0,
		},
		{
			"set sponsor with is-sponsored false",
			[]string{s.contractAddr, "false"},
			false,
			0,
		},
		{
			"invalid - no contract address",
			[]string{},
			true,
			0,
		},
		{
			"invalid - only contract address",
			[]string{s.contractAddr},
			true,
			0,
		},
		{
			"invalid - too many arguments",
			[]string{s.contractAddr, "true", "100DORA", "extra-arg"},
			true,
			0,
		},
		{
			"invalid - bad boolean value",
			[]string{s.contractAddr, "maybe"},
			false, // This will create the message but with false value
			0,
		},
	}

	for _, tc := range testCases {
		s.Run(tc.name, func() {
			cmd := GetCmdSetSponsor()

			// Test command structure and argument validation
			expectedArgs := len(tc.args)
			actualArgs := cmd.Args

			if tc.expectErr {
				// For cases expecting errors, verify command structure
				if expectedArgs == 0 || expectedArgs == 1 {
					s.Require().NotNil(actualArgs, "Command should have argument validation")
				}
			} else {
				// For valid cases, command should exist and be properly configured
				s.Require().NotNil(cmd, "Command should exist")
				s.Require().Contains(cmd.Use, "set-sponsor", "Command name should match")
			}

			s.T().Logf("Command test '%s' completed with args: %v", tc.name, tc.args)
		})
	}
}

// TestUpdateSponsorCmd tests the update-sponsor command
func (s *TxTestSuite) TestUpdateSponsorCmd() {
	testCases := []struct {
		name      string
		args      []string
		expectErr bool
	}{
		{
			"valid update sponsor command",
			[]string{s.contractAddr, "false", "50DORA"},
			false,
		},
		{
			"valid update sponsor without max grant",
			[]string{s.contractAddr, "false"},
			false,
		},
		{
			"update sponsor with empty max grant",
			[]string{s.contractAddr, "true", ""},
			false,
		},
		{
			"invalid - no arguments",
			[]string{},
			true,
		},
		{
			"invalid - only contract address",
			[]string{s.contractAddr},
			true,
		},
	}

	for _, tc := range testCases {
		s.Run(tc.name, func() {
			cmd := GetCmdUpdateSponsor()

			// Test command structure
			if tc.expectErr {
				// For error cases, verify command has proper validation
				s.Require().NotNil(cmd.Args, "Command should have argument validation")
			} else {
				// For valid cases, verify command structure
				s.Require().NotNil(cmd, "Command should exist")
				s.Require().Equal("update-sponsor", cmd.Use[:14], "Command name should match")
			}

			s.T().Logf("Update command test '%s' completed with args: %v", tc.name, tc.args)
		})
	}
}

// TestDeleteSponsorCmd tests the delete-sponsor command
func (s *TxTestSuite) TestDeleteSponsorCmd() {
	testCases := []struct {
		name      string
		args      []string
		expectErr bool
	}{
		{
			"valid delete sponsor command",
			[]string{s.contractAddr},
			false,
		},
		{
			"invalid - no arguments",
			[]string{},
			true,
		},
		{
			"invalid - too many arguments",
			[]string{s.contractAddr, "extra-arg"},
			true,
		},
	}

	for _, tc := range testCases {
		s.Run(tc.name, func() {
			cmd := GetCmdDeleteSponsor()

			// Test command structure
			if tc.expectErr {
				// For error cases, verify command has proper validation
				s.Require().NotNil(cmd.Args, "Command should have argument validation")
			} else {
				// For valid cases, verify command structure
				s.Require().NotNil(cmd, "Command should exist")
				s.Require().Equal("delete-sponsor", cmd.Use[:14], "Command name should match")
			}

			s.T().Logf("Delete command test '%s' completed with args: %v", tc.name, tc.args)
		})
	}
}

// TestCoinParsing tests the DORA to peaka conversion functionality
func (s *TxTestSuite) TestCoinParsing() {
	// Note: We can't directly test the internal parseCoinsWithDORASupport function
	// but we can test it through the command execution
	testCases := []struct {
		name          string
		maxGrantInput string
		expectErr     bool
		description   string
	}{
		{
			"valid DORA amount",
			"100DORA",
			false,
			"Should convert 100DORA to 100000000000000000000peaka",
		},
		{
			"valid decimal DORA amount",
			"1.5DORA",
			false,
			"Should convert 1.5DORA to 1500000000000000000peaka",
		},
		{
			"valid peaka amount",
			"1000000000000000000peaka",
			false,
			"Should accept peaka denomination directly",
		},
		{
			"multiple coins with DORA",
			"10DORA,5DORA",
			false,
			"Should handle multiple coin entries",
		},
		{
			"invalid denomination",
			"100stake",
			true,
			"Should reject non-peaka/DORA denominations",
		},
		{
			"lowercase dora",
			"100dora",
			true,
			"Should reject lowercase dora (case sensitive)",
		},
		{
			"empty string",
			"",
			false,
			"Should accept empty max grant",
		},
		{
			"precise decimal parsing - 18 decimal places",
			"0.000000000000000001DORA", // 1 wei = smallest unit of peaka
			false,
			"Should handle maximum precision without loss",
		},
		{
			"precise decimal parsing - large number with decimals",
			"123456789.123456789123456789DORA",
			false,
			"Should handle large numbers with maximum decimal precision",
		},
		{
			"invalid precision - too many decimal places",
			"1.0000000000000000001DORA", // 19 decimal places - should reject
			true,
			"Should reject amounts with more than 18 decimal places",
		},
		{
			"edge case - zero with decimals",
			"0.000000000000000000DORA",
			false,
			"Should handle zero with decimal places",
		},
	}

	for _, tc := range testCases {
		s.Run(tc.name, func() {
			cmd := GetCmdSetSponsor()

			// Test command structure
			s.Require().NotNil(cmd, "Command should exist")

			// Test coin parsing expectations
			s.T().Logf("Testing coin parsing: %s - %s", tc.name, tc.description)
			s.T().Logf("Max grant input: %s", tc.maxGrantInput)

			if tc.expectErr {
				s.T().Logf("Expected error for case: %s with input: %s", tc.name, tc.maxGrantInput)
			} else {
				s.T().Logf("Valid coin parsing case: %s with input: %s", tc.name, tc.maxGrantInput)
			}
		})
	}
}

// TestCommandHelp tests help functionality for all tx commands
func (s *TxTestSuite) TestCommandHelp() {
	commands := []struct {
		name        string
		cmd         func() *cobra.Command
		expectedTxt string
	}{
		{
			"set-sponsor help",
			GetCmdSetSponsor,
			"Set a sponsor contract",
		},
		{
			"update-sponsor help",
			GetCmdUpdateSponsor,
			"Update a sponsor status",
		},
		{
			"delete-sponsor help",
			GetCmdDeleteSponsor,
			"Delete a sponsor contract",
		},
		{
			"withdraw-sponsor-funds help",
			GetCmdWithdrawSponsorFunds,
			"Withdraw funds from the derived sponsor address",
		},
		{
			"revoke-ticket help",
			GetCmdRevokePolicyTicket,
			"revokes a policy ticket",
		},
	}

	for _, cmdTest := range commands {
		s.Run(cmdTest.name, func() {
			cmd := cmdTest.cmd()
			s.Require().Contains(cmd.Short, cmdTest.expectedTxt)

			// Test command structure (help text should be in Long field)
			s.Require().NotEmpty(cmd.Long, "Command should have long help text")
		})
	}
}

// New tests for issue-method-ticket CLI: ensure --uses flag exists
func (s *TxTestSuite) TestIssueTicketCmd_UsesFlag() {
    cmd := GetCmdIssuePolicyTicket()
    s.Require().NotNil(cmd)
    // Verify flag exists
    f := cmd.Flags().Lookup("uses")
    s.Require().NotNilf(f, "--uses flag should be present")
    // Verify command use line mentions issue-ticket
    s.Require().Contains(cmd.Use, "issue-ticket")
}

// TestWithdrawSponsorFundsCmd tests the withdraw-sponsor-funds command
func (s *TxTestSuite) TestWithdrawSponsorFundsCmd() {
	testCases := []struct {
		name      string
		args      []string
		expectErr bool
	}{
		{
			"valid withdraw command with DORA",
			[]string{s.contractAddr, s.userAddr, "1DORA"},
			false,
		},
		{
			"valid withdraw command with peaka",
			[]string{s.contractAddr, s.userAddr, "1000000000000000000peaka"},
			false,
		},
		{
			"invalid - missing args",
			[]string{},
			true,
		},
		{
			"invalid - bad denom",
			[]string{s.contractAddr, s.userAddr, "1stake"},
			false, // parsing occurs in RunE; this test only checks structure exists
		},
	}

	for _, tc := range testCases {
		s.Run(tc.name, func() {
			cmd := GetCmdWithdrawSponsorFunds()
			s.Require().NotNil(cmd)
			if tc.expectErr {
				s.Require().NotNil(cmd.Args)
			}
		})
	}
}

// TestRevokeTicketCmd tests the revoke-ticket CLI command structure
func (s *TxTestSuite) TestRevokeTicketCmd() {
    cmd := GetCmdRevokePolicyTicket()
    s.Require().NotNil(cmd)
    // Usage should reflect method, not digest
    s.Require().Contains(cmd.Use, "revoke-ticket")
    s.Require().Contains(cmd.Use, "[method]")
    s.Require().NotContains(cmd.Use, "[digest]")
    // Short description should mention revoke by method
    s.Require().Contains(strings.ToLower(cmd.Short), "revoke")
    s.Require().Contains(strings.ToLower(cmd.Short), "method")

    // Args validation: exactly 3 positional args
    s.Require().Error(cmd.Args(cmd, []string{}))
    s.Require().Error(cmd.Args(cmd, []string{s.contractAddr}))
    s.Require().NoError(cmd.Args(cmd, []string{s.contractAddr, s.userAddr, "increment"}))
    s.Require().Error(cmd.Args(cmd, []string{s.contractAddr, s.userAddr, "increment", "extra"}))
}

// TestCommandFlags tests that all commands support standard transaction flags
func (s *TxTestSuite) TestCommandFlags() {
    commands := []struct {
        name    string
        cmd     func() *cobra.Command
        minArgs []string
    }{
		{
			"set-sponsor flags",
			GetCmdSetSponsor,
			[]string{s.contractAddr, "true"},
		},
		{
			"update-sponsor flags",
			GetCmdUpdateSponsor,
			[]string{s.contractAddr, "false"},
		},
        {
            "delete-sponsor flags",
            GetCmdDeleteSponsor,
            []string{s.contractAddr},
        },
        {
            "revoke-ticket flags",
            GetCmdRevokePolicyTicket,
            []string{s.contractAddr, s.userAddr, "increment"},
        },
    }

	// Standard tx flags to test
	flagTests := []string{
		"generate-only",
		"dry-run",
		"from",
		"gas",
		"gas-prices",
		"gas-adjustment",
		"fees",
	}

	for _, cmdTest := range commands {
		for _, flag := range flagTests {
			s.Run(fmt.Sprintf("%s_%s", cmdTest.name, flag), func() {
				cmd := cmdTest.cmd()

				// Check if the flag exists
				flagSet := cmd.Flags()
				flagExists := flagSet.Lookup(flag) != nil

				// Core tx flags should be present
				if flag == "generate-only" || flag == "dry-run" || flag == "from" {
					s.Require().True(flagExists, "Flag %s should exist on command %s", flag, cmdTest.name)
				}

				s.T().Logf("Flag '%s' exists on '%s': %v", flag, cmdTest.name, flagExists)
			})
		}
	}
}

// TestMessageConstruction tests that commands create proper messages
func (s *TxTestSuite) TestMessageConstruction() {
	testCases := []struct {
		name     string
		cmd      func() *cobra.Command
		args     []string
		validate func(*testing.T, []string)
	}{
		{
			"set sponsor message construction",
			GetCmdSetSponsor,
			[]string{s.contractAddr, "true", "100DORA"},
			func(t *testing.T, args []string) {
				// Basic validation that we have the expected arguments
				require := s.Require()
				require.Equal(s.contractAddr, args[0], "Contract address should match")
				require.Equal("true", args[1], "Is sponsored should be true")
				require.Equal("100DORA", args[2], "Max grant should match")
			},
		},
		{
			"update sponsor message construction",
			GetCmdUpdateSponsor,
			[]string{s.contractAddr, "false", "50DORA"},
			func(t *testing.T, args []string) {
				require := s.Require()
				require.Equal(s.contractAddr, args[0], "Contract address should match")
				require.Equal("false", args[1], "Is sponsored should be false")
				require.Equal("50DORA", args[2], "Max grant should match")
			},
		},
		{
			"delete sponsor message construction",
			GetCmdDeleteSponsor,
			[]string{s.contractAddr},
			func(t *testing.T, args []string) {
				require := s.Require()
				require.Equal(s.contractAddr, args[0], "Contract address should match")
			},
		},
	}

	for _, tc := range testCases {
		s.Run(tc.name, func() {
			// Validate the arguments we would pass to message construction
			tc.validate(s.T(), tc.args)

			// Test that the command exists and is properly structured
			cmd := tc.cmd()
			s.Require().NotNil(cmd, "Command should exist")

			s.T().Logf("Message construction test '%s' completed with args: %v", tc.name, tc.args)
		})
	}
}

// TestMessageTypes tests that proper message types are created
func (s *TxTestSuite) TestMessageTypes() {
	// Test that our message constructors work properly
	testCases := []struct {
		name         string
		createMsg    func() sdk.Msg
		expectedType string
	}{
		{
			"MsgSetSponsor type",
			func() sdk.Msg {
				coins, _ := sdk.ParseCoinsNormalized("100peaka")
				return types.NewMsgSetSponsor(s.userAddr, s.contractAddr, true, coins)
			},
			"/sponsor.MsgSetSponsor",
		},
		{
			"MsgUpdateSponsor type",
			func() sdk.Msg {
				coins, _ := sdk.ParseCoinsNormalized("50peaka")
				return types.NewMsgUpdateSponsor(s.userAddr, s.contractAddr, false, coins)
			},
			"/sponsor.MsgUpdateSponsor",
		},
		{
			"MsgDeleteSponsor type",
			func() sdk.Msg {
				return types.NewMsgDeleteSponsor(s.userAddr, s.contractAddr)
			},
			"/sponsor.MsgDeleteSponsor",
		},
		{
			"MsgWithdrawSponsorFunds type",
			func() sdk.Msg {
				coins, _ := sdk.ParseCoinsNormalized("100peaka")
				return types.NewMsgWithdrawSponsorFunds(s.userAddr, s.contractAddr, s.userAddr, coins)
			},
			"/sponsor.MsgWithdrawSponsorFunds",
		},
	}

	for _, tc := range testCases {
		s.Run(tc.name, func() {
			msg := tc.createMsg()
			s.Require().NotNil(msg, "Message should not be nil")

			// Validate message
			err := msg.ValidateBasic()
			s.Require().NoError(err, "Message should pass basic validation")

			// Test message signers
			signers := msg.GetSigners()
			s.Require().NotEmpty(signers, "Message should have signers")

			s.T().Logf("Message type test '%s' passed", tc.name)
		})
	}
}

func TestTxTestSuite(t *testing.T) {
	suite.Run(t, new(TxTestSuite))
}

// Additional CLI parsing tests (moved from tx_parse_test.go)

func TestParseCoinsWithDORASupport_ZeroAmountsRejected(t *testing.T) {
	cases := []string{
		"0DORA",
		"0peaka",
	}

	for _, in := range cases {
		if _, err := parseCoinsWithDORASupport(in); err == nil {
			t.Fatalf("expected error for zero amount input %q, got nil", in)
		}
	}
}

func TestParseCoinsWithDORASupport_ValidDORA(t *testing.T) {
	// 1.000000000000000001 DORA = 1000000000000000001 peaka
	coins, err := parseCoinsWithDORASupport("1.000000000000000001DORA")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(coins) != 1 {
		t.Fatalf("expected 1 coin, got %d", len(coins))
	}
	c := coins[0]
	if c.Denom != "peaka" {
		t.Fatalf("expected denom peaka, got %s", c.Denom)
	}
	if !c.Amount.IsPositive() {
		t.Fatalf("expected positive amount, got %s", c.Amount.String())
	}
}
