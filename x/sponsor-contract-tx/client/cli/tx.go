package cli

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"cosmossdk.io/math"
	"github.com/spf13/cobra"

	"github.com/cosmos/cosmos-sdk/client"
	"github.com/cosmos/cosmos-sdk/client/flags"
	"github.com/cosmos/cosmos-sdk/client/tx"
	sdk "github.com/cosmos/cosmos-sdk/types"

	"github.com/DoraFactory/doravota/x/sponsor-contract-tx/types"
)

// GetTxCmd returns the transaction commands for the sponsor module
func GetTxCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:                        types.ModuleName,
		Short:                      "Cosmwasm Contract Sponsor transaction subcommands",
		DisableFlagParsing:         true,
		SuggestionsMinimumDistance: 2,
		RunE:                       client.ValidateCmd,
	}

	cmd.AddCommand(
		GetCmdSetSponsor(),
		GetCmdUpdateSponsor(),
		GetCmdDeleteSponsor(),
		GetCmdWithdrawSponsorFunds(),
		GetCmdIssuePolicyTicket(),
		GetCmdRevokePolicyTicket(),
	)

	return cmd
}

// GetCmdIssuePolicyTicket submits a MsgIssuePolicyTicket (admin or ticket issuer)
func GetCmdIssuePolicyTicket() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "issue-ticket [contract-address] [user-address] --method name [--method name]... [--uses N]",
		Short: "Admin or ticket issuer issues a method-level policy ticket",
		Args:  cobra.ExactArgs(2),
	}
	var method string
	var uses uint32
	cmd.Flags().StringVar(&method, "method", "", "Top-level execute method name (required)")
	cmd.Flags().Uint32Var(&uses, "uses", 0, "Requested uses for this ticket (0 or omitted implies 1; clamped by params)")
	cmd.RunE = func(cmd *cobra.Command, args []string) error {
		if strings.TrimSpace(method) == "" {
			return fmt.Errorf("--method is required")
		}
		clientCtx, err := client.GetClientTxContext(cmd)
		if err != nil {
			return err
		}
		m := &types.MsgIssuePolicyTicket{
			Creator:         clientCtx.GetFromAddress().String(),
			ContractAddress: args[0],
			UserAddress:     args[1],
			Method:          method,
			Uses:            uses,
		}
		if err := m.ValidateBasic(); err != nil {
			return err
		}
		return tx.GenerateOrBroadcastTxCLI(clientCtx, cmd.Flags(), m)
	}
	flags.AddTxFlagsToCmd(cmd)
	return cmd
}

// GetCmdRevokePolicyTicket submits a MsgRevokePolicyTicket (admin or ticket issuer)
func GetCmdRevokePolicyTicket() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "revoke-ticket [contract-address] [user-address] [digest]",
		Short: "Admin or ticket issuer revokes a policy ticket",
		Args:  cobra.ExactArgs(3),
		RunE: func(cmd *cobra.Command, args []string) error {
			clientCtx, err := client.GetClientTxContext(cmd)
			if err != nil {
				return err
			}
			m := &types.MsgRevokePolicyTicket{
				Creator:         clientCtx.GetFromAddress().String(),
				ContractAddress: args[0],
				UserAddress:     args[1],
				Digest:          args[2],
			}
			if err := m.ValidateBasic(); err != nil {
				return err
			}
			return tx.GenerateOrBroadcastTxCLI(clientCtx, cmd.Flags(), m)
		},
	}
	flags.AddTxFlagsToCmd(cmd)
	return cmd
}

// GetCmdWithdrawSponsorFunds implements the withdraw sponsor funds command
func GetCmdWithdrawSponsorFunds() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "withdraw-sponsor-funds [contract-address] [recipient] [amount]",
		Short: "Withdraw funds from the derived sponsor address to a recipient (admin only)",
		Long: `Withdraw funds from the derived sponsor address to a recipient.
Only the contract admin can execute this. Amount supports peaka and DORA (1 DORA = 10^18 peaka), e.g. 10DORA or 10000000000000000000peaka.
If amount is omitted the command withdraws the entire spendable balance.`,
		Args: cobra.RangeArgs(2, 3),
		RunE: func(cmd *cobra.Command, args []string) error {
			clientCtx, err := client.GetClientTxContext(cmd)
			if err != nil {
				return err
			}

			var coins sdk.Coins
			if len(args) == 3 {
				coins, err = parseCoinsWithDORASupport(args[2])
				if err != nil {
					return err
				}
			}

			msg := types.NewMsgWithdrawSponsorFunds(clientCtx.GetFromAddress().String(), args[0], args[1], coins)
			if err := msg.ValidateBasic(); err != nil {
				return err
			}
			return tx.GenerateOrBroadcastTxCLI(clientCtx, cmd.Flags(), msg)
		},
	}
	flags.AddTxFlagsToCmd(cmd)
	return cmd
}

// parseBoolParameter parses boolean parameter with proper validation
func parseBoolParameter(value string) (bool, error) {
	switch value {
	case "true":
		return true, nil
	case "false":
		return false, nil
	default:
		return false, fmt.Errorf("invalid boolean value: %s", value)
	}
}

// convertDORAToPeaka converts a DORA amount string to peaka using exact decimal math
// Supports integer and decimal inputs with up to 18 decimal places
// Returns error for amounts that cannot be exactly represented in peaka
func convertDORAToPeaka(doraAmountStr string) (math.Int, error) {
	// Parse the DORA amount as decimal
	parts := strings.Split(doraAmountStr, ".")
	if len(parts) > 2 {
		return math.Int{}, fmt.Errorf("invalid decimal format: %s", doraAmountStr)
	}

	// Parse integer part
	integerPart, err := strconv.ParseUint(parts[0], 10, 64)
	if err != nil {
		return math.Int{}, fmt.Errorf("invalid integer part: %s", parts[0])
	}

	// Parse decimal part if present
	var decimalPart uint64 = 0
	var decimalDigits int = 0

	if len(parts) == 2 {
		decimalStr := parts[1]
		decimalDigits = len(decimalStr)

		// Reject if more than 18 decimal places (can't be exactly represented in peaka)
		if decimalDigits > 18 {
			return math.Int{}, fmt.Errorf("too many decimal places: %d (max 18)", decimalDigits)
		}

		if decimalDigits > 0 {
			decimalPart, err = strconv.ParseUint(decimalStr, 10, 64)
			if err != nil {
				return math.Int{}, fmt.Errorf("invalid decimal part: %s", decimalStr)
			}
		}
	}

	// Convert to peaka: DORA * 10^18 = (integerPart * 10^18) + (decimalPart * 10^(18-decimalDigits))

	// Integer part contribution
	integerContribution := math.NewIntFromUint64(integerPart)
	multiplier := math.NewIntFromUint64(1000000000000000000) // 10^18
	integerContribution = integerContribution.Mul(multiplier)

	// Decimal part contribution
	var decimalContribution math.Int
	if decimalPart > 0 {
		decimalContribution = math.NewIntFromUint64(decimalPart)
		// Multiply by 10^(18-decimalDigits)
		decimalMultiplier := math.NewIntFromUint64(1)
		for i := 0; i < 18-decimalDigits; i++ {
			decimalMultiplier = decimalMultiplier.MulRaw(10)
		}
		decimalContribution = decimalContribution.Mul(decimalMultiplier)
	} else {
		decimalContribution = math.ZeroInt()
	}

	// Sum the contributions
	totalPeaka := integerContribution.Add(decimalContribution)

	// Validate the result is positive
	if !totalPeaka.IsPositive() && !totalPeaka.IsZero() {
		return math.Int{}, fmt.Errorf("result must be non-negative")
	}

	if totalPeaka.IsZero() && (integerPart > 0 || decimalPart > 0) {
		return math.Int{}, fmt.Errorf("amount too small to represent in peaka")
	}

	return totalPeaka, nil
}

// parseCoinsWithDORASupport parses coins string with support for DORA to base denom conversion
// 1 DORA = 10^18 base units
// Only supports uppercase "DORA" and base denom denominations
// Uses exact decimal math to avoid precision loss
func parseCoinsWithDORASupport(coinsStr string) (sdk.Coins, error) {
	// Convert DORA to base denom if present (case sensitive, only uppercase)
	doraPattern := regexp.MustCompile(`(\d+(?:\.\d+)?)(DORA)`)
	convertedStr := doraPattern.ReplaceAllStringFunc(coinsStr, func(match string) string {
		// Extract the amount and unit
		submatches := doraPattern.FindStringSubmatch(match)
		if len(submatches) < 2 {
			return match // Fallback to original if no match
		}
		amountStr := submatches[1]

		// Convert DORA to base denom using exact decimal math
		peakaAmount, err := convertDORAToPeaka(amountStr)
		if err != nil {
			return match // Fallback to original on error - will be caught by validation later
		}

		return peakaAmount.String() + types.SponsorshipDenom
	})

	// Parse the converted string
	coins, err := sdk.ParseCoinsNormalized(convertedStr)
	if err != nil {
		return nil, err
	}

	// Validate that only base denom is present
	for _, coin := range coins {
		if coin.Denom != types.SponsorshipDenom {
			return nil, fmt.Errorf("invalid denomination '%s': only 'peaka' and 'DORA' are supported", coin.Denom)
		}
		// Friendly validation: disallow zero amounts early at CLI
		if coin.Amount.IsZero() {
			return nil, fmt.Errorf("amount must be greater than 0; got 0 for '%s' (if you meant 'no amount', omit the argument)", coin.Denom)
		}
	}

	// Also reject if total parsed amount equals zero (e.g. input normalizes to empty or zero)
	if coins.AmountOf(types.SponsorshipDenom).IsZero() {
		return nil, fmt.Errorf("amount must be greater than 0")
	}

	return coins, nil
}

// GetCmdSetSponsor implements the set sponsor command
func GetCmdSetSponsor() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "set-sponsor [contract-address] [is-sponsored] [max-grant-per-user]",
		Short: "Set a sponsor contract",
		Long: `Set a sponsor contract.
max-grant-per-user should be a comma-separated list of coins (e.g., "100DORA").
Note: Use uppercase "DORA" (1 DORA = 10^18 peaka) or directly use "peaka".
If not provided, no grant limit will be set.`,
		Args: cobra.RangeArgs(2, 3),
		RunE: func(cmd *cobra.Command, args []string) error {
			clientCtx, err := client.GetClientTxContext(cmd)
			if err != nil {
				return err
			}

			isSponsored, err := parseBoolParameter(args[1])
			if err != nil {
				return fmt.Errorf("invalid is-sponsored parameter '%s': must be 'true' or 'false'", args[1])
			}

			var maxGrantPerUser sdk.Coins
			if len(args) > 2 && args[2] != "" {
				maxGrantPerUser, err = parseCoinsWithDORASupport(args[2])
				if err != nil {
					return err
				}
			}

			msg := types.NewMsgSetSponsor(clientCtx.GetFromAddress().String(), args[0], isSponsored, maxGrantPerUser)

			return tx.GenerateOrBroadcastTxCLI(clientCtx, cmd.Flags(), msg)
		},
	}

	flags.AddTxFlagsToCmd(cmd)
	return cmd
}

// GetCmdUpdateSponsor implements the update sponsor command
func GetCmdUpdateSponsor() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "update-sponsor [contract-address] [is-sponsored] [max-grant-per-user]",
		Short: "Update a sponsor status",
		Long: `Update a sponsor status.
max-grant-per-user should be a comma-separated list of coins (e.g., "10DORA").
Note: Use uppercase "DORA" (1 DORA = 10^18 peaka) or directly use "peaka".
If not provided, no grant limit will be set.`,
		Args: cobra.RangeArgs(2, 3),
		RunE: func(cmd *cobra.Command, args []string) error {
			clientCtx, err := client.GetClientTxContext(cmd)
			if err != nil {
				return err
			}

			isSponsored, err := parseBoolParameter(args[1])
			if err != nil {
				return fmt.Errorf("invalid is-sponsored parameter '%s': must be 'true' or 'false'", args[1])
			}

			var maxGrantPerUser sdk.Coins
			if len(args) > 2 && args[2] != "" {
				maxGrantPerUser, err = parseCoinsWithDORASupport(args[2])
				if err != nil {
					return err
				}
			}

			msg := types.NewMsgUpdateSponsor(clientCtx.GetFromAddress().String(), args[0], isSponsored, maxGrantPerUser)

			return tx.GenerateOrBroadcastTxCLI(clientCtx, cmd.Flags(), msg)
		},
	}

	flags.AddTxFlagsToCmd(cmd)
	return cmd
}

// GetCmdDeleteSponsor implements the delete sponsor command
func GetCmdDeleteSponsor() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "delete-sponsor [contract-address]",
		Short: "Delete a sponsor contract",
		Long: `Delete a sponsor contract.
This will remove the sponsorship configuration for the specified contract address.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			clientCtx, err := client.GetClientTxContext(cmd)
			if err != nil {
				return err
			}

			msg := types.NewMsgDeleteSponsor(clientCtx.GetFromAddress().String(), args[0])

			return tx.GenerateOrBroadcastTxCLI(clientCtx, cmd.Flags(), msg)
		},
	}

	flags.AddTxFlagsToCmd(cmd)
	return cmd
}
