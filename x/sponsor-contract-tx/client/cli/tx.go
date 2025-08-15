package cli

import (
	"fmt"
	"math/big"
	"regexp"

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
		Short:                      "Sponsor transaction subcommands",
		DisableFlagParsing:         true,
		SuggestionsMinimumDistance: 2,
		RunE:                       client.ValidateCmd,
	}

	cmd.AddCommand(
		GetCmdSetSponsor(),
		GetCmdUpdateSponsor(),
		GetCmdDeleteSponsor(),
	)

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

// parseCoinsWithDORASupport parses coins string with support for DORA to peaka conversion
// 1 DORA = 10^18 peaka
// Only supports uppercase "DORA" and "peaka" denominations
func parseCoinsWithDORASupport(coinsStr string) (sdk.Coins, error) {
	// Convert DORA to peaka if present (case sensitive, only uppercase)
	doraPattern := regexp.MustCompile(`(\d+(?:\.\d+)?)(DORA)`)
	convertedStr := doraPattern.ReplaceAllStringFunc(coinsStr, func(match string) string {
		// Extract the amount and unit
		submatches := doraPattern.FindStringSubmatch(match)
		if len(submatches) < 2 {
			return match // Fallback to original if no match
		}
		amountStr := submatches[1]

		// Convert to big.Float for precision
		amount := new(big.Float)
		amount.SetString(amountStr)

		// Multiply by 10^18
		multiplier := new(big.Float)
		multiplier.SetString("1000000000000000000") // 10^18

		result := new(big.Float)
		result.Mul(amount, multiplier)

		// Convert to integer
		resultInt := new(big.Int)
		result.Int(resultInt)

		return resultInt.String() + "peaka"
	})

	// Parse the converted string
	coins, err := sdk.ParseCoinsNormalized(convertedStr)
	if err != nil {
		return nil, err
	}

	// Validate that only peaka denom is present
	for _, coin := range coins {
		if coin.Denom != "peaka" {
			return nil, fmt.Errorf("invalid denomination '%s': only 'peaka' and 'DORA' are supported", coin.Denom)
		}
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
		Args:  cobra.ExactArgs(1),
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