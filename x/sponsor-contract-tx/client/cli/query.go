package cli

import (
	"context"

	"github.com/cosmos/cosmos-sdk/client"
	"github.com/cosmos/cosmos-sdk/client/flags"
	"github.com/spf13/cobra"

	"github.com/DoraFactory/doravota/x/sponsor-contract-tx/types"
)

// GetQueryCmd returns the query commands for the sponsor module
func GetQueryCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:                        types.ModuleName,
		Short:                      "Sponsor query subcommands",
		DisableFlagParsing:         true,
		SuggestionsMinimumDistance: 2,
		RunE:                       client.ValidateCmd,
	}

	cmd.AddCommand(
		GetCmdQueryAllSponsors(),
		GetCmdQuerySponsorInfo(),
		GetCmdQueryUserGrantUsage(),
		GetCmdQueryParams(),
	)

	return cmd
}

// GetCmdQueryAllSponsors implements the query all-sponsors command
func GetCmdQueryAllSponsors() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "all-sponsors",
		Short: "Query all sponsor contracts' info",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			clientCtx, err := client.GetClientQueryContext(cmd)
			if err != nil {
				return err
			}

			queryClient := types.NewQueryClient(clientCtx)

			req := &types.QueryAllSponsorsRequest{}
			res, err := queryClient.AllSponsors(context.Background(), req)
			if err != nil {
				return err
			}

			return clientCtx.PrintProto(res)
		},
	}

	flags.AddQueryFlagsToCmd(cmd)
	return cmd
}

// GetCmdQuerySponsorInfo implements the query sponsor status command
func GetCmdQuerySponsorInfo() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "sponsor-info [contract-address]",
		Short: "Query the info of a sponsor contract",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			clientCtx, err := client.GetClientQueryContext(cmd)
			if err != nil {
				return err
			}

			queryClient := types.NewQueryClient(clientCtx)

			req := &types.QuerySponsorRequest{
				ContractAddress: args[0],
			}
			res, err := queryClient.Sponsor(context.Background(), req)
			if err != nil {
				return err
			}

			return clientCtx.PrintProto(res)
		},
	}

	flags.AddQueryFlagsToCmd(cmd)
	return cmd
}

// GetCmdQueryParams implements the query params command
func GetCmdQueryParams() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "params",
		Short: "Query the parameters of the sponsor module",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			clientCtx, err := client.GetClientQueryContext(cmd)
			if err != nil {
				return err
			}

			queryClient := types.NewQueryClient(clientCtx)

			req := &types.QueryParamsRequest{}
			res, err := queryClient.Params(context.Background(), req)
			if err != nil {
				return err
			}

			return clientCtx.PrintProto(res)
		},
	}

	flags.AddQueryFlagsToCmd(cmd)
	return cmd
}

// GetCmdQueryUserGrantUsage implements the query user grant usage command
func GetCmdQueryUserGrantUsage() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "grant-usage [user-address] [contract-address]",
		Short: "Query grant usage for a specific user and contract",
		Long: `Query the grant usage information for a specific user and contract.
This shows how much of the sponsor's grant the user has already consumed.`,
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			clientCtx, err := client.GetClientQueryContext(cmd)
			if err != nil {
				return err
			}

			queryClient := types.NewQueryClient(clientCtx)

			req := &types.QueryUserGrantUsageRequest{
				UserAddress:     args[0],
				ContractAddress: args[1],
			}
			res, err := queryClient.UserGrantUsage(context.Background(), req)
			if err != nil {
				return err
			}

			return clientCtx.PrintProto(res)
		},
	}

	flags.AddQueryFlagsToCmd(cmd)
	return cmd
}
