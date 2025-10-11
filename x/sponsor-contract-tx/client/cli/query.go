package cli

import (
	"context"

	"github.com/cosmos/cosmos-sdk/client"
	"github.com/cosmos/cosmos-sdk/client/flags"
	sdkquery "github.com/cosmos/cosmos-sdk/types/query"
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
		GetCmdQueryBlockedStatus(),
		GetCmdQueryAllBlockedStatuses(),
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

// GetCmdQueryBlockedStatus implements the query blocked-status command
func GetCmdQueryBlockedStatus() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "blocked-status [contract-address] [user-address]",
		Short: "Query global cooldown status for a user on a contract",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			clientCtx, err := client.GetClientQueryContext(cmd)
			if err != nil {
				return err
			}

			queryClient := types.NewQueryClient(clientCtx)
			req := &types.QueryBlockedStatusRequest{
				ContractAddress: args[0],
				UserAddress:     args[1],
			}
			res, err := queryClient.BlockedStatus(context.Background(), req)
			if err != nil {
				return err
			}
			return clientCtx.PrintProto(res)
		},
	}

	flags.AddQueryFlagsToCmd(cmd)
	return cmd
}

// GetCmdQueryAllBlockedStatuses implements the query all-blocked-statuses command with pagination
func GetCmdQueryAllBlockedStatuses() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "all-blocked-statuses",
		Short: "Query all global cooldown records with optional filters and pagination",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			clientCtx, err := client.GetClientQueryContext(cmd)
			if err != nil {
				return err
			}

			queryClient := types.NewQueryClient(clientCtx)

			contract, _ := cmd.Flags().GetString("contract")
			onlyBlocked, _ := cmd.Flags().GetBool("only-blocked")

			// Read standard pagination flags
			pageReq, err := readPageRequest(cmd)
			if err != nil {
				return err
			}

			req := &types.QueryAllBlockedStatusesRequest{
				ContractAddress: contract,
				OnlyBlocked:     onlyBlocked,
				Pagination:      pageReq,
			}
			res, err := queryClient.AllBlockedStatuses(context.Background(), req)
			if err != nil {
				return err
			}
			return clientCtx.PrintProto(res)
		},
	}

	flags.AddQueryFlagsToCmd(cmd)
	// Add filtering flags
	cmd.Flags().String("contract", "", "Filter by contract address")
	cmd.Flags().Bool("only-blocked", false, "Only include currently blocked entries")
	// Add pagination flags: page, limit, page-key etc.
	flags.AddPaginationFlagsToCmd(cmd, "all-blocked-statuses")

	return cmd
}

// readPageRequest reads pagination flags into a PageRequest. It mirrors client.ReadPageRequest but avoids import churn if versions differ.
func readPageRequest(cmd *cobra.Command) (*sdkquery.PageRequest, error) {
	pageReq := &sdkquery.PageRequest{}
	// The standard flags are: --page, --limit, --page-key, --offset, --count-total, --reverse
	// We populate what is available via flags helpers.
	page, _ := cmd.Flags().GetUint64(flags.FlagPage)
	limit, _ := cmd.Flags().GetUint64(flags.FlagLimit)
	pageKey, _ := cmd.Flags().GetBytesBase64(flags.FlagPageKey)
	offset, _ := cmd.Flags().GetUint64(flags.FlagOffset)
	countTotal, _ := cmd.Flags().GetBool(flags.FlagCountTotal)
	reverse, _ := cmd.Flags().GetBool(flags.FlagReverse)

	// Cosmos SDK uses either page+limit or key-based pagination. Populate both if set.
	if len(pageKey) > 0 {
		pageReq.Key = pageKey
	}
	// The older SDKs often use offset; newer prefer page/limit. We'll set both if present.
	if offset > 0 {
		pageReq.Offset = offset
	}
	if page > 0 {
		// page is 1-based in flags; convert to 0-based offset
		if limit > 0 {
			pageReq.Offset = (page - 1) * limit
		}
	}
	if limit > 0 {
		pageReq.Limit = limit
	}
	pageReq.CountTotal = countTotal
	pageReq.Reverse = reverse
	return pageReq, nil
}
