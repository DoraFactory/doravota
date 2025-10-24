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
        GetCmdQueryPolicyTicket(),
        GetCmdQueryPolicyTicketByMethod(),
        GetCmdQueryPolicyTickets(),
        GetCmdQuerySponsorBalance(),
    )

	return cmd
}

// GetCmdQueryPolicyTicket queries a policy ticket
func GetCmdQueryPolicyTicket() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "ticket [contract-address] [user-address] [digest]",
		Short: "Query a policy ticket for (contract,user,digest)",
		Args:  cobra.ExactArgs(3),
		RunE: func(cmd *cobra.Command, args []string) error {
			clientCtx, err := client.GetClientQueryContext(cmd)
			if err != nil {
				return err
			}
			qc := types.NewQueryClient(clientCtx)
			res, err := qc.PolicyTicket(context.Background(), &types.QueryPolicyTicketRequest{
				ContractAddress: args[0], UserAddress: args[1], Digest: args[2],
			})
			if err != nil {
				return err
			}
			return clientCtx.PrintProto(res)
		},
	}
	flags.AddQueryFlagsToCmd(cmd)
	return cmd
}

// Additional query subcommands can be added as needed.

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

			// Read standard pagination flags
			pageReq, err := readPageRequest(cmd)
			if err != nil {
				return err
			}

			req := &types.QueryAllSponsorsRequest{Pagination: pageReq}
			res, err := queryClient.AllSponsors(context.Background(), req)
			if err != nil {
				return err
			}

			return clientCtx.PrintProto(res)
		},
	}

	flags.AddQueryFlagsToCmd(cmd)
	// Add pagination flags: page, limit, page-key etc.
	flags.AddPaginationFlagsToCmd(cmd, "all-sponsors")
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

// ReadPageRequestForTests exposes readPageRequest for unit tests in external package.
// It is a thin wrapper used only by tests.
func ReadPageRequestForTests(cmd *cobra.Command) (*sdkquery.PageRequest, error) {
    return readPageRequest(cmd)
}

// GetCmdQueryPolicyTickets queries policy tickets with pagination
func GetCmdQueryPolicyTickets() *cobra.Command {
    cmd := &cobra.Command{
        Use:   "tickets [contract-address] [user-address]",
        Short: "List policy tickets under a contract (optionally for a user)",
        Args:  cobra.RangeArgs(1, 2),
        RunE: func(cmd *cobra.Command, args []string) error {
            clientCtx, err := client.GetClientQueryContext(cmd)
            if err != nil { return err }
            qc := types.NewQueryClient(clientCtx)
            pageReq, err := readPageRequest(cmd)
            if err != nil { return err }
            req := &types.QueryPolicyTicketsRequest{ContractAddress: args[0], Pagination: pageReq}
            if len(args) == 2 { req.UserAddress = args[1] }
            res, err := qc.PolicyTickets(context.Background(), req)
            if err != nil { return err }
            return clientCtx.PrintProto(res)
        },
    }
    flags.AddQueryFlagsToCmd(cmd)
    flags.AddPaginationFlagsToCmd(cmd, "tickets")
    return cmd
}

// GetCmdQueryPolicyTicketByMethod queries a policy ticket by method name
func GetCmdQueryPolicyTicketByMethod() *cobra.Command {
    cmd := &cobra.Command{
        Use:   "ticket-by-method [contract-address] [user-address] [method]",
        Short: "Query a policy ticket for (contract,user,method)",
        Args:  cobra.ExactArgs(3),
        RunE: func(cmd *cobra.Command, args []string) error {
            clientCtx, err := client.GetClientQueryContext(cmd)
            if err != nil { return err }
            qc := types.NewQueryClient(clientCtx)
            res, err := qc.PolicyTicketByMethod(context.Background(), &types.QueryPolicyTicketByMethodRequest{
                ContractAddress: args[0], UserAddress: args[1], Method: args[2],
            })
            if err != nil { return err }
            return clientCtx.PrintProto(res)
        },
    }
    flags.AddQueryFlagsToCmd(cmd)
    return cmd
}

// GetCmdQuerySponsorBalance queries sponsor balance (spendable peaka) for a contract's derived sponsor address
func GetCmdQuerySponsorBalance() *cobra.Command {
    cmd := &cobra.Command{
        Use:   "sponsor-balance [contract-address]",
        Short: "Query sponsor derived address and its spendable peaka balance",
        Args:  cobra.ExactArgs(1),
        RunE: func(cmd *cobra.Command, args []string) error {
            clientCtx, err := client.GetClientQueryContext(cmd)
            if err != nil { return err }
            qc := types.NewQueryClient(clientCtx)
            res, err := qc.SponsorBalance(context.Background(), &types.QuerySponsorBalanceRequest{ContractAddress: args[0]})
            if err != nil { return err }
            return clientCtx.PrintProto(res)
        },
    }
    flags.AddQueryFlagsToCmd(cmd)
    return cmd
}
