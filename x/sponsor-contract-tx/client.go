package sponsor

import (
	"context"

	"github.com/spf13/cobra"

	"github.com/cosmos/cosmos-sdk/client"
	"github.com/cosmos/cosmos-sdk/client/flags"
	"github.com/cosmos/cosmos-sdk/client/tx"

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
		GetCmdQuerySponsorStatus(),
	)

	return cmd
}

// GetCmdSetSponsor implements the set sponsor command
func GetCmdSetSponsor() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "set-sponsor [contract-address] [is-sponsored]",
		Short: "Set a sponsor for a contract",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			clientCtx, err := client.GetClientTxContext(cmd)
			if err != nil {
				return err
			}

			isSponsored := args[1] == "true"
			msg := types.NewMsgSetSponsor(clientCtx.GetFromAddress().String(), args[0], isSponsored)

			return tx.GenerateOrBroadcastTxCLI(clientCtx, cmd.Flags(), msg)
		},
	}

	flags.AddTxFlagsToCmd(cmd)
	return cmd
}

// GetCmdUpdateSponsor implements the update sponsor command
func GetCmdUpdateSponsor() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "update-sponsor [contract-address] [is-sponsored]",
		Short: "Update a sponsor status",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			clientCtx, err := client.GetClientTxContext(cmd)
			if err != nil {
				return err
			}

			isSponsored := args[1] == "true"
			msg := types.NewMsgUpdateSponsor(clientCtx.GetFromAddress().String(), args[0], isSponsored)

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
		Short: "Delete a sponsor",
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

// GetCmdQueryAllSponsors implements the query all-sponsors command
func GetCmdQueryAllSponsors() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "all-sponsors",
		Short: "Query all sponsors",
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

// GetCmdQuerySponsorStatus implements the query sponsor status command
func GetCmdQuerySponsorStatus() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "status [contract-address]",
		Short: "Query sponsor status for a contract",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			clientCtx, err := client.GetClientQueryContext(cmd)
			if err != nil {
				return err
			}

			queryClient := types.NewQueryClient(clientCtx)

			req := &types.QueryIsSponsoredRequest{
				ContractAddress: args[0],
			}
			res, err := queryClient.IsSponsored(context.Background(), req)
			if err != nil {
				return err
			}

			return clientCtx.PrintProto(res)
		},
	}

	flags.AddQueryFlagsToCmd(cmd)
	return cmd
}
