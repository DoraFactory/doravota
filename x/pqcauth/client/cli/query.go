package cli

import (
	"context"
	"strconv"

	"github.com/cosmos/cosmos-sdk/client"
	"github.com/cosmos/cosmos-sdk/client/flags"
	"github.com/spf13/cobra"

	"github.com/DoraFactory/doravota/x/pqcauth/types"
)

func GetQueryCmd() *cobra.Command {
	command := &cobra.Command{
		Use:                        types.ModuleName,
		Short:                      "Query post-quantum account authorization",
		DisableFlagParsing:         true,
		SuggestionsMinimumDistance: 2,
		RunE:                       client.ValidateCmd,
	}
	command.AddCommand(
		queryParamsCommand(),
		queryAccountCommand(),
		queryKeyCommand(),
		queryKeysCommand(),
	)
	return command
}

func queryParamsCommand() *cobra.Command {
	command := &cobra.Command{
		Use:   "params",
		Short: "Query active and pending pqcauth parameters",
		Args:  cobra.NoArgs,
		RunE: func(command *cobra.Command, _ []string) error {
			clientCtx, err := client.GetClientQueryContext(command)
			if err != nil {
				return err
			}
			response, err := types.NewQueryClient(clientCtx).Params(
				context.Background(),
				&types.QueryParamsRequest{},
			)
			if err != nil {
				return err
			}
			return clientCtx.PrintProto(response)
		},
	}
	flags.AddQueryFlagsToCmd(command)
	return command
}

func queryAccountCommand() *cobra.Command {
	command := &cobra.Command{
		Use:   "account [owner]",
		Short: "Query effective PQC policy and active signing key",
		Args:  cobra.ExactArgs(1),
		RunE: func(command *cobra.Command, args []string) error {
			clientCtx, err := client.GetClientQueryContext(command)
			if err != nil {
				return err
			}
			response, err := types.NewQueryClient(clientCtx).Account(
				context.Background(),
				&types.QueryAccountRequest{Owner: args[0]},
			)
			if err != nil {
				return err
			}
			return clientCtx.PrintProto(response)
		},
	}
	flags.AddQueryFlagsToCmd(command)
	return command
}

func queryKeyCommand() *cobra.Command {
	command := &cobra.Command{
		Use:   "key [owner] [key-id]",
		Short: "Query one historical PQC key record",
		Args:  cobra.ExactArgs(2),
		RunE: func(command *cobra.Command, args []string) error {
			keyID, err := strconv.ParseUint(args[1], 10, 64)
			if err != nil || keyID == 0 {
				return types.ErrInvalidKey.Wrap("key id must be a positive integer")
			}
			clientCtx, err := client.GetClientQueryContext(command)
			if err != nil {
				return err
			}
			response, err := types.NewQueryClient(clientCtx).Key(
				context.Background(),
				&types.QueryKeyRequest{Owner: args[0], KeyId: keyID},
			)
			if err != nil {
				return err
			}
			return clientCtx.PrintProto(response)
		},
	}
	flags.AddQueryFlagsToCmd(command)
	return command
}

func queryKeysCommand() *cobra.Command {
	command := &cobra.Command{
		Use:   "keys [owner]",
		Short: "List PQC key records for an account",
		Args:  cobra.ExactArgs(1),
		RunE: func(command *cobra.Command, args []string) error {
			clientCtx, err := client.GetClientQueryContext(command)
			if err != nil {
				return err
			}
			pageRequest, err := client.ReadPageRequest(command.Flags())
			if err != nil {
				return err
			}
			response, err := types.NewQueryClient(clientCtx).Keys(
				context.Background(),
				&types.QueryKeysRequest{Owner: args[0], Pagination: pageRequest},
			)
			if err != nil {
				return err
			}
			return clientCtx.PrintProto(response)
		},
	}
	flags.AddQueryFlagsToCmd(command)
	flags.AddPaginationFlagsToCmd(command, "PQC account keys")
	return command
}
