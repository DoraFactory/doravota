package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"

	sdk "github.com/cosmos/cosmos-sdk/types"
	authtypes "github.com/cosmos/cosmos-sdk/x/auth/types"
	"github.com/spf13/cobra"

	appparams "github.com/DoraFactory/doravota/app/params"
	pqcauthtypes "github.com/DoraFactory/doravota/x/pqcauth/types"
)

func pqcauthAuditCommand(encodingConfig appparams.EncodingConfig) *cobra.Command {
	command := &cobra.Command{
		Use:   "pqcauth",
		Short: "Offline PQC authentication maintenance",
	}
	command.AddCommand(pqcauthAuditStateCommand(encodingConfig))
	return command
}

func pqcauthAuditStateCommand(encodingConfig appparams.EncodingConfig) *cobra.Command {
	command := &cobra.Command{
		Use:   "audit-state [exported-state.json]",
		Short: "Audit an exported pqcauth state before an upgrade",
		Long: "Audit pqcauth and auth state from a complete `dorad export` JSON document. " +
			"The command is offline and never queries a public RPC endpoint.",
		Args: cobra.ExactArgs(1),
		RunE: func(command *cobra.Command, args []string) error {
			height, err := command.Flags().GetInt64("height")
			if err != nil {
				return err
			}
			maxIssues, err := command.Flags().GetUint32("max-issues")
			if err != nil {
				return err
			}
			maxIssues = pqcauthtypes.NormalizeStateAuditMaxIssues(maxIssues)

			raw, err := os.ReadFile(args[0])
			if err != nil {
				return err
			}
			appState, err := exportedAppState(raw)
			if err != nil {
				return err
			}

			pqcRaw, exists := appState[pqcauthtypes.ModuleName]
			if !exists {
				return fmt.Errorf("exported state does not contain %q", pqcauthtypes.ModuleName)
			}
			var pqcGenesis pqcauthtypes.GenesisState
			if err := encodingConfig.Marshaler.UnmarshalJSON(pqcRaw, &pqcGenesis); err != nil {
				return fmt.Errorf("decode pqcauth state: %w", err)
			}
			report := pqcauthtypes.AuditGenesisState(pqcGenesis, height, true, maxIssues)

			authRaw, exists := appState[authtypes.ModuleName]
			if !exists {
				report.AddIssue(maxIssues, "missing_auth_state", "", "complete auth state is required to validate pqcauth owners")
			} else {
				var authGenesis authtypes.GenesisState
				if err := encodingConfig.Marshaler.UnmarshalJSON(authRaw, &authGenesis); err != nil {
					report.AddIssue(maxIssues, "auth_state_decode_failure", "", err.Error())
				} else if err := authtypes.ValidateGenesis(authGenesis); err != nil {
					report.AddIssue(maxIssues, "invalid_auth_state", "", err.Error())
				} else if accounts, err := authtypes.UnpackAccounts(authGenesis.Accounts); err != nil {
					report.AddIssue(maxIssues, "auth_account_unpack_failure", "", err.Error())
				} else {
					auditExportedOwnerAccounts(&report, maxIssues, pqcGenesis, accounts)
				}
			}

			encoder := json.NewEncoder(command.OutOrStdout())
			encoder.SetIndent("", "  ")
			if err := encoder.Encode(report); err != nil {
				return err
			}
			return report.Error()
		},
	}
	command.Flags().Int64(
		"height",
		-1,
		"exported block height; enables effective-key checks when non-negative",
	)
	command.Flags().Uint32(
		"max-issues",
		pqcauthtypes.DefaultStateAuditMaxIssues,
		"maximum detailed issues to print",
	)
	return command
}

func exportedAppState(raw []byte) (map[string]json.RawMessage, error) {
	var document map[string]json.RawMessage
	if err := json.Unmarshal(raw, &document); err != nil {
		return nil, fmt.Errorf("decode exported state: %w", err)
	}
	if encoded, exists := document["app_state"]; exists {
		var appState map[string]json.RawMessage
		if err := json.Unmarshal(encoded, &appState); err != nil {
			return nil, fmt.Errorf("decode app_state: %w", err)
		}
		return appState, nil
	}
	return document, nil
}

func auditExportedOwnerAccounts(
	report *pqcauthtypes.StateAuditReport,
	maxIssues uint32,
	genesis pqcauthtypes.GenesisState,
	accounts authtypes.GenesisAccounts,
) {
	byAddress := make(map[string]authtypes.GenesisAccount, len(accounts))
	for _, account := range accounts {
		byAddress[account.GetAddress().String()] = account
	}
	owners := make(map[string]struct{})
	for _, key := range genesis.Keys {
		owners[key.Owner] = struct{}{}
	}
	for _, policy := range genesis.Policies {
		owners[policy.Owner] = struct{}{}
	}
	for _, sequence := range genesis.KeySequences {
		owners[sequence.Owner] = struct{}{}
	}
	for _, history := range genesis.KeyHistories {
		owners[history.Owner] = struct{}{}
	}
	ordered := make([]string, 0, len(owners))
	for owner := range owners {
		ordered = append(ordered, owner)
	}
	sort.Strings(ordered)
	for _, owner := range ordered {
		address, err := sdk.AccAddressFromBech32(owner)
		if err != nil || address.String() != owner {
			continue
		}
		account := byAddress[owner]
		if account == nil {
			report.AddIssue(maxIssues, "owner_account_not_found", owner, "pqcauth state has no matching auth account")
			continue
		}
		switch pqcauthtypes.ClassifyAccountAuthentication(account.GetPubKey()) {
		case pqcauthtypes.AccountAuthenticationClassic:
			// Expected: pqcauth only supplements classic SDK accounts.
		case pqcauthtypes.AccountAuthenticationNativePQC:
			report.AddIssue(maxIssues, "native_pqc_owner", owner, "native ML-DSA accounts must not register pqcauth state")
		default:
			report.AddIssue(maxIssues, "unsupported_owner_authentication", owner, "owner does not use a supported classic SDK public key")
		}
	}
}
