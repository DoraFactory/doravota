package cmd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/cosmos/cosmos-sdk/client"
	"github.com/cosmos/cosmos-sdk/client/flags"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/cosmos/cosmos-sdk/types/query"
	authtypes "github.com/cosmos/cosmos-sdk/x/auth/types"
	"github.com/cosmos/cosmos-sdk/x/authz"
	"github.com/cosmos/cosmos-sdk/x/feegrant"
	"github.com/spf13/cobra"

	appparams "github.com/DoraFactory/doravota/app/params"
	pqcauthtypes "github.com/DoraFactory/doravota/x/pqcauth/types"
)

const (
	defaultProtectionReadinessLimit = uint64(20)
	maxProtectionReadinessLimit     = uint64(100)
)

var errProtectionNotReady = errors.New("account is not ready to enable pqcauth protection")

type protectionReadinessCapability struct {
	Kind       string `json:"kind"`
	Grantee    string `json:"grantee"`
	TypeURL    string `json:"type_url,omitempty"`
	Expiration string `json:"expiration,omitempty"`
}

type protectionReadinessReport struct {
	Address                  string                          `json:"address"`
	AccountAuthentication    string                          `json:"account_authentication"`
	Sequence                 uint64                          `json:"sequence"`
	PublicKeyPublished       bool                            `json:"public_key_published"`
	FreshAccountCandidate    bool                            `json:"fresh_account_candidate"`
	PQCAuthEligible          bool                            `json:"pqcauth_eligible"`
	CapabilityCleanupReady   bool                            `json:"capability_cleanup_ready"`
	Ready                    bool                            `json:"ready"`
	AuthzGrants              []protectionReadinessCapability `json:"authz_grants"`
	FeegrantAllowances       []protectionReadinessCapability `json:"feegrant_allowances"`
	AuthzResultsTruncated    bool                            `json:"authz_results_truncated"`
	FeegrantResultsTruncated bool                            `json:"feegrant_results_truncated"`
	Issues                   []string                        `json:"issues"`
}

type granterGrantsQuery func(
	context.Context,
	*authz.QueryGranterGrantsRequest,
) (*authz.QueryGranterGrantsResponse, error)

type granterAllowancesQuery func(
	context.Context,
	*feegrant.QueryAllowancesByGranterRequest,
) (*feegrant.QueryAllowancesByGranterResponse, error)

func pqcauthProtectionReadinessCommand(encodingConfig appparams.EncodingConfig) *cobra.Command {
	command := &cobra.Command{
		Use:   "protection-readiness [address]",
		Short: "Check delegated capabilities before enabling pqcauth protection",
		Long: "Query an account and list existing authz grants and feegrant allowances issued by it. " +
			"The check is read-only and intended to run before registration or self-enforcement.",
		Args: cobra.ExactArgs(1),
		RunE: func(command *cobra.Command, args []string) error {
			address, err := sdk.AccAddressFromBech32(args[0])
			if err != nil {
				return fmt.Errorf("address must be canonical bech32: %w", err)
			}
			if address.String() != args[0] {
				return errors.New("address must use the canonical bech32 representation")
			}
			limit, err := command.Flags().GetUint64("limit")
			if err != nil {
				return err
			}
			if limit == 0 || limit > maxProtectionReadinessLimit {
				return fmt.Errorf("limit must be between 1 and %d", maxProtectionReadinessLimit)
			}

			clientCtx, err := client.GetClientQueryContext(command)
			if err != nil {
				return err
			}
			ctx := command.Context()
			accountResponse, err := authtypes.NewQueryClient(clientCtx).Account(
				ctx,
				&authtypes.QueryAccountRequest{Address: address.String()},
			)
			if err != nil {
				return fmt.Errorf("query auth account: %w", err)
			}
			if accountResponse == nil || accountResponse.Account == nil {
				return errors.New("query auth account returned an empty response")
			}
			var account sdk.AccountI
			if err := encodingConfig.InterfaceRegistry.UnpackAny(accountResponse.Account, &account); err != nil {
				return fmt.Errorf("unpack auth account: %w", err)
			}
			if account == nil || !account.GetAddress().Equals(address) {
				return errors.New("queried auth account does not match the requested address")
			}

			authzClient := authz.NewQueryClient(clientCtx)
			feegrantClient := feegrant.NewQueryClient(clientCtx)
			report, err := buildProtectionReadinessReport(
				ctx,
				account,
				limit,
				func(ctx context.Context, request *authz.QueryGranterGrantsRequest) (*authz.QueryGranterGrantsResponse, error) {
					return authzClient.GranterGrants(ctx, request)
				},
				func(ctx context.Context, request *feegrant.QueryAllowancesByGranterRequest) (*feegrant.QueryAllowancesByGranterResponse, error) {
					return feegrantClient.AllowancesByGranter(ctx, request)
				},
			)
			if err != nil {
				return err
			}

			encoder := json.NewEncoder(command.OutOrStdout())
			encoder.SetIndent("", "  ")
			if err := encoder.Encode(report); err != nil {
				return err
			}
			if !report.Ready {
				return errProtectionNotReady
			}
			return nil
		},
	}
	command.Flags().Uint64(
		"limit",
		defaultProtectionReadinessLimit,
		"maximum authz grants and feegrant allowances to include per category",
	)
	flags.AddQueryFlagsToCmd(command)
	return command
}

func buildProtectionReadinessReport(
	ctx context.Context,
	account sdk.AccountI,
	limit uint64,
	queryAuthz granterGrantsQuery,
	queryFeegrant granterAllowancesQuery,
) (protectionReadinessReport, error) {
	if account == nil {
		return protectionReadinessReport{}, errors.New("account is nil")
	}
	if limit == 0 || limit > maxProtectionReadinessLimit {
		return protectionReadinessReport{}, fmt.Errorf("limit must be between 1 and %d", maxProtectionReadinessLimit)
	}
	address := account.GetAddress().String()
	report := protectionReadinessReport{
		Address:               address,
		Sequence:              account.GetSequence(),
		PublicKeyPublished:    account.GetPubKey() != nil,
		FreshAccountCandidate: account.GetSequence() == 0 && account.GetPubKey() == nil,
		AuthzGrants:           []protectionReadinessCapability{},
		FeegrantAllowances:    []protectionReadinessCapability{},
		Issues:                []string{},
	}

	switch {
	case account.GetPubKey() == nil:
		report.AccountAuthentication = "classic_key_not_published"
		report.PQCAuthEligible = true
	case pqcauthtypes.ClassifyAccountAuthentication(account.GetPubKey()) == pqcauthtypes.AccountAuthenticationClassic:
		report.AccountAuthentication = "classic"
		report.PQCAuthEligible = true
	case pqcauthtypes.ClassifyAccountAuthentication(account.GetPubKey()) == pqcauthtypes.AccountAuthenticationNativePQC:
		report.AccountAuthentication = "native_mldsa65"
		report.Issues = append(report.Issues, "native ML-DSA-65 accounts already use native PQC authentication and cannot register pqcauth")
	default:
		report.AccountAuthentication = "unsupported"
		report.Issues = append(report.Issues, "account public-key type is not eligible for pqcauth")
	}

	pageRequest := func() *query.PageRequest {
		return &query.PageRequest{Limit: limit, CountTotal: false}
	}
	authzResponse, err := queryAuthz(ctx, &authz.QueryGranterGrantsRequest{
		Granter:    address,
		Pagination: pageRequest(),
	})
	if err != nil {
		return protectionReadinessReport{}, fmt.Errorf("query authz grants by granter: %w", err)
	}
	if authzResponse == nil {
		return protectionReadinessReport{}, errors.New("query authz grants returned an empty response")
	}
	if uint64(len(authzResponse.Grants)) > limit {
		return protectionReadinessReport{}, errors.New("query authz grants exceeded the requested result limit")
	}
	for _, grant := range authzResponse.Grants {
		if grant == nil {
			return protectionReadinessReport{}, errors.New("query authz grants returned a nil grant")
		}
		if grant.Granter != address {
			return protectionReadinessReport{}, errors.New("query authz grants returned a mismatched granter")
		}
		capability := protectionReadinessCapability{Kind: "authz", Grantee: grant.Grantee}
		if grant.Authorization != nil {
			capability.TypeURL = grant.Authorization.TypeUrl
		}
		if grant.Expiration != nil {
			capability.Expiration = grant.Expiration.UTC().Format(time.RFC3339)
		}
		report.AuthzGrants = append(report.AuthzGrants, capability)
	}
	if authzResponse.Pagination != nil {
		report.AuthzResultsTruncated = len(authzResponse.Pagination.NextKey) != 0
	}

	feegrantResponse, err := queryFeegrant(ctx, &feegrant.QueryAllowancesByGranterRequest{
		Granter:    address,
		Pagination: pageRequest(),
	})
	if err != nil {
		return protectionReadinessReport{}, fmt.Errorf("query feegrant allowances by granter: %w", err)
	}
	if feegrantResponse == nil {
		return protectionReadinessReport{}, errors.New("query feegrant allowances returned an empty response")
	}
	if uint64(len(feegrantResponse.Allowances)) > limit {
		return protectionReadinessReport{}, errors.New("query feegrant allowances exceeded the requested result limit")
	}
	for _, allowance := range feegrantResponse.Allowances {
		if allowance == nil {
			return protectionReadinessReport{}, errors.New("query feegrant allowances returned a nil allowance")
		}
		if allowance.Granter != address {
			return protectionReadinessReport{}, errors.New("query feegrant allowances returned a mismatched granter")
		}
		capability := protectionReadinessCapability{Kind: "feegrant", Grantee: allowance.Grantee}
		if allowance.Allowance != nil {
			capability.TypeURL = allowance.Allowance.TypeUrl
		}
		report.FeegrantAllowances = append(report.FeegrantAllowances, capability)
	}
	if feegrantResponse.Pagination != nil {
		report.FeegrantResultsTruncated = len(feegrantResponse.Pagination.NextKey) != 0
	}

	report.CapabilityCleanupReady = len(report.AuthzGrants) == 0 && len(report.FeegrantAllowances) == 0 &&
		!report.AuthzResultsTruncated && !report.FeegrantResultsTruncated
	if len(report.AuthzGrants) != 0 || report.AuthzResultsTruncated {
		report.Issues = append(report.Issues, "revoke all authz grants issued by this account before enabling pqcauth protection")
	}
	if len(report.FeegrantAllowances) != 0 || report.FeegrantResultsTruncated {
		report.Issues = append(report.Issues, "revoke all feegrant allowances issued by this account before enabling pqcauth protection")
	}
	report.Ready = report.PQCAuthEligible && report.CapabilityCleanupReady
	return report, nil
}
