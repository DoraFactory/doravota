package cmd

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/cosmos/cosmos-sdk/codec/types"
	sdkmldsa65 "github.com/cosmos/cosmos-sdk/crypto/keys/mldsa65"
	"github.com/cosmos/cosmos-sdk/crypto/keys/secp256k1"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/cosmos/cosmos-sdk/types/query"
	authtypes "github.com/cosmos/cosmos-sdk/x/auth/types"
	"github.com/cosmos/cosmos-sdk/x/authz"
	"github.com/cosmos/cosmos-sdk/x/feegrant"
	"github.com/stretchr/testify/require"
)

func TestBuildProtectionReadinessReportAcceptsFreshClassicAccount(t *testing.T) {
	address := sdk.AccAddress(secp256k1.GenPrivKey().PubKey().Address())
	account := authtypes.NewBaseAccount(address, nil, 1, 0)

	report, err := buildProtectionReadinessReport(
		context.Background(),
		account,
		20,
		emptyAuthzGrants,
		emptyFeegrantAllowances,
	)
	require.NoError(t, err)
	require.True(t, report.Ready)
	require.True(t, report.PQCAuthEligible)
	require.True(t, report.CapabilityCleanupReady)
	require.True(t, report.FreshAccountCandidate)
	require.False(t, report.PublicKeyPublished)
	require.Equal(t, "classic_key_not_published", report.AccountAuthentication)
}

func TestBuildProtectionReadinessReportListsOutstandingCapabilities(t *testing.T) {
	privateKey := secp256k1.GenPrivKey()
	address := sdk.AccAddress(privateKey.PubKey().Address())
	account := authtypes.NewBaseAccount(address, privateKey.PubKey(), 1, 7)
	expiration := time.Unix(1_800_000_000, 0).UTC()

	report, err := buildProtectionReadinessReport(
		context.Background(),
		account,
		20,
		func(_ context.Context, request *authz.QueryGranterGrantsRequest) (*authz.QueryGranterGrantsResponse, error) {
			require.Equal(t, address.String(), request.Granter)
			require.Equal(t, uint64(20), request.Pagination.Limit)
			require.False(t, request.Pagination.CountTotal)
			return &authz.QueryGranterGrantsResponse{
				Grants: []*authz.GrantAuthorization{{
					Granter:       address.String(),
					Grantee:       sdk.AccAddress([]byte("authz-grantee-0000000")).String(),
					Authorization: &types.Any{TypeUrl: "/cosmos.bank.v1beta1.SendAuthorization"},
					Expiration:    &expiration,
				}},
				Pagination: &query.PageResponse{NextKey: []byte{1}},
			}, nil
		},
		func(_ context.Context, request *feegrant.QueryAllowancesByGranterRequest) (*feegrant.QueryAllowancesByGranterResponse, error) {
			require.Equal(t, address.String(), request.Granter)
			return &feegrant.QueryAllowancesByGranterResponse{
				Allowances: []*feegrant.Grant{{
					Granter:   address.String(),
					Grantee:   sdk.AccAddress([]byte("fee-grantee-00000000")).String(),
					Allowance: &types.Any{TypeUrl: "/cosmos.feegrant.v1beta1.BasicAllowance"},
				}},
			}, nil
		},
	)
	require.NoError(t, err)
	require.False(t, report.Ready)
	require.False(t, report.CapabilityCleanupReady)
	require.True(t, report.AuthzResultsTruncated)
	require.Len(t, report.AuthzGrants, 1)
	require.Equal(t, expiration.Format(time.RFC3339), report.AuthzGrants[0].Expiration)
	require.Len(t, report.FeegrantAllowances, 1)
	require.Len(t, report.Issues, 2)
}

func TestBuildProtectionReadinessReportRejectsNativeMLDSAAccount(t *testing.T) {
	privateKey, err := sdkmldsa65.GenPrivKey()
	require.NoError(t, err)
	address := sdk.AccAddress(privateKey.PubKey().Address())
	account := authtypes.NewBaseAccount(address, privateKey.PubKey(), 1, 0)

	report, err := buildProtectionReadinessReport(
		context.Background(),
		account,
		20,
		emptyAuthzGrants,
		emptyFeegrantAllowances,
	)
	require.NoError(t, err)
	require.False(t, report.Ready)
	require.False(t, report.PQCAuthEligible)
	require.True(t, report.CapabilityCleanupReady)
	require.Equal(t, "native_mldsa65", report.AccountAuthentication)
	require.Contains(t, report.Issues[0], "cannot register pqcauth")
}

func TestBuildProtectionReadinessReportFailsClosedOnQueryError(t *testing.T) {
	privateKey := secp256k1.GenPrivKey()
	address := sdk.AccAddress(privateKey.PubKey().Address())
	account := authtypes.NewBaseAccount(address, privateKey.PubKey(), 1, 0)
	expected := errors.New("rpc unavailable")

	_, err := buildProtectionReadinessReport(
		context.Background(),
		account,
		20,
		func(context.Context, *authz.QueryGranterGrantsRequest) (*authz.QueryGranterGrantsResponse, error) {
			return nil, expected
		},
		emptyFeegrantAllowances,
	)
	require.ErrorIs(t, err, expected)
	require.Contains(t, err.Error(), "query authz grants by granter")
}

func TestBuildProtectionReadinessReportFailsClosedOnMalformedQueryResult(t *testing.T) {
	privateKey := secp256k1.GenPrivKey()
	address := sdk.AccAddress(privateKey.PubKey().Address())
	account := authtypes.NewBaseAccount(address, privateKey.PubKey(), 1, 0)

	_, err := buildProtectionReadinessReport(
		context.Background(),
		account,
		20,
		func(context.Context, *authz.QueryGranterGrantsRequest) (*authz.QueryGranterGrantsResponse, error) {
			return &authz.QueryGranterGrantsResponse{
				Grants: []*authz.GrantAuthorization{{Granter: "unexpected"}},
			}, nil
		},
		emptyFeegrantAllowances,
	)
	require.EqualError(t, err, "query authz grants returned a mismatched granter")
}

func emptyAuthzGrants(
	context.Context,
	*authz.QueryGranterGrantsRequest,
) (*authz.QueryGranterGrantsResponse, error) {
	return &authz.QueryGranterGrantsResponse{}, nil
}

func emptyFeegrantAllowances(
	context.Context,
	*feegrant.QueryAllowancesByGranterRequest,
) (*feegrant.QueryAllowancesByGranterResponse, error) {
	return &feegrant.QueryAllowancesByGranterResponse{}, nil
}
