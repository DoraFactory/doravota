package cmd

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	sdkmldsa65 "github.com/cosmos/cosmos-sdk/crypto/keys/mldsa65"
	"github.com/cosmos/cosmos-sdk/crypto/keys/secp256k1"
	sdk "github.com/cosmos/cosmos-sdk/types"
	authtypes "github.com/cosmos/cosmos-sdk/x/auth/types"
	"github.com/stretchr/testify/require"

	"github.com/DoraFactory/doravota/app"
	pqcauthtypes "github.com/DoraFactory/doravota/x/pqcauth/types"
)

func TestPQCAuthAuditStateCommandAcceptsConsistentExport(t *testing.T) {
	encodingConfig := app.MakeEncodingConfig()
	pqcRaw, err := encodingConfig.Marshaler.MarshalJSON(pqcauthtypes.DefaultGenesisState())
	require.NoError(t, err)
	authRaw, err := encodingConfig.Marshaler.MarshalJSON(authtypes.DefaultGenesisState())
	require.NoError(t, err)
	export := marshalAuditExport(t, map[string]json.RawMessage{
		pqcauthtypes.ModuleName: pqcRaw,
		authtypes.ModuleName:    authRaw,
	})

	command := pqcauthAuditStateCommand(encodingConfig)
	command.SilenceUsage = true
	command.SilenceErrors = true
	output := new(bytes.Buffer)
	command.SetOut(output)
	command.SetArgs([]string{export, "--height", "10"})
	require.NoError(t, command.Execute())

	var report pqcauthtypes.StateAuditReport
	require.NoError(t, json.Unmarshal(output.Bytes(), &report))
	require.True(t, report.Consistent)
	require.Equal(t, int64(10), report.Height)
}

func TestPQCAuthAuditStateCommandFailsClosedWithoutAuthState(t *testing.T) {
	encodingConfig := app.MakeEncodingConfig()
	pqcRaw, err := encodingConfig.Marshaler.MarshalJSON(pqcauthtypes.DefaultGenesisState())
	require.NoError(t, err)
	export := marshalAuditExport(t, map[string]json.RawMessage{
		pqcauthtypes.ModuleName: pqcRaw,
	})

	command := pqcauthAuditStateCommand(encodingConfig)
	command.SilenceUsage = true
	command.SilenceErrors = true
	output := new(bytes.Buffer)
	command.SetOut(output)
	command.SetArgs([]string{export})
	err = command.Execute()
	require.ErrorIs(t, err, pqcauthtypes.ErrInconsistentState)

	var report pqcauthtypes.StateAuditReport
	require.NoError(t, json.Unmarshal(output.Bytes(), &report))
	require.False(t, report.Consistent)
	require.Equal(t, "missing_auth_state", report.Issues[0].Code)
}

func TestAuditExportedOwnerAccountsClassifiesClassicAndNativeOwners(t *testing.T) {
	classicKey := secp256k1.GenPrivKey()
	classicAddress := sdk.AccAddress(classicKey.PubKey().Address())
	classic := authtypes.NewBaseAccount(classicAddress, classicKey.PubKey(), 1, 0)
	nativeKey, err := sdkmldsa65.GenPrivKey()
	require.NoError(t, err)
	nativeAddress := sdk.AccAddress(nativeKey.PubKey().Address())
	native := authtypes.NewBaseAccount(nativeAddress, nativeKey.PubKey(), 2, 0)
	missingAddress := sdk.AccAddress(bytes.Repeat([]byte{0x77}, 20))
	genesis := pqcauthtypes.GenesisState{Keys: []pqcauthtypes.PQCKeyRecord{
		{Owner: classicAddress.String()},
		{Owner: nativeAddress.String()},
		{Owner: missingAddress.String()},
	}}
	report := pqcauthtypes.NewStateAuditReport(10)

	auditExportedOwnerAccounts(
		&report,
		100,
		genesis,
		authtypes.GenesisAccounts{classic, native},
	)

	require.False(t, report.Consistent)
	require.Equal(t, uint64(2), report.TotalIssues)
	codes := map[string]bool{}
	for _, issue := range report.Issues {
		codes[issue.Code] = true
	}
	require.True(t, codes["native_pqc_owner"])
	require.True(t, codes["owner_account_not_found"])
}

func marshalAuditExport(t testing.TB, appState map[string]json.RawMessage) string {
	t.Helper()
	raw, err := json.Marshal(map[string]any{"app_state": appState})
	require.NoError(t, err)
	path := filepath.Join(t.TempDir(), "export.json")
	require.NoError(t, os.WriteFile(path, raw, 0o600))
	return path
}
