package cli

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestValidateProtectedSigningOptions(t *testing.T) {
	require.NoError(t, validateProtectedSigningOptions(true, "", ""))
	require.NoError(t, validateProtectedSigningOptions(false, "account.mldsa65", ""))
	require.NoError(t, validateProtectedSigningOptions(false, "", "prepared.pqcbundle"))

	err := validateProtectedSigningOptions(false, "", "")
	require.ErrorContains(t, err, "--"+flagPQCPrivateKey)
	require.ErrorContains(t, err, "--"+flagPQCSignBundleOutput)

	err = validateProtectedSigningOptions(
		true,
		"account.mldsa65",
		"prepared.pqcbundle",
	)
	require.ErrorContains(t, err, "mutually exclusive")
}
