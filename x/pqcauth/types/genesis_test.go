package types

import (
	"bytes"
	"testing"

	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/stretchr/testify/require"

	pqccrypto "github.com/DoraFactory/doravota/x/pqcauth/crypto"
)

func validGenesisForTest(t testing.TB) GenesisState {
	t.Helper()
	publicKeySize, _, err := pqccrypto.Sizes(pqccrypto.AlgorithmMLDSA65)
	require.NoError(t, err)
	owner := sdk.AccAddress(bytes.Repeat([]byte{0x91}, 20)).String()
	return GenesisState{
		Params: DefaultParams(),
		Keys: []PQCKeyRecord{
			{
				Owner:           owner,
				KeyId:           1,
				Algorithm:       Algorithm_ALGORITHM_ML_DSA_65,
				PublicKey:       make([]byte, publicKeySize),
				Role:            KeyRole_KEY_ROLE_SIGNING,
				Status:          KeyStatus_KEY_STATUS_LIVE,
				EffectiveHeight: 1,
			},
			{
				Owner:           owner,
				KeyId:           2,
				Algorithm:       Algorithm_ALGORITHM_ML_DSA_65,
				PublicKey:       make([]byte, publicKeySize),
				Role:            KeyRole_KEY_ROLE_RECOVERY,
				Status:          KeyStatus_KEY_STATUS_LIVE,
				EffectiveHeight: 1,
			},
		},
		Policies: []AccountPolicy{{
			Owner:               owner,
			CurrentSigningKeyId: 1,
			RecoveryKeyId:       2,
			PolicyVersion:       1,
		}},
		KeySequences: []AccountKeySequence{{
			Owner:     owner,
			NextKeyId: 3,
		}},
	}
}

func TestDefaultAndPopulatedGenesisValidate(t *testing.T) {
	require.NoError(t, ValidateGenesis(*DefaultGenesisState()))
	require.NoError(t, ValidateGenesis(validGenesisForTest(t)))
}

func TestGenesisValidationRejectsInconsistentState(t *testing.T) {
	testCases := []struct {
		name   string
		mutate func(*GenesisState)
	}{
		{"params", func(genesis *GenesisState) { genesis.Params.NetworkId = nil }},
		{"key owner", func(genesis *GenesisState) { genesis.Keys[0].Owner = "invalid" }},
		{"key id", func(genesis *GenesisState) { genesis.Keys[0].KeyId = 0 }},
		{"key algorithm", func(genesis *GenesisState) {
			genesis.Keys[0].Algorithm = Algorithm(99)
		}},
		{"public key size", func(genesis *GenesisState) { genesis.Keys[0].PublicKey = nil }},
		{"role", func(genesis *GenesisState) {
			genesis.Keys[0].Role = KeyRole_KEY_ROLE_UNSPECIFIED
		}},
		{"status", func(genesis *GenesisState) {
			genesis.Keys[0].Status = KeyStatus_KEY_STATUS_UNSPECIFIED
		}},
		{"revoked current signing key", func(genesis *GenesisState) {
			genesis.Keys[0].Status = KeyStatus_KEY_STATUS_REVOKED
		}},
		{"revoked recovery key", func(genesis *GenesisState) {
			genesis.Keys[1].Status = KeyStatus_KEY_STATUS_REVOKED
		}},
		{"maximum key identifier", func(genesis *GenesisState) {
			genesis.Keys[0].KeyId = ^uint64(0)
		}},
		{"height window", func(genesis *GenesisState) {
			genesis.Keys[0].InactiveFromHeight = genesis.Keys[0].EffectiveHeight
		}},
		{"duplicate key", func(genesis *GenesisState) {
			genesis.Keys = append(genesis.Keys, genesis.Keys[0])
		}},
		{"policy owner", func(genesis *GenesisState) {
			genesis.Policies[0].Owner = "invalid"
		}},
		{"duplicate policy", func(genesis *GenesisState) {
			genesis.Policies = append(genesis.Policies, genesis.Policies[0])
		}},
		{"policy without signing key", func(genesis *GenesisState) {
			genesis.Policies[0].CurrentSigningKeyId = 0
		}},
		{"missing current signing key", func(genesis *GenesisState) {
			genesis.Policies[0].CurrentSigningKeyId = 9
		}},
		{"zero policy version", func(genesis *GenesisState) {
			genesis.Policies[0].PolicyVersion = 0
		}},
		{"incomplete pending policy", func(genesis *GenesisState) {
			genesis.Policies[0].PendingSigningKeyId = 2
			genesis.Policies[0].PendingEffectiveHeight = 2
			genesis.Policies[0].PendingPolicyVersion = 2
		}},
		{"missing pending recovery key", func(genesis *GenesisState) {
			signing := genesis.Keys[0]
			signing.KeyId = 3
			genesis.Keys = append(genesis.Keys, signing)
			genesis.Policies[0].PendingSigningKeyId = 3
			genesis.Policies[0].PendingRecoveryKeyId = 9
			genesis.Policies[0].PendingEffectiveHeight = 2
			genesis.Policies[0].PendingPolicyVersion = 2
		}},
		{"missing recovery key", func(genesis *GenesisState) {
			genesis.Policies[0].RecoveryKeyId = 9
		}},
		{"sequence owner", func(genesis *GenesisState) {
			genesis.KeySequences[0].Owner = "invalid"
		}},
		{"duplicate sequence", func(genesis *GenesisState) {
			genesis.KeySequences = append(
				genesis.KeySequences,
				genesis.KeySequences[0],
			)
		}},
		{"zero next id", func(genesis *GenesisState) {
			genesis.KeySequences[0].NextKeyId = 0
		}},
		{"next id behind key", func(genesis *GenesisState) {
			genesis.KeySequences[0].NextKeyId = 2
		}},
		{"next id exceeds lifetime quota", func(genesis *GenesisState) {
			genesis.KeySequences[0].NextKeyId =
				uint64(genesis.Params.EffectiveMaxKeysPerAccount()) + 2
		}},
		{"key count exceeds lifetime quota", func(genesis *GenesisState) {
			for id := uint64(3); id <= 9; id++ {
				key := genesis.Keys[0]
				key.KeyId = id
				genesis.Keys = append(genesis.Keys, key)
			}
		}},
		{"pending policy version skips generation", func(genesis *GenesisState) {
			pending := genesis.Keys[0]
			pending.KeyId = 3
			pending.EffectiveHeight = 20
			genesis.Keys[0].InactiveFromHeight = 20
			genesis.Keys = append(genesis.Keys, pending)
			genesis.Policies[0].PendingSigningKeyId = 3
			genesis.Policies[0].PendingEffectiveHeight = 20
			genesis.Policies[0].PendingPolicyVersion = 3
		}},
		{"pending key activation mismatch", func(genesis *GenesisState) {
			pending := genesis.Keys[0]
			pending.KeyId = 3
			pending.EffectiveHeight = 21
			genesis.Keys[0].InactiveFromHeight = 20
			genesis.Keys = append(genesis.Keys, pending)
			genesis.Policies[0].PendingSigningKeyId = 3
			genesis.Policies[0].PendingEffectiveHeight = 20
			genesis.Policies[0].PendingPolicyVersion = 2
		}},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			genesis := validGenesisForTest(t)
			testCase.mutate(&genesis)
			require.Error(t, ValidateGenesis(genesis))
		})
	}
}
