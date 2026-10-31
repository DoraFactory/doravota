package app_test

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	pqcclient "github.com/DoraFactory/doravota/x/pqcauth/client"
	pqctypes "github.com/DoraFactory/doravota/x/pqcauth/types"
	abci "github.com/cometbft/cometbft/abci/types"
	"github.com/cosmos/cosmos-sdk/crypto/hd"
	"github.com/cosmos/cosmos-sdk/crypto/keyring"
	sdk "github.com/cosmos/cosmos-sdk/types"
	banktypes "github.com/cosmos/cosmos-sdk/x/bank/types"
	"github.com/cosmos/cosmos-sdk/x/feegrant"
	"github.com/stretchr/testify/require"
)

func reviewEnroll(t *testing.T, c *pqcChain) (pqcclient.PQCSigner, pqcclient.PQCSigner) {
	t.Helper()
	signer, _, next := reviewEnrollWithRecovery(t, c)
	return signer, next
}

func reviewEnrollWithRecovery(t *testing.T, c *pqcChain) (pqcclient.PQCSigner, pqcclient.PQCSigner, pqcclient.PQCSigner) {
	t.Helper()
	keys := keyring.NewInMemory(c.app.AppCodec())
	for _, name := range []string{"sign", "recovery", "next"} {
		_, _, err := keys.NewMnemonic(name, keyring.English, "m/44'/118'/0'/0/0", "", hd.MlDsa65)
		require.NoError(t, err)
	}
	signer, err := pqcclient.NewKeyringSigner(keys, "sign")
	require.NoError(t, err)
	recovery, err := pqcclient.NewKeyringSigner(keys, "recovery")
	require.NoError(t, err)
	next, err := pqcclient.NewKeyringSigner(keys, "next")
	require.NoError(t, err)
	pub, proof := reviewProof(t, c, signer, 1, pqctypes.KeyRole_KEY_ROLE_SIGNING, pqctypes.PurposeRegisterSigning, 0, pqctypes.RegisterProofContext)
	rpub, rproof := reviewProof(t, c, recovery, 2, pqctypes.KeyRole_KEY_ROLE_RECOVERY, pqctypes.PurposeRegisterRecovery, 0, pqctypes.RegisterProofContext)
	msg := &pqctypes.MsgRegisterKey{Owner: sdk.AccAddress(c.key.PubKey().Address()).String(), ExpectedSigningKeyId: 1, SigningAlgorithm: pqctypes.Algorithm_ALGORITHM_ML_DSA_65, SigningPublicKey: pub, SigningKeyProof: proof, RecoveryAlgorithm: pqctypes.Algorithm_ALGORITHM_ML_DSA_65, RecoveryPublicKey: rpub, RecoveryKeyProof: rproof, SelfEnforce: true}
	result := c.block(t, c.tx(t, c.key, nil, msg))
	require.Zero(t, result.Code, result.Log)
	c.block(t, nil)
	return signer, recovery, next
}

func reviewProof(t *testing.T, c *pqcChain, s pqcclient.PQCSigner, id uint64, role pqctypes.KeyRole, purpose string, version uint64, domain string) ([]byte, []byte) {
	t.Helper()
	pub, err := s.PublicKey(context.Background())
	require.NoError(t, err)
	doc, err := pqctypes.MarshalKeyProofDocV1(pqctypes.KeyProofDocV1{FormatVersion: 1, NetworkId: c.app.PQCAuthKeeper.GetParams(c.app.NewContext(true)).NetworkId, ChainId: "policy-test", Owner: sdk.AccAddress(c.key.PubKey().Address()).String(), ProposedKeyId: id, Algorithm: pqctypes.Algorithm_ALGORITHM_ML_DSA_65, PublicKey: pub, Role: role, Purpose: purpose, CurrentPolicyVersion: version})
	require.NoError(t, err)
	sig, err := s.Sign(context.Background(), doc, []byte(domain))
	require.NoError(t, err)
	return pub, sig
}

func TestPQCAuthRevokeRetiredKeyPreservesStateAudit(t *testing.T) {
	c := newPQCChain(t)
	signer, next := reviewEnroll(t, c)
	pub, proof := reviewProof(t, c, next, 3, pqctypes.KeyRole_KEY_ROLE_SIGNING, pqctypes.PurposeRotateSigning, 1, pqctypes.RotateProofContext)
	rotate := &pqctypes.MsgRotateKey{Owner: sdk.AccAddress(c.key.PubKey().Address()).String(), ExpectedNewKeyId: 3, NewAlgorithm: pqctypes.Algorithm_ALGORITHM_ML_DSA_65, NewPublicKey: pub, NewKeyProof: proof}
	result := c.block(t, c.tx(t, c.key, signer, rotate))
	require.Zero(t, result.Code, result.Log)
	c.block(t, nil)
	before := c.app.PQCAuthKeeper.AuditState(c.app.NewContext(true).WithBlockHeight(c.height), 100)
	require.True(t, before.Consistent, "%+v", before.Issues)
	revoke := &pqctypes.MsgRevokeKey{Owner: rotate.Owner, KeyId: 1}
	result = c.block(t, c.tx(t, c.key, next, revoke))
	require.Zero(t, result.Code, result.Log)
	after := c.app.PQCAuthKeeper.AuditState(c.app.NewContext(true).WithBlockHeight(c.height), 100)
	require.True(t, after.Consistent, "successful rotation and revoke corrupted audit: %+v", after.Issues)
}

func TestPQCAuthFeegrantExpiryPreservesSDKSemantics(t *testing.T) {
	c := newPQCChain(t)
	owner := sdk.AccAddress(c.key.PubKey().Address())
	recipient := sdk.AccAddress(c.other.PubKey().Address())
	expiration := c.stamp.Add(3 * time.Second)
	grant, err := feegrant.NewMsgGrantAllowance(&feegrant.BasicAllowance{Expiration: &expiration}, owner, recipient)
	require.NoError(t, err)
	result := c.block(t, c.tx(t, c.key, nil, grant))
	require.Zero(t, result.Code, result.Log)
	c.block(t, nil)
	ctx := c.app.NewContext(true).WithBlockHeight(c.height).WithBlockTime(expiration)
	_, err = c.app.FeeGrantKeeper.GetAllowance(ctx, owner, recipient)
	require.Error(t, err, "canonical feegrant must be removed at expiration equality")
	report := c.app.PQCAuthKeeper.AuditState(ctx, 100)
	require.True(t, report.Consistent, "core state audit: %+v", report.Issues)
	t.Run("enrollment_after_expiration", func(t *testing.T) {
		reviewEnroll(t, c)
	})
	// Successful enrollment must leave core PQC state consistent.
	ctx = c.app.NewContext(true).WithBlockHeight(c.height)
	report = c.app.PQCAuthKeeper.AuditState(ctx, 100)
	require.True(t, report.Consistent, "core state after enrollment: %+v", report.Issues)
}

// A zero-height export must fail before preparing/mutating export state. A
// normal-height export retains usable keys and remains importable.
func TestPQCAuthExportHeightSafety(t *testing.T) {
	c := newPQCChain(t)
	signer, _ := reviewEnroll(t, c)
	owner := sdk.AccAddress(c.key.PubKey().Address())
	send := banktypes.NewMsgSend(owner, sdk.AccAddress(c.other.PubKey().Address()), sdk.NewCoins(sdk.NewInt64Coin(sdk.DefaultBondDenom, 1)))
	signedTransfer := c.tx(t, c.key, signer, send)
	before, err := c.app.ExportAppStateAndValidators(false, nil, nil)
	require.NoError(t, err)
	_, err = c.app.ExportAppStateAndValidators(true, nil, nil)
	require.ErrorContains(t, err, "zero-height export is unsupported with PQCAuth")
	after, err := c.app.ExportAppStateAndValidators(false, nil, nil)
	require.NoError(t, err)
	require.Equal(t, before, after, "rejected export must not change application state")
	var state map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(after.AppState, &state))
	var genesis pqctypes.GenesisState
	require.NoError(t, c.app.AppCodec().UnmarshalJSON(state[pqctypes.ModuleName], &genesis))
	require.NoError(t, pqctypes.ValidateGenesis(genesis))
	restored := policyTestApp(t)
	stamp := c.stamp.Add(time.Hour)
	_, err = restored.InitChain(&abci.RequestInitChain{ChainId: "policy-test", InitialHeight: after.Height, Time: stamp, ConsensusParams: &after.ConsensusParams, AppStateBytes: after.AppState})
	require.NoError(t, err)
	restarted := &pqcChain{app: restored, key: c.key, other: c.other, height: after.Height - 1, stamp: stamp}
	result := restarted.block(t, signedTransfer)
	require.Zero(t, result.Code, "protected transfer after normal-height import: %s", result.Log)
}

func TestPQCAuthEmptyStateZeroHeightExport(t *testing.T) {
	c := newPQCChain(t)
	exported, err := c.app.ExportAppStateAndValidators(true, nil, nil)
	require.NoError(t, err)
	require.Zero(t, exported.Height)
}
