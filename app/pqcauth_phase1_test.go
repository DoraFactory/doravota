package app_test

import (
	"context"
	"encoding/binary"
	"testing"

	"github.com/DoraFactory/doravota/app"
	"github.com/DoraFactory/doravota/x/pqcauth"
	pqccrypto "github.com/DoraFactory/doravota/x/pqcauth/crypto"
	pqctypes "github.com/DoraFactory/doravota/x/pqcauth/types"
	tmproto "github.com/cometbft/cometbft/proto/tendermint/types"
	storetypes "github.com/cosmos/cosmos-sdk/store/v2/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
	txtypes "github.com/cosmos/cosmos-sdk/types/tx"
	authtypes "github.com/cosmos/cosmos-sdk/x/auth/types"
	"github.com/cosmos/cosmos-sdk/x/authz"
	banktypes "github.com/cosmos/cosmos-sdk/x/bank/types"
	"github.com/cosmos/cosmos-sdk/x/feegrant"
	upgradetypes "github.com/cosmos/cosmos-sdk/x/upgrade/types"
	"github.com/stretchr/testify/require"
)

func TestPQCAuthPhaseOnePreservesDelegationSemantics(t *testing.T) {
	c := newPQCChain(t)
	a := c.app
	owner := sdk.AccAddress(c.key.PubKey().Address())
	grantee := sdk.AccAddress(c.other.PubKey().Address())
	send := banktypes.NewMsgSend(owner, grantee, sdk.NewCoins(sdk.NewInt64Coin(sdk.DefaultBondDenom, 7)))
	exec := authz.NewMsgExec(grantee, []sdk.Msg{send})
	result := c.block(t, c.tx(t, c.other, nil, &exec))
	require.NotZero(t, result.Code, "delegated execution still requires an SDK grant")
	grant, err := authz.NewMsgGrant(owner, grantee, authz.NewGenericAuthorization(sdk.MsgTypeURL(send)), nil)
	require.NoError(t, err)
	fees, err := feegrant.NewMsgGrantAllowance(&feegrant.BasicAllowance{}, owner, grantee)
	require.NoError(t, err)
	result = c.block(t, c.tx(t, c.key, nil, grant, fees))
	require.Zero(t, result.Code, result.Log)

	// Existing delegations do not prevent enrollment and are not revoked by it.
	signer, _ := reviewEnroll(t, c)
	result = c.block(t, c.tx(t, c.key, nil, send))
	require.NotZero(t, result.Code, "direct owner transactions must still carry PQC authorization")
	result = c.block(t, c.tx(t, c.key, signer, send))
	require.Zero(t, result.Code, result.Log)
	before := a.BankKeeper.GetBalance(a.NewContext(true), owner, sdk.DefaultBondDenom).Amount
	result = c.block(t, c.tx(t, c.other, nil, &exec))
	require.Zero(t, result.Code, result.Log)
	require.Equal(t, before.SubRaw(7), a.BankKeeper.GetBalance(a.NewContext(true), owner, sdk.DefaultBondDenom).Amount)
	selfSend := banktypes.NewMsgSend(grantee, grantee, sdk.NewCoins(sdk.NewInt64Coin(sdk.DefaultBondDenom, 1)))
	before = a.BankKeeper.GetBalance(a.NewContext(true), owner, sdk.DefaultBondDenom).Amount
	result = c.block(t, c.txWithFeeGranter(t, c.other, nil, owner, selfSend))
	require.Zero(t, result.Code, result.Log)
	require.Equal(t, before.SubRaw(10), a.BankKeeper.GetBalance(a.NewContext(true), owner, sdk.DefaultBondDenom).Amount)

	// Ordinary delegation changes are signed by the protected owner, but impose
	// no extra PQC enrollment requirement on the grantee.
	revokeAuth := &authz.MsgRevoke{Granter: owner.String(), Grantee: grantee.String(), MsgTypeUrl: sdk.MsgTypeURL(send)}
	revokeFee := feegrant.NewMsgRevokeAllowance(owner, grantee)
	result = c.block(t, c.tx(t, c.key, signer, revokeAuth, &revokeFee))
	require.Zero(t, result.Code, result.Log)
	result = c.block(t, c.tx(t, c.other, nil, &exec))
	require.NotZero(t, result.Code, "revoked Authz must stay unusable")
	result = c.block(t, c.txWithFeeGranter(t, c.other, nil, owner, selfSend))
	require.NotZero(t, result.Code, "revoked Feegrant must stay unusable")
	result = c.block(t, c.tx(t, c.key, signer, grant, fees))
	require.Zero(t, result.Code, result.Log)
	result = c.block(t, c.tx(t, c.other, nil, &exec))
	require.Zero(t, result.Code, result.Log)
	result = c.block(t, c.txWithFeeGranter(t, c.other, nil, owner, selfSend))
	require.Zero(t, result.Code, result.Log)
	// Protection may be disabled and re-enabled without rebuilding or clearing
	// grants. Both lifecycle changes still need the owner's current PQC factor.
	for _, enabled := range []bool{false, true} {
		result = c.block(t, c.tx(t, c.key, signer, &pqctypes.MsgSetProtection{Owner: owner.String(), Enabled: enabled}))
		require.Zero(t, result.Code, result.Log)
		c.block(t, nil)
	}
	result = c.block(t, c.tx(t, c.key, nil, send))
	require.NotZero(t, result.Code)
	result = c.block(t, c.tx(t, c.other, nil, &exec))
	require.Zero(t, result.Code, result.Log)

	// A protected grantee must satisfy its OWN PQC policy, even when executing
	// a delegation or using somebody else's fee allowance.
	ownerKey := c.key
	c.key = c.other
	granteeSigner, _ := reviewEnroll(t, c)
	c.key = ownerKey
	result = c.block(t, c.tx(t, c.other, nil, &exec))
	require.NotZero(t, result.Code)
	result = c.block(t, c.tx(t, c.other, granteeSigner, &exec))
	require.Zero(t, result.Code, result.Log)
	result = c.block(t, c.txWithFeeGranter(t, c.other, nil, owner, selfSend))
	require.NotZero(t, result.Code)
	result = c.block(t, c.txWithFeeGranter(t, c.other, granteeSigner, owner, selfSend))
	require.Zero(t, result.Code, result.Log)
	assertPhaseOneHasNoDelegationIndex(t, c)
}

func TestPQCAuthPhaseOneDelegationCannotManageKeys(t *testing.T) {
	c := newPQCChain(t)
	owner := sdk.AccAddress(c.key.PubKey().Address())
	grantee := sdk.AccAddress(c.other.PubKey().Address())
	lifecycle := []sdk.Msg{
		&pqctypes.MsgRegisterKey{Owner: owner.String()},
		&pqctypes.MsgRotateKey{Owner: owner.String()},
		&pqctypes.MsgRotateRecoveryKey{Owner: owner.String()},
		&pqctypes.MsgSetProtection{Owner: owner.String(), Enabled: false},
		&pqctypes.MsgRevokeKey{Owner: owner.String(), KeyId: 1},
		&pqctypes.MsgRecoverKey{Owner: owner.String()},
		&pqctypes.MsgCancelRecovery{Owner: owner.String()},
	}
	for _, msg := range lifecycle {
		grant, err := authz.NewMsgGrant(owner, grantee, authz.NewGenericAuthorization(sdk.MsgTypeURL(msg)), nil)
		require.NoError(t, err)
		result := c.block(t, c.tx(t, c.key, nil, grant))
		require.Zero(t, result.Code, result.Log)
	}
	signer, _ := reviewEnroll(t, c)
	before, found := c.app.PQCAuthKeeper.GetEffectiveAccountPolicy(c.app.NewContext(true).WithBlockHeight(c.height), owner)
	require.True(t, found)
	for _, msg := range lifecycle {
		t.Run(sdk.MsgTypeURL(msg), func(t *testing.T) {
			exec := authz.NewMsgExec(grantee, []sdk.Msg{msg})
			result := c.block(t, c.tx(t, c.other, nil, &exec))
			require.NotZero(t, result.Code)
			require.Contains(t, result.Log, "cannot be embedded")
		})
	}
	after, found := c.app.PQCAuthKeeper.GetEffectiveAccountPolicy(c.app.NewContext(true).WithBlockHeight(c.height), owner)
	require.True(t, found)
	require.Equal(t, before, after)
	// Rejected attempts do not stop subsequent authorized transactions.
	send := banktypes.NewMsgSend(owner, grantee, sdk.NewCoins(sdk.NewInt64Coin(sdk.DefaultBondDenom, 1)))
	result := c.block(t, c.tx(t, c.key, signer, send))
	require.Zero(t, result.Code, result.Log)
	assertPhaseOneHasNoDelegationIndex(t, c)
}

func TestPQCAuthPhaseOneRecoveryPreservesDelegations(t *testing.T) {
	params := pqctypes.DefaultParams()
	params.RecoveryDelayBlocks = 4 // Test-only challenge period.
	c := newPQCChain(t, params)
	owner := sdk.AccAddress(c.key.PubKey().Address())
	grantee := sdk.AccAddress(c.other.PubKey().Address())
	send := banktypes.NewMsgSend(owner, grantee, sdk.NewCoins(sdk.NewInt64Coin(sdk.DefaultBondDenom, 2)))
	grant, err := authz.NewMsgGrant(owner, grantee, authz.NewGenericAuthorization(sdk.MsgTypeURL(send)), nil)
	require.NoError(t, err)
	feeGrant, err := feegrant.NewMsgGrantAllowance(&feegrant.BasicAllowance{}, owner, grantee)
	require.NoError(t, err)
	result := c.block(t, c.tx(t, c.key, nil, grant, feeGrant))
	require.Zero(t, result.Code, result.Log)
	old, recovery, replacement := reviewEnrollWithRecovery(t, c)
	ctx := c.app.NewContext(true).WithBlockHeight(c.height + 1)
	policy, found := c.app.PQCAuthKeeper.GetEffectiveAccountPolicy(ctx, owner)
	require.True(t, found)
	pub, proof := reviewProof(t, c, replacement, 3, pqctypes.KeyRole_KEY_ROLE_SIGNING, pqctypes.PurposeRecoverSigning, policy.PolicyVersion, pqctypes.RecoveryKeyProofContext)
	_, signatureSize, err := pqccrypto.Sizes(pqccrypto.AlgorithmMLDSA65)
	require.NoError(t, err)
	msg := &pqctypes.MsgRecoverKey{
		Owner: owner.String(), RecoveryKeyId: 2, ExpectedNewSigningKeyId: 3,
		ExpectedRecoveryDelayBlocks: params.RecoveryDelayBlocks,
		NewSigningAlgorithm:         pqctypes.Algorithm_ALGORITHM_ML_DSA_65,
		NewSigningPublicKey:         pub, NewSigningKeyProof: proof,
		RecoverySignature: make([]byte, signatureSize),
	}
	unsigned, err := c.app.TxConfig().TxDecoder()(c.tx(t, c.key, nil, msg))
	require.NoError(t, err)
	account := c.app.AccountKeeper.GetAccount(ctx, owner)
	doc, err := pqctypes.NewRecoverySignDocV1(unsigned.(interface{ GetProtoTx() *txtypes.Tx }).GetProtoTx(),
		c.app.PQCAuthKeeper.GetParams(ctx).NetworkId, "policy-test", account.GetAccountNumber(), account.GetSequence(),
		0, owner.String(), owner.String(), 2, 3, msg.NewSigningAlgorithm, pub, policy.PolicyVersion)
	require.NoError(t, err)
	signBytes, err := pqctypes.MarshalRecoverySignDocV1(doc)
	require.NoError(t, err)
	msg.RecoverySignature, err = recovery.Sign(context.Background(), signBytes, []byte(pqctypes.RecoverySignatureContext))
	require.NoError(t, err)
	result = c.block(t, c.tx(t, c.key, nil, msg))
	require.Zero(t, result.Code, result.Log)
	// A future factor must not work before the challenge period ends.
	result = c.block(t, c.tx(t, c.key, replacement, send))
	require.NotZero(t, result.Code)
	for i := uint64(0); i < params.RecoveryDelayBlocks; i++ {
		c.block(t, nil)
	}
	result = c.block(t, c.tx(t, c.key, old, send))
	require.NotZero(t, result.Code, "the old PQC factor must no longer authorize direct transactions")
	result = c.block(t, c.tx(t, c.key, replacement, send))
	require.Zero(t, result.Code, result.Log)
	exec := authz.NewMsgExec(grantee, []sdk.Msg{send})
	result = c.block(t, c.tx(t, c.other, nil, &exec))
	require.Zero(t, result.Code, result.Log)
	before := c.app.BankKeeper.GetBalance(c.app.NewContext(true), owner, sdk.DefaultBondDenom).Amount
	selfSend := banktypes.NewMsgSend(grantee, grantee, sdk.NewCoins(sdk.NewInt64Coin(sdk.DefaultBondDenom, 1)))
	result = c.block(t, c.txWithFeeGranter(t, c.other, nil, owner, selfSend))
	require.Zero(t, result.Code, result.Log)
	require.Equal(t, before.SubRaw(10), c.app.BankKeeper.GetBalance(c.app.NewContext(true), owner, sdk.DefaultBondDenom).Amount)
	assertPhaseOneHasNoDelegationIndex(t, c)
}

func assertPhaseOneHasNoDelegationIndex(t *testing.T, c *pqcChain) {
	t.Helper()
	ctx := c.app.NewContext(true).WithBlockHeight(c.height)
	store := ctx.KVStore(c.app.GetKey(pqctypes.StoreKey))
	iterator := store.Iterator([]byte{0x06}, []byte{0x08})
	defer iterator.Close()
	require.False(t, iterator.Valid(), "phase one must never maintain legacy delegation indexes")
	report := c.app.PQCAuthKeeper.AuditState(ctx, 20)
	require.True(t, report.Consistent, "%+v", report.Issues)
}

// An upgrade test that fails on any access to these stores is independent of
// their cardinality: neither one grant nor millions may be read by PQC init.
type phaseOneGuardedMultiStore struct {
	storetypes.MultiStore
	forbidden map[storetypes.StoreKey]bool
}

func (s phaseOneGuardedMultiStore) GetKVStore(key storetypes.StoreKey) storetypes.KVStore {
	s.check(key)
	return s.MultiStore.GetKVStore(key)
}

func (s phaseOneGuardedMultiStore) check(key storetypes.StoreKey) {
	if s.forbidden[key] {
		panic("PQC upgrade accessed unrelated store: " + key.Name())
	}
}

func (s phaseOneGuardedMultiStore) GetStore(key storetypes.StoreKey) storetypes.Store {
	s.check(key)
	return s.MultiStore.GetStore(key)
}

func (s phaseOneGuardedMultiStore) GetObjKVStore(key storetypes.StoreKey) storetypes.ObjKVStore {
	s.check(key)
	return s.MultiStore.GetObjKVStore(key)
}

type phaseOneGuardedCache struct {
	phaseOneGuardedMultiStore
	write func()
}

func (s phaseOneGuardedCache) Write() { s.write() }

func (s phaseOneGuardedMultiStore) CacheMultiStore() storetypes.CacheMultiStore {
	cache := s.MultiStore.CacheMultiStore()
	return phaseOneGuardedCache{phaseOneGuardedMultiStore{cache, s.forbidden}, cache.Write}
}

func (s phaseOneGuardedMultiStore) CacheMultiStoreWithVersion(version int64) (storetypes.CacheMultiStore, error) {
	cache, err := s.MultiStore.CacheMultiStoreWithVersion(version)
	if err != nil {
		return nil, err
	}
	return phaseOneGuardedCache{phaseOneGuardedMultiStore{cache, s.forbidden}, cache.Write}, nil
}

func TestPQCAuthPhaseOneUpgradeDoesNotScanDelegations(t *testing.T) {
	c := newPQCChain(t)
	a := c.app
	ctx := a.NewNextBlockContext(tmproto.Header{ChainID: "policy-test", Height: c.height + 1})
	owner := sdk.AccAddress(c.key.PubKey().Address())
	for i := uint64(1); i <= 1000; i++ {
		grantee := make(sdk.AccAddress, 20)
		binary.BigEndian.PutUint64(grantee[12:], i)
		require.NoError(t, a.FeeGrantKeeper.SetBankKeeper(a.BankKeeper).GrantAllowance(ctx, owner, grantee, &feegrant.BasicAllowance{}))
	}
	ctx.KVStore(a.GetKey(upgradetypes.StoreKey)).Delete(append([]byte{upgradetypes.VersionMapByte}, []byte(pqctypes.ModuleName)...))
	ctx.KVStore(a.GetKey(pqctypes.StoreKey)).Delete(pqctypes.ParamsKey)
	guard := phaseOneGuardedMultiStore{MultiStore: ctx.MultiStore(), forbidden: map[storetypes.StoreKey]bool{
		a.GetKey(feegrant.StoreKey): true, a.GetKey(authz.ModuleName): true,
		a.GetKey(authtypes.StoreKey): true, a.GetKey(banktypes.StoreKey): true,
	}}
	require.NotPanics(t, func() {
		require.NoError(t, a.UpgradeKeeper.ApplyUpgrade(ctx.WithMultiStore(guard), upgradetypes.Plan{Name: app.PQCAuthUpgradeName, Height: c.height + 1}))
	})
	versions, err := a.UpgradeKeeper.GetModuleVersionMap(ctx)
	require.NoError(t, err)
	require.Equal(t, (pqcauth.AppModule{}).ConsensusVersion(), versions[pqctypes.ModuleName])
	count := 0
	require.NoError(t, a.FeeGrantKeeper.IterateAllFeeAllowances(ctx, func(grant feegrant.Grant) bool { count++; return false }))
	require.Equal(t, 1000, count)
	iterator := ctx.KVStore(a.GetKey(pqctypes.StoreKey)).Iterator(nil, nil)
	defer iterator.Close()
	require.True(t, iterator.Valid())
	require.Equal(t, pqctypes.ParamsKey, iterator.Key())
	iterator.Next()
	require.False(t, iterator.Valid(), "initialization must only write PQC parameters")
}
