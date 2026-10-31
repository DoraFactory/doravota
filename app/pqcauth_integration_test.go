package app_test

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/DoraFactory/doravota/app"
	"github.com/DoraFactory/doravota/app/wasmarchive"
	pqcclient "github.com/DoraFactory/doravota/x/pqcauth/client"
	pqctypes "github.com/DoraFactory/doravota/x/pqcauth/types"
	abci "github.com/cometbft/cometbft/abci/types"
	"github.com/cometbft/cometbft/crypto/ed25519"
	tmproto "github.com/cometbft/cometbft/proto/tendermint/types"
	tmtypes "github.com/cometbft/cometbft/types"
	sdkclient "github.com/cosmos/cosmos-sdk/client"
	sdktx "github.com/cosmos/cosmos-sdk/client/tx"
	codectypes "github.com/cosmos/cosmos-sdk/codec/types"
	"github.com/cosmos/cosmos-sdk/crypto/hd"
	"github.com/cosmos/cosmos-sdk/crypto/keyring"
	"github.com/cosmos/cosmos-sdk/crypto/keys/mldsa65"
	"github.com/cosmos/cosmos-sdk/crypto/keys/secp256k1"
	simtestutil "github.com/cosmos/cosmos-sdk/testutil/sims"
	sdk "github.com/cosmos/cosmos-sdk/types"
	txtypes "github.com/cosmos/cosmos-sdk/types/tx"
	"github.com/cosmos/cosmos-sdk/types/tx/signing"
	authsigning "github.com/cosmos/cosmos-sdk/x/auth/signing"
	authtypes "github.com/cosmos/cosmos-sdk/x/auth/types"
	"github.com/cosmos/cosmos-sdk/x/authz"
	banktypes "github.com/cosmos/cosmos-sdk/x/bank/types"
	"github.com/cosmos/cosmos-sdk/x/feegrant"
	upgradetypes "github.com/cosmos/cosmos-sdk/x/upgrade/types"
	"github.com/stretchr/testify/require"
)

type pqcChain struct {
	app    *app.App
	key    *secp256k1.PrivKey
	other  *secp256k1.PrivKey
	height int64
	stamp  time.Time
}

func newPQCChain(t *testing.T, params ...pqctypes.Params) *pqcChain {
	t.Helper()
	a := policyTestApp(t)
	key, other := secp256k1.GenPrivKey(), secp256k1.GenPrivKey()
	owner := sdk.AccAddress(key.PubKey().Address())
	second := sdk.AccAddress(other.PubKey().Address())
	cp := tmtypes.DefaultConsensusParams().ToProto()
	genesis, err := simtestutil.GenesisStateWithValSet(a.AppCodec(), app.NewDefaultGenesisState(a.AppCodec()), tmtypes.NewValidatorSet([]*tmtypes.Validator{tmtypes.NewValidator(ed25519.GenPrivKey().PubKey(), 1)}), []authtypes.GenesisAccount{authtypes.NewBaseAccountWithAddress(owner), authtypes.NewBaseAccountWithAddress(second)}, banktypes.Balance{Address: owner.String(), Coins: sdk.NewCoins(sdk.NewInt64Coin(sdk.DefaultBondDenom, 100000000))}, banktypes.Balance{Address: second.String(), Coins: sdk.NewCoins(sdk.NewInt64Coin(sdk.DefaultBondDenom, 1000000))})
	require.NoError(t, err)
	if len(params) != 0 {
		require.Len(t, params, 1)
		pqcGenesis := pqctypes.DefaultGenesisState()
		pqcGenesis.Params = params[0]
		genesis[pqctypes.ModuleName] = a.AppCodec().MustMarshalJSON(pqcGenesis)
	}
	raw, err := json.Marshal(genesis)
	require.NoError(t, err)
	stamp := time.Unix(1700000000, 0)
	_, err = a.InitChain(&abci.RequestInitChain{ChainId: "policy-test", InitialHeight: 1, Time: stamp, ConsensusParams: &cp, AppStateBytes: raw})
	require.NoError(t, err)
	chain := &pqcChain{a, key, other, 0, stamp}
	chain.block(t, nil)
	return chain
}
func (c *pqcChain) block(t *testing.T, raw []byte) *abci.ExecTxResult {
	t.Helper()
	c.height++
	var txs [][]byte
	if raw != nil {
		txs = [][]byte{raw}
	}
	result, err := c.app.FinalizeBlock(&abci.RequestFinalizeBlock{Height: c.height, Time: c.stamp.Add(time.Duration(c.height) * time.Second), Txs: txs})
	require.NoError(t, err)
	_, err = c.app.Commit()
	require.NoError(t, err)
	if raw == nil {
		return nil
	}
	require.Len(t, result.TxResults, 1)
	return result.TxResults[0]
}
func (c *pqcChain) tx(t *testing.T, key *secp256k1.PrivKey, factor pqcclient.PQCSigner, msgs ...sdk.Msg) []byte {
	return c.txWithFeeGranter(t, key, factor, nil, msgs...)
}
func (c *pqcChain) txWithFeeGranter(t *testing.T, key *secp256k1.PrivKey, factor pqcclient.PQCSigner, granter sdk.AccAddress, msgs ...sdk.Msg) []byte {
	t.Helper()
	ctx := c.app.NewContext(true)
	owner := sdk.AccAddress(key.PubKey().Address())
	acc := c.app.AccountKeeper.GetAccount(ctx, owner)
	b := c.app.TxConfig().NewTxBuilder()
	require.NoError(t, b.SetMsgs(msgs...))
	b.SetGasLimit(3000000)
	b.SetFeeAmount(sdk.NewCoins(sdk.NewInt64Coin(sdk.DefaultBondDenom, 10)))
	if granter != nil {
		b.SetFeeGranter(granter)
	}
	require.NoError(t, b.SetSignatures(signing.SignatureV2{PubKey: key.PubKey(), Sequence: acc.GetSequence(), Data: &signing.SingleSignatureData{SignMode: signing.SignMode_SIGN_MODE_DIRECT}}))
	if factor != nil {
		record, policy, active := c.app.PQCAuthKeeper.GetActiveSigningKey(ctx.WithBlockHeight(c.height+1), owner)
		require.True(t, active)
		protoTx := b.(interface{ GetProtoTx() *txtypes.Tx }).GetProtoTx()
		doc, err := pqctypes.NewPQCSignDocV1(protoTx, c.app.PQCAuthKeeper.GetParams(ctx).NetworkId, "policy-test", acc.GetAccountNumber(), acc.GetSequence(), 0, owner.String(), record.KeyId, record.Algorithm, policy.PolicyVersion)
		require.NoError(t, err)
		bytes, err := pqctypes.MarshalPQCSignDocV1(doc)
		require.NoError(t, err)
		sig, err := factor.Sign(context.Background(), bytes, []byte(pqctypes.TxSignatureContext))
		require.NoError(t, err)
		ext, err := codectypes.NewAnyWithValue(&pqctypes.ExtensionPQCAuth{FormatVersion: 1, Signatures: []pqctypes.SignerPQCSignature{{Signer: owner.String(), SignerIndex: 0, KeyId: record.KeyId, Algorithm: record.Algorithm, PolicyVersion: policy.PolicyVersion, Signature: sig}}})
		require.NoError(t, err)
		b.(sdkclient.ExtendedTxBuilder).SetExtensionOptions(ext)
	}
	sig, err := sdktx.SignWithPrivKey(context.Background(), signing.SignMode_SIGN_MODE_DIRECT, authsigning.SignerData{Address: owner.String(), ChainID: "policy-test", AccountNumber: acc.GetAccountNumber(), Sequence: acc.GetSequence(), PubKey: key.PubKey()}, b, key, c.app.TxConfig(), acc.GetSequence())
	require.NoError(t, err)
	require.NoError(t, b.SetSignatures(sig))
	raw, err := c.app.TxConfig().TxEncoder()(b.GetTx())
	require.NoError(t, err)
	return raw
}
func TestPQCAuthRealFailedMessagesKeepSDKFeegrantSemantics(t *testing.T) {
	c := newPQCChain(t)
	a := c.app
	owner := sdk.AccAddress(c.key.PubKey().Address())
	grantee := sdk.AccAddress(c.other.PubKey().Address())
	grant, err := feegrant.NewMsgGrantAllowance(&feegrant.BasicAllowance{}, owner, grantee)
	require.NoError(t, err)
	before := a.BankKeeper.GetBalance(a.NewContext(true), owner, sdk.DefaultBondDenom).Amount
	fail := banktypes.NewMsgSend(owner, grantee, sdk.NewCoins(sdk.NewInt64Coin(sdk.DefaultBondDenom, 200000000)))
	result := c.block(t, c.tx(t, c.key, nil, grant, fail))
	require.NotZero(t, result.Code)
	ctx := a.NewContext(true)
	_, err = a.FeeGrantKeeper.GetAllowance(ctx, owner, grantee)
	require.Error(t, err)
	require.Equal(t, before.SubRaw(10), a.BankKeeper.GetBalance(ctx, owner, sdk.DefaultBondDenom).Amount)
	require.Equal(t, uint64(1), a.AccountKeeper.GetAccount(ctx, owner).GetSequence())
	// The SDK grant is committed only on successful message execution.
	result = c.block(t, c.tx(t, c.key, nil, grant))
	require.Zero(t, result.Code, result.Log)
	ctx = a.NewContext(true)
	_, err = a.FeeGrantKeeper.GetAllowance(ctx, owner, grantee)
	require.NoError(t, err)
	// An unauthorized nested revoke passes structural Ante but fails in authz.
	revoke := feegrant.NewMsgRevokeAllowance(owner, grantee)
	exec := authz.NewMsgExec(grantee, []sdk.Msg{&revoke})
	result = c.block(t, c.tx(t, c.other, nil, &exec))
	require.NotZero(t, result.Code)
	ctx = a.NewContext(true)
	_, err = a.FeeGrantKeeper.GetAllowance(ctx, owner, grantee)
	require.NoError(t, err)
	// Successful nested mutations retain ordinary SDK routing.
	authGrant, err := authz.NewMsgGrant(owner, grantee, authz.NewGenericAuthorization(sdk.MsgTypeURL(&revoke)), nil)
	require.NoError(t, err)
	result = c.block(t, c.tx(t, c.key, nil, authGrant))
	require.Zero(t, result.Code, result.Log)
	result = c.block(t, c.tx(t, c.other, nil, &exec))
	require.Zero(t, result.Code, result.Log)
	ctx = a.NewContext(true)
	_, err = a.FeeGrantKeeper.GetAllowance(ctx, owner, grantee)
	require.Error(t, err)
	// Actual fee consumption is an Ante mutation and MUST persist even when
	// messages fail. Exhaustion must remove the SDK grant.
	limited, err := feegrant.NewMsgGrantAllowance(&feegrant.BasicAllowance{SpendLimit: sdk.NewCoins(sdk.NewInt64Coin(sdk.DefaultBondDenom, 10))}, owner, grantee)
	require.NoError(t, err)
	result = c.block(t, c.tx(t, c.key, nil, limited))
	require.Zero(t, result.Code, result.Log)
	before = a.BankKeeper.GetBalance(a.NewContext(true), owner, sdk.DefaultBondDenom).Amount
	overspend := banktypes.NewMsgSend(grantee, owner, sdk.NewCoins(sdk.NewInt64Coin(sdk.DefaultBondDenom, 200000000)))
	result = c.block(t, c.txWithFeeGranter(t, c.other, nil, owner, overspend))
	require.NotZero(t, result.Code)
	ctx = a.NewContext(true)
	require.Equal(t, before.SubRaw(10), a.BankKeeper.GetBalance(ctx, owner, sdk.DefaultBondDenom).Amount)
	_, err = a.FeeGrantKeeper.GetAllowance(ctx, owner, grantee)
	require.Error(t, err)
}
func TestPQCAuthSDKKeyringRegistrationAndHybridTransfer(t *testing.T) {
	c := newPQCChain(t)
	a := c.app
	owner := sdk.AccAddress(c.key.PubKey().Address())
	recipient := sdk.AccAddress(c.other.PubKey().Address())
	keys := keyring.NewInMemory(a.AppCodec())
	path := "m/44'/118'/0'/0/0"
	_, _, err := keys.NewMnemonic("sign", keyring.English, path, "", hd.MlDsa65)
	require.NoError(t, err)
	_, _, err = keys.NewMnemonic("recover", keyring.English, path, "", hd.MlDsa65)
	require.NoError(t, err)
	signer, err := pqcclient.NewKeyringSigner(keys, "sign")
	require.NoError(t, err)
	recovery, err := pqcclient.NewKeyringSigner(keys, "recover")
	require.NoError(t, err)
	proof := func(s pqcclient.PQCSigner, id uint64, role pqctypes.KeyRole, purpose string) ([]byte, []byte) {
		pub, err := s.PublicKey(context.Background())
		require.NoError(t, err)
		doc, err := pqctypes.MarshalKeyProofDocV1(pqctypes.KeyProofDocV1{FormatVersion: 1, NetworkId: a.PQCAuthKeeper.GetParams(a.NewContext(true)).NetworkId, ChainId: "policy-test", Owner: owner.String(), ProposedKeyId: id, Algorithm: pqctypes.Algorithm_ALGORITHM_ML_DSA_65, PublicKey: pub, Role: role, Purpose: purpose})
		require.NoError(t, err)
		sig, err := s.Sign(context.Background(), doc, []byte(pqctypes.RegisterProofContext))
		require.NoError(t, err)
		return pub, sig
	}
	pub, sig := proof(signer, 1, pqctypes.KeyRole_KEY_ROLE_SIGNING, pqctypes.PurposeRegisterSigning)
	rpub, rsig := proof(recovery, 2, pqctypes.KeyRole_KEY_ROLE_RECOVERY, pqctypes.PurposeRegisterRecovery)
	register := &pqctypes.MsgRegisterKey{Owner: owner.String(), ExpectedSigningKeyId: 1, SigningAlgorithm: pqctypes.Algorithm_ALGORITHM_ML_DSA_65, SigningPublicKey: pub, SigningKeyProof: sig, SelfEnforce: true, RecoveryAlgorithm: pqctypes.Algorithm_ALGORITHM_ML_DSA_65, RecoveryPublicKey: rpub, RecoveryKeyProof: rsig}
	result := c.block(t, c.tx(t, c.key, nil, register))
	require.Zero(t, result.Code, result.Log)
	send := banktypes.NewMsgSend(owner, recipient, sdk.NewCoins(sdk.NewInt64Coin(sdk.DefaultBondDenom, 7)))
	result = c.block(t, c.tx(t, c.key, nil, send))
	require.NotZero(t, result.Code, "classic-only transaction must be rejected after activation")
	raw := c.tx(t, c.key, signer, send)
	result = c.block(t, raw)
	require.Zero(t, result.Code, result.Log)
	result = c.block(t, raw)
	require.NotZero(t, result.Code, "replay must fail")
	require.EqualValues(t, 1000007, a.BankKeeper.GetBalance(a.NewContext(true), recipient, sdk.DefaultBondDenom).Amount.Int64())
}

func TestPQCAuthProposalBudgetsPreserveSDKGasPolicy(t *testing.T) {
	c := newPQCChain(t)
	a := c.app
	ctx := a.NewNextBlockContext(tmproto.Header{ChainID: "policy-test", Height: c.height + 1})
	params := a.PQCAuthKeeper.GetParams(ctx)
	params.MaxPqcVerificationsPerBlock = 1
	params.MaxPqcVerificationsPerTx = 1
	require.NoError(t, a.PQCAuthKeeper.SetParams(ctx, params))
	a.SimWriteState()
	// Structurally valid native ML-DSA signatures cost one verification each.
	// Existing SDK NoOp mempool policy does not execute Ante in proposal checks.
	key, err := mldsa65.GenPrivKey()
	require.NoError(t, err)
	txs := make([][]byte, 2)
	for i := range txs {
		b := a.TxConfig().NewTxBuilder()
		require.NoError(t, b.SetMsgs(banktypes.NewMsgSend(sdk.AccAddress(key.PubKey().Address()), sdk.AccAddress(c.key.PubKey().Address()), sdk.NewCoins(sdk.NewInt64Coin(sdk.DefaultBondDenom, 1)))))
		b.SetGasLimit(1000000)
		require.NoError(t, b.SetSignatures(signing.SignatureV2{PubKey: key.PubKey(), Sequence: uint64(i), Data: &signing.SingleSignatureData{SignMode: signing.SignMode_SIGN_MODE_DIRECT, Signature: make([]byte, 3309)}}))
		txs[i], err = a.TxConfig().TxEncoder()(b.GetTx())
		require.NoError(t, err)
	}
	prepared, err := a.PrepareProposal(&abci.RequestPrepareProposal{Height: c.height + 1, MaxTxBytes: 1000000, Txs: txs})
	require.NoError(t, err)
	require.Len(t, prepared.Txs, 1)
	rejected, err := a.ProcessProposal(&abci.RequestProcessProposal{Height: c.height + 1, Txs: txs})
	require.NoError(t, err)
	require.Equal(t, abci.ResponseProcessProposal_REJECT, rejected.Status)
	accepted, err := a.ProcessProposal(&abci.RequestProcessProposal{Height: c.height + 1, Txs: prepared.Txs})
	require.NoError(t, err)
	require.Equal(t, abci.ResponseProcessProposal_ACCEPT, accepted.Status)
}

func TestPQCAuthCandidateUpgradePreservesExistingFeegrants(t *testing.T) {
	c := newPQCChain(t)
	a := c.app
	ctx := a.NewNextBlockContext(tmproto.Header{ChainID: "policy-test", Height: c.height + 1})
	owner := sdk.AccAddress(c.key.PubKey().Address())
	grantee := sdk.AccAddress(c.other.PubKey().Address())
	// Seed canonical pre-upgrade state; phase one must leave it untouched.
	require.NoError(t, a.FeeGrantKeeper.GrantAllowance(ctx, owner, grantee, &feegrant.BasicAllowance{}))
	versions, err := a.UpgradeKeeper.GetModuleVersionMap(ctx)
	require.NoError(t, err)
	delete(versions, pqctypes.ModuleName)
	ctx.KVStore(a.GetKey(upgradetypes.StoreKey)).Delete(append([]byte{upgradetypes.VersionMapByte}, []byte(pqctypes.ModuleName)...))
	require.NoError(t, a.UpgradeKeeper.SetModuleVersionMap(ctx, versions))
	archive := ctx.KVStore(a.GetKey(wasmarchive.StoreKey))
	archive.Set([]byte("sentinel"), []byte("preserved"))
	require.NoError(t, a.UpgradeKeeper.ApplyUpgrade(ctx, upgradetypes.Plan{Name: app.PQCAuthUpgradeName, Height: c.height}))
	_, err = a.FeeGrantKeeper.GetAllowance(ctx, owner, grantee)
	require.NoError(t, err)
	params := a.PQCAuthKeeper.GetParams(ctx)
	require.Equal(t, pqctypes.EnforcementMode_ENFORCEMENT_MODE_OPTIONAL, params.EnforcementMode)
	require.False(t, pqctypes.UsesLegacyDefaultNetworkID(params.NetworkId))
	require.Equal(t, []byte("preserved"), archive.Get([]byte("sentinel")))
	versions, err = a.UpgradeKeeper.GetModuleVersionMap(ctx)
	require.NoError(t, err)
	require.NotZero(t, versions[pqctypes.ModuleName])
	require.ErrorContains(t, a.UpgradeKeeper.ApplyUpgrade(ctx, upgradetypes.Plan{Name: app.PQCAuthUpgradeName, Height: c.height}), "already initialized")
	require.ErrorContains(t, a.UpgradeKeeper.ApplyUpgrade(ctx, upgradetypes.Plan{Name: "v1.0.0", Height: c.height}), "released binary")
}
