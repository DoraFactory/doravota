package app_test

import (
	"context"
	"testing"
	"time"

	pqcclient "github.com/DoraFactory/doravota/x/pqcauth/client"
	pqckeeper "github.com/DoraFactory/doravota/x/pqcauth/keeper"
	pqctypes "github.com/DoraFactory/doravota/x/pqcauth/types"
	abci "github.com/cometbft/cometbft/abci/types"
	tmproto "github.com/cometbft/cometbft/proto/tendermint/types"
	sdkclient "github.com/cosmos/cosmos-sdk/client"
	sdktx "github.com/cosmos/cosmos-sdk/client/tx"
	codectypes "github.com/cosmos/cosmos-sdk/codec/types"
	"github.com/cosmos/cosmos-sdk/crypto/keys/mldsa65"
	"github.com/cosmos/cosmos-sdk/crypto/keys/secp256k1"
	cryptotypes "github.com/cosmos/cosmos-sdk/crypto/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
	txtypes "github.com/cosmos/cosmos-sdk/types/tx"
	"github.com/cosmos/cosmos-sdk/types/tx/signing"
	authsigning "github.com/cosmos/cosmos-sdk/x/auth/signing"
	banktypes "github.com/cosmos/cosmos-sdk/x/bank/types"
	"github.com/stretchr/testify/require"
)

func selectionSend(from, to cryptotypes.PrivKey) sdk.Msg {
	return banktypes.NewMsgSend(sdk.AccAddress(from.PubKey().Address()), sdk.AccAddress(to.PubKey().Address()), sdk.NewCoins(sdk.NewInt64Coin(sdk.DefaultBondDenom, 1)))
}

// Sign the actual transaction, including explicit future sequences, using all
// classic/native keys and any protected factors. Keys are in SDK signer order.
func selectionTx(t *testing.T, c *pqcChain, keys []cryptotypes.PrivKey, factors []pqcclient.PQCSigner, offsets []uint64, payer sdk.AccAddress, msgs ...sdk.Msg) []byte {
	t.Helper()
	ctx := c.app.NewContext(true).WithBlockHeight(c.height + 1)
	b := c.app.TxConfig().NewTxBuilder()
	require.NoError(t, b.SetMsgs(msgs...))
	b.SetGasLimit(5_000_000)
	b.SetFeeAmount(sdk.NewCoins(sdk.NewInt64Coin(sdk.DefaultBondDenom, 10)))
	if payer != nil {
		b.SetFeePayer(payer)
	}
	sigs := make([]signing.SignatureV2, len(keys))
	for i, key := range keys {
		acc := c.app.AccountKeeper.GetAccount(ctx, sdk.AccAddress(key.PubKey().Address()))
		sigs[i] = signing.SignatureV2{PubKey: key.PubKey(), Sequence: acc.GetSequence() + offsets[i], Data: &signing.SingleSignatureData{SignMode: signing.SignMode_SIGN_MODE_DIRECT}}
	}
	require.NoError(t, b.SetSignatures(sigs...))
	ext := &pqctypes.ExtensionPQCAuth{FormatVersion: 1}
	for i, factor := range factors {
		if factor == nil {
			continue
		}
		owner := sdk.AccAddress(keys[i].PubKey().Address())
		acc := c.app.AccountKeeper.GetAccount(ctx, owner)
		record, policy, active := c.app.PQCAuthKeeper.GetActiveSigningKey(ctx, owner)
		require.True(t, active)
		protoTx := b.(interface{ GetProtoTx() *txtypes.Tx }).GetProtoTx()
		doc, err := pqctypes.NewPQCSignDocV1(protoTx, c.app.PQCAuthKeeper.GetParams(ctx).NetworkId, "policy-test", acc.GetAccountNumber(), sigs[i].Sequence, uint32(i), owner.String(), record.KeyId, record.Algorithm, policy.PolicyVersion)
		require.NoError(t, err)
		bz, err := pqctypes.MarshalPQCSignDocV1(doc)
		require.NoError(t, err)
		sig, err := factor.Sign(context.Background(), bz, []byte(pqctypes.TxSignatureContext))
		require.NoError(t, err)
		ext.Signatures = append(ext.Signatures, pqctypes.SignerPQCSignature{Signer: owner.String(), SignerIndex: uint32(i), KeyId: record.KeyId, Algorithm: record.Algorithm, PolicyVersion: policy.PolicyVersion, Signature: sig})
	}
	if len(ext.Signatures) != 0 {
		option, err := codectypes.NewAnyWithValue(ext)
		require.NoError(t, err)
		b.(sdkclient.ExtendedTxBuilder).SetExtensionOptions(option)
	}
	for i, key := range keys {
		owner := sdk.AccAddress(key.PubKey().Address())
		acc := c.app.AccountKeeper.GetAccount(ctx, owner)
		var err error
		sigs[i], err = sdktx.SignWithPrivKey(context.Background(), signing.SignMode_SIGN_MODE_DIRECT, authsigning.SignerData{Address: owner.String(), ChainID: "policy-test", AccountNumber: acc.GetAccountNumber(), Sequence: sigs[i].Sequence, PubKey: key.PubKey()}, b, key, c.app.TxConfig(), sigs[i].Sequence)
		require.NoError(t, err)
	}
	require.NoError(t, b.SetSignatures(sigs...))
	raw, err := c.app.TxConfig().TxEncoder()(b.GetTx())
	require.NoError(t, err)
	return raw
}

func selectionCheck(t *testing.T, c *pqcChain, txs [][]byte) {
	t.Helper()
	for _, raw := range txs {
		r, err := c.app.CheckTx(&abci.RequestCheckTx{Tx: raw})
		require.NoError(t, err)
		require.Zero(t, r.Code, r.Log)
	}
}

func selectionExecute(t *testing.T, c *pqcChain, candidates, want [][]byte) {
	t.Helper()
	h := c.height + 1
	stamp := c.stamp.Add(time.Duration(h) * time.Second)
	prepared, err := c.app.PrepareProposal(&abci.RequestPrepareProposal{Height: h, Time: stamp, MaxTxBytes: 1_000_000, Txs: candidates})
	require.NoError(t, err)
	require.Equal(t, want, prepared.Txs)
	processed, err := c.app.ProcessProposal(&abci.RequestProcessProposal{Height: h, Time: stamp, Txs: prepared.Txs})
	require.NoError(t, err)
	require.Equal(t, abci.ResponseProcessProposal_ACCEPT, processed.Status)
	result, err := c.app.FinalizeBlock(&abci.RequestFinalizeBlock{Height: h, Time: stamp, Txs: prepared.Txs})
	require.NoError(t, err)
	require.Len(t, result.TxResults, len(want))
	for _, r := range result.TxResults {
		require.Zero(t, r.Code, r.Log)
	}
	_, err = c.app.Commit()
	require.NoError(t, err)
	c.height = h
	c.block(t, nil)
	require.True(t, c.app.PQCAuthKeeper.AuditState(c.app.NewContext(true).WithBlockHeight(c.height), 100).Consistent)
}

func TestPQCAuthProposalBudgetKeepsIndependentTransactions(t *testing.T) {
	for _, separatePayer := range []bool{false, true} {
		name := "multi-signer"
		if separatePayer {
			name = "independent-fee-payer"
		}
		t.Run(name, func(t *testing.T) {
			c := newPQCChain(t, minimumCapacityParams())
			native, err := mldsa65.GenPrivKey()
			require.NoError(t, err)
			fund := banktypes.NewMsgSend(sdk.AccAddress(c.key.PubKey().Address()), sdk.AccAddress(native.PubKey().Address()), sdk.NewCoins(sdk.NewInt64Coin(sdk.DefaultBondDenom, 100000)))
			r := c.block(t, c.tx(t, c.key, nil, fund))
			require.Zero(t, r.Code, r.Log)
			var txs [][]byte
			for seq := uint64(0); seq < 4; seq++ {
				txs = append(txs, selectionTx(t, c, []cryptotypes.PrivKey{&native}, nil, []uint64{seq}, nil, selectionSend(&native, c.other)))
			}
			// Fourth native tx exceeds budget 3. Its dependent co-signed tx
			// propagates the omission to the other account, without blocking D.
			msgs := []sdk.Msg{selectionSend(&native, c.other)}
			var payer sdk.AccAddress
			if separatePayer {
				payer = sdk.AccAddress(c.key.PubKey().Address())
			} else {
				msgs = append(msgs, selectionSend(c.key, c.other))
			}
			txs = append(txs, selectionTx(t, c, []cryptotypes.PrivKey{&native, c.key}, nil, []uint64{4, 0}, payer, msgs...))
			txs = append(txs, selectionTx(t, c, []cryptotypes.PrivKey{c.key}, nil, []uint64{1}, nil, selectionSend(c.key, c.other)))
			plain := selectionTx(t, c, []cryptotypes.PrivKey{c.other}, nil, []uint64{0}, nil, selectionSend(c.other, c.key))
			txs = append(txs, plain)
			selectionCheck(t, c, txs)
			want := append(append([][]byte{}, txs[:3]...), plain)
			selectionExecute(t, c, txs, want)
			t.Log("all candidates passed sequential CheckTx; independent work executed after exhausted PQC budget")
		})
	}
}

func TestPQCAuthProposalParameterActivationDependencies(t *testing.T) {
	for _, lowerBytes := range []bool{false, true} {
		for _, separatePayer := range []bool{false, true} {
			name := "signer-limit"
			if lowerBytes {
				name = "byte-and-signer-limit"
			}
			if separatePayer {
				name += "/fee-payer"
			} else {
				name += "/multi-signer"
			}
			t.Run(name, func(t *testing.T) {
				p := pqctypes.DefaultParams()
				p.GovernanceSafetyDelayBlocks = 2
				c := newPQCChain(t, p)
				first, second, third, independent := c.key, c.other, secp256k1.GenPrivKey(), secp256k1.GenPrivKey()
				for _, key := range []*secp256k1.PrivKey{third, independent} {
					fund := banktypes.NewMsgSend(sdk.AccAddress(first.PubKey().Address()), sdk.AccAddress(key.PubKey().Address()), sdk.NewCoins(sdk.NewInt64Coin(sdk.DefaultBondDenom, 100000)))
					r := c.block(t, c.tx(t, first, nil, fund))
					require.Zero(t, r.Code, r.Log)
				}
				keys := []cryptotypes.PrivKey{first, second, third}
				var factors []pqcclient.PQCSigner
				for _, key := range []*secp256k1.PrivKey{first, second, third} {
					c.key = key
					factor, _ := reviewEnroll(t, c)
					factors = append(factors, factor)
				}
				c.key = first
				ctx := c.app.NewNextBlockContext(tmproto.Header{ChainID: "policy-test", Height: c.height + 1})
				requested := c.app.PQCAuthKeeper.GetParams(ctx)
				requested.MaxPqcSigners = 2
				if lowerBytes {
					requested.MaxPqcAuthBytes = pqctypes.MinimumPQCAuthBytes(2)
				}
				scheduled, err := pqckeeper.NewMsgServer(c.app.PQCAuthKeeper).UpdateParams(ctx, &pqctypes.MsgUpdateParams{Authority: c.app.PQCAuthKeeper.Authority(), Params: requested})
				require.NoError(t, err)
				c.app.SimWriteState()
				for uint64(c.height) < scheduled.ActivationHeight-1 {
					c.block(t, nil)
				}
				msgs := []sdk.Msg{selectionSend(first, independent), selectionSend(second, independent)}
				var payer sdk.AccAddress
				if separatePayer {
					payer = sdk.AccAddress(third.PubKey().Address())
				} else {
					msgs = append(msgs, selectionSend(third, independent))
				}
				head := selectionTx(t, c, keys, factors, []uint64{0, 0, 0}, payer, msgs...)
				dependent := selectionTx(t, c, []cryptotypes.PrivKey{first}, factors[:1], []uint64{1}, nil, selectionSend(first, independent))
				payerTail := selectionTx(t, c, []cryptotypes.PrivKey{third}, factors[2:], []uint64{1}, nil, selectionSend(third, independent))
				plain := selectionTx(t, c, []cryptotypes.PrivKey{independent}, nil, []uint64{0}, nil, selectionSend(independent, first))
				txs := [][]byte{head, dependent, payerTail, plain}
				selectionCheck(t, c, txs)
				old, err := c.app.PrepareProposal(&abci.RequestPrepareProposal{Height: c.height, MaxTxBytes: 1_000_000, Txs: txs})
				require.NoError(t, err)
				require.Equal(t, txs, old.Txs)
				strict, err := c.app.ProcessProposal(&abci.RequestProcessProposal{Height: c.height + 1, Txs: txs})
				require.NoError(t, err)
				require.Equal(t, abci.ResponseProcessProposal_REJECT, strict.Status)
				selectionExecute(t, c, txs, [][]byte{plain})
				// The omitted accounts can re-sign at their still-current sequence.
				retry := selectionTx(t, c, []cryptotypes.PrivKey{first}, factors[:1], []uint64{0}, nil, selectionSend(first, independent))
				r := c.block(t, retry)
				require.Zero(t, r.Code, r.Log)
				t.Log("real old-height CheckTx passed; new-height selection removed head and all sequence dependants, kept independent transfer")
			})
		}
	}
}
