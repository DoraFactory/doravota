package app_test

import (
	"testing"

	abci "github.com/cometbft/cometbft/abci/types"
	tmproto "github.com/cometbft/cometbft/proto/tendermint/types"
	"github.com/cosmos/cosmos-sdk/crypto/keys/mldsa65"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/cosmos/cosmos-sdk/types/tx/signing"
	banktypes "github.com/cosmos/cosmos-sdk/x/bank/types"
	"github.com/stretchr/testify/require"
)

// Four independent applications must agree across the activation boundary.
// This tests proposal structure/budget decisions, not signature validity;
// cryptographic transaction execution is covered by app and live-node tests.
func TestPQCAuthFourApplicationProposalActivationBoundary(t *testing.T) {
	key, err := mldsa65.GenPrivKey()
	require.NoError(t, err)
	var shared [][]byte
	for replica := 0; replica < 4; replica++ {
		c := newPQCChain(t)
		a := c.app
		ctx := a.NewNextBlockContext(tmproto.Header{ChainID: "policy-test", Height: 2})
		params := a.PQCAuthKeeper.GetParams(ctx)
		params.MaxPqcVerificationsPerTx = 1
		params.MaxPqcVerificationsPerBlock = 4
		scheduled := params.AsScheduled()
		scheduled.MaxPqcVerificationsPerBlock = 2
		params.Pending = &scheduled
		params.PendingActivationHeight = 3
		require.NoError(t, a.PQCAuthKeeper.SetParams(ctx, params))
		a.SimWriteState()
		if replica == 0 {
			for i := 0; i < 5; i++ {
				b := a.TxConfig().NewTxBuilder()
				owner := sdk.AccAddress(key.PubKey().Address())
				require.NoError(t, b.SetMsgs(banktypes.NewMsgSend(owner, owner, sdk.NewCoins(sdk.NewInt64Coin(sdk.DefaultBondDenom, 1)))))
				b.SetGasLimit(1000000)
				require.NoError(t, b.SetSignatures(signing.SignatureV2{PubKey: key.PubKey(), Sequence: uint64(i), Data: &signing.SingleSignatureData{SignMode: signing.SignMode_SIGN_MODE_DIRECT, Signature: make([]byte, 3309)}}))
				raw, err := a.TxConfig().TxEncoder()(b.GetTx())
				require.NoError(t, err)
				shared = append(shared, raw)
			}
		}
		for _, h := range []int64{2, 3, 4} {
			limit := 4
			if h >= 3 {
				limit = 2
			}
			for _, n := range []int{limit - 1, limit, limit + 1} {
				r, err := a.ProcessProposal(&abci.RequestProcessProposal{Height: h, Txs: shared[:n]})
				require.NoError(t, err)
				want := abci.ResponseProcessProposal_ACCEPT
				if n > limit {
					want = abci.ResponseProcessProposal_REJECT
				}
				require.Equal(t, want, r.Status, "replica=%d height=%d count=%d", replica, h, n)
			}
			r, err := a.ProcessProposal(&abci.RequestProcessProposal{Height: h, Txs: [][]byte{{0xff}}})
			require.NoError(t, err)
			require.Equal(t, abci.ResponseProcessProposal_REJECT, r.Status)
			prepared, err := a.PrepareProposal(&abci.RequestPrepareProposal{Height: h, MaxTxBytes: 1000000, Txs: append([][]byte{{0xff}}, shared...)})
			require.NoError(t, err)
			require.Equal(t, shared[:limit], prepared.Txs)
			accepted, err := a.ProcessProposal(&abci.RequestProcessProposal{Height: h, Txs: prepared.Txs})
			require.NoError(t, err)
			require.Equal(t, abci.ResponseProcessProposal_ACCEPT, accepted.Status)
			// Repeated consensus rounds make the same decision and do not consume budget.
			repeat, err := a.ProcessProposal(&abci.RequestProcessProposal{Height: h, Txs: prepared.Txs})
			require.NoError(t, err)
			require.Equal(t, accepted.Status, repeat.Status)
			require.Equal(t, uint32(4), a.PQCAuthKeeper.GetParams(a.NewContext(true)).MaxPqcVerificationsPerBlock)
		}
	}
}
