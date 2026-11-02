package app_test

import (
	"fmt"
	"testing"
	"time"

	"cosmossdk.io/collections"
	pqctypes "github.com/DoraFactory/doravota/x/pqcauth/types"
	abci "github.com/cometbft/cometbft/abci/types"
	tmproto "github.com/cometbft/cometbft/proto/tendermint/types"
	codectypes "github.com/cosmos/cosmos-sdk/codec/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
	gov "github.com/cosmos/cosmos-sdk/x/gov/types/v1"
	"github.com/stretchr/testify/require"
)

// Seed only the pre-execution voting fixture. Tally, message routing, proposal
// cache rollback, EndBlock and Commit all run through the real application.
// Deposits/submission are covered separately by the signed governance test.
func seedPQCReadyProposal(t *testing.T, c *pqcChain, ctx sdk.Context, id uint64, msgs ...sdk.Msg) {
	t.Helper()
	packed := make([]*codectypes.Any, len(msgs))
	for i, msg := range msgs {
		var err error
		packed[i], err = codectypes.NewAnyWithValue(msg)
		require.NoError(t, err)
	}
	expiry := ctx.BlockTime()
	p := gov.Proposal{Id: id, Messages: packed, Status: gov.StatusVotingPeriod, Title: "PQC order regression", Summary: "isolated application test", VotingEndTime: &expiry}
	require.NoError(t, c.app.GovKeeper.SetProposal(ctx, p))
	require.NoError(t, c.app.GovKeeper.ActiveProposalsQueue.Set(ctx, collections.Join(expiry, id), id))
	// GenesisStateWithValSet delegates all test voting power to c.key.
	require.NoError(t, c.app.GovKeeper.AddVote(ctx, id, sdk.AccAddress(c.key.PubKey().Address()), gov.NewNonSplitVoteOption(gov.OptionYes), ""))
}

func TestPQCAuthSignedGovernanceSubmissionVoteAndRollback(t *testing.T) {
	for _, ordinary := range []bool{false, true} {
		t.Run(fmt.Sprint(ordinary), func(t *testing.T) {
			p := pqctypes.DefaultParams()
			p.GovernanceSafetyDelayBlocks = 4
			if ordinary {
				pending := p.AsScheduled()
				pending.EnforcementMode = pqctypes.EnforcementMode_ENFORCEMENT_MODE_REQUIRED_FOR_REGISTERED
				p.Pending, p.PendingActivationHeight = &pending, 20
			}
			c := newPQCChain(t, p)
			ctx := c.app.NewNextBlockContext(tmproto.Header{ChainID: "policy-test", Height: 2, Time: c.stamp.Add(2 * time.Second)})
			gp, err := c.app.GovKeeper.Params.Get(ctx)
			require.NoError(t, err)
			period, expedited := 3*time.Second, time.Second
			gp.VotingPeriod, gp.ExpeditedVotingPeriod = &period, &expedited
			gp.MinDeposit = sdk.NewCoins(sdk.NewInt64Coin(sdk.DefaultBondDenom, 1))
			gp.ExpeditedMinDeposit = sdk.NewCoins(sdk.NewInt64Coin(sdk.DefaultBondDenom, 2))
			require.NoError(t, gp.ValidateBasic())
			require.NoError(t, c.app.GovKeeper.Params.Set(ctx, gp))
			c.app.SimWriteState()
			c.block(t, nil)
			before := c.app.PQCAuthKeeper.GetParams(c.app.NewContext(true))
			active := before
			active.Pending, active.PendingActivationHeight = nil, 0
			paused := active
			paused.EmergencyMode = pqctypes.EmergencyMode_EMERGENCY_MODE_PAUSE_PQC_TRANSACTIONS
			authority := c.app.PQCAuthKeeper.Authority()
			owner := sdk.AccAddress(c.key.PubKey().Address())
			balance := c.app.BankKeeper.GetBalance(c.app.NewContext(true), owner, sdk.DefaultBondDenom).Amount
			id, err := c.app.GovKeeper.ProposalID.Peek(c.app.NewContext(true))
			require.NoError(t, err)
			submit, err := gov.NewMsgSubmitProposal([]sdk.Msg{
				&pqctypes.MsgUpdateParams{Authority: authority, Params: paused, EmergencyOnly: true},
				&pqctypes.MsgUpdateParams{Authority: authority, Params: active},
			}, sdk.NewCoins(sdk.NewInt64Coin(sdk.DefaultBondDenom, 1)), owner.String(), "", "PQC governance execution", "signed submission vote and execution", false)
			require.NoError(t, err)
			for _, msg := range []sdk.Msg{submit, gov.NewMsgVote(owner, id, gov.OptionYes, "")} {
				raw := c.tx(t, c.key, nil, msg)
				check, err := c.app.CheckTx(&abci.RequestCheckTx{Tx: raw})
				require.NoError(t, err)
				require.Zero(t, check.Code, check.Log)
				r := c.block(t, raw)
				require.Zero(t, r.Code, r.Log)
			}
			proposal, err := c.app.GovKeeper.Proposals.Get(c.app.NewContext(true), id)
			require.NoError(t, err)
			require.Equal(t, gov.StatusVotingPeriod, proposal.Status)
			for c.stamp.Add(time.Duration(c.height) * time.Second).Before(*proposal.VotingEndTime) {
				c.block(t, nil)
			}
			proposal, err = c.app.GovKeeper.Proposals.Get(c.app.NewContext(true), id)
			require.NoError(t, err)
			require.Equal(t, gov.StatusFailed, proposal.Status, proposal.FailedReason)
			require.Contains(t, proposal.FailedReason, "wait for the H+1 emergency activation")
			require.Equal(t, before, c.app.PQCAuthKeeper.GetParams(c.app.NewContext(true)))
			require.Equal(t, balance.SubRaw(20), c.app.BankKeeper.GetBalance(c.app.NewContext(true), owner, sdk.DefaultBondDenom).Amount, "deposit refunded; only two normal tx fees retained")
			require.Equal(t, uint64(2), c.app.AccountKeeper.GetAccount(c.app.NewContext(true), owner).GetSequence())
			c.block(t, nil)
			require.True(t, c.app.PQCAuthKeeper.AuditState(c.app.NewContext(true).WithBlockHeight(c.height), 100).Consistent)
			t.Logf("signed submit + vote passed CheckTx/Finalize; proposal=%d status=%s; final height=%d", id, proposal.Status, c.height)
		})
	}
}

func TestPQCAuthGovernanceEndBlockOrderingAndRollback(t *testing.T) {
	for _, mode := range []pqctypes.EmergencyMode{pqctypes.EmergencyMode_EMERGENCY_MODE_PAUSE_NEW_KEYS, pqctypes.EmergencyMode_EMERGENCY_MODE_PAUSE_PQC_TRANSACTIONS} {
		for _, ordinary := range []bool{false, true} {
			for _, scenario := range []string{"same-proposal", "separate-pause-first", "separate-cancel-first", "rollback-all", "failed-then-valid"} {
				t.Run(fmt.Sprintf("%s/ordinary=%t/%s", mode, ordinary, scenario), func(t *testing.T) {
					base := pqctypes.DefaultParams()
					base.GovernanceSafetyDelayBlocks = 4
					base.MaxEmergencyDurationBlocks = 20
					initial := base
					if ordinary {
						pending := base.AsScheduled()
						pending.EnforcementMode = pqctypes.EnforcementMode_ENFORCEMENT_MODE_REQUIRED_FOR_REGISTERED
						initial.Pending, initial.PendingActivationHeight = &pending, 6
					}
					c := newPQCChain(t, initial)
					initial = c.app.PQCAuthKeeper.GetParams(c.app.NewContext(true))
					base.NetworkId = initial.NetworkId
					ctx := c.app.NewNextBlockContext(tmproto.Header{ChainID: "policy-test", Height: 2, Time: c.stamp.Add(2 * time.Second)})
					authority := c.app.PQCAuthKeeper.Authority()
					paused := base
					paused.EmergencyMode = mode
					pause := &pqctypes.MsgUpdateParams{Authority: authority, Params: paused, EmergencyOnly: true}
					cancel := &pqctypes.MsgUpdateParams{Authority: authority, Params: base}
					invalid := base
					invalid.VerificationGas = 1
					bad := &pqctypes.MsgUpdateParams{Authority: authority, Params: invalid}
					want := map[uint64]gov.ProposalStatus{10: gov.StatusPassed}
					switch scenario {
					case "same-proposal":
						seedPQCReadyProposal(t, c, ctx, 10, pause, cancel)
						want[10] = gov.StatusFailed
					case "separate-pause-first":
						// Deliberately insert higher ID first; queue order is expiry/ID.
						seedPQCReadyProposal(t, c, ctx, 20, cancel)
						seedPQCReadyProposal(t, c, ctx, 10, pause)
						want[20] = gov.StatusFailed
					case "separate-cancel-first":
						seedPQCReadyProposal(t, c, ctx, 20, pause)
						seedPQCReadyProposal(t, c, ctx, 10, cancel)
						want[20] = gov.StatusPassed
					case "rollback-all":
						seedPQCReadyProposal(t, c, ctx, 10, pause, bad)
						want[10] = gov.StatusFailed
					case "failed-then-valid":
						seedPQCReadyProposal(t, c, ctx, 20, pause)
						seedPQCReadyProposal(t, c, ctx, 10, pause, bad)
						want[10], want[20] = gov.StatusFailed, gov.StatusPassed
					}
					c.app.SimWriteState() // fixture only; below is actual FinalizeBlock/Commit
					c.block(t, nil)
					read := c.app.NewContext(true).WithBlockHeight(c.height)
					for id, status := range want {
						p, err := c.app.GovKeeper.Proposals.Get(read, id)
						require.NoError(t, err)
						require.Equal(t, status, p.Status, p.FailedReason)
						require.NotNil(t, p.FinalTallyResult)
						require.NotEqual(t, "0", p.FinalTallyResult.YesCount, "must actually pass tally, not skip handlers")
						if status == gov.StatusFailed {
							require.NotEmpty(t, p.FailedReason)
						}
					}
					stored := c.app.PQCAuthKeeper.GetParams(read)
					wantPaused := scenario == "separate-cancel-first" || scenario == "failed-then-valid" || scenario == "separate-pause-first"
					wantOrdinary := ordinary && scenario != "separate-cancel-first"
					if scenario == "rollback-all" || scenario == "same-proposal" {
						require.Equal(t, initial, stored, "failed proposal must roll back earlier PQC writes")
					}
					if wantOrdinary {
						require.NotNil(t, stored.Pending)
						require.Equal(t, uint64(6), stored.PendingActivationHeight)
						require.Equal(t, pqctypes.EnforcementMode_ENFORCEMENT_MODE_REQUIRED_FOR_REGISTERED, stored.Pending.EnforcementMode)
					}
					// Check committed H+1 activation, old ordinary activation, expiry,
					// and subsequent blocks; failed gov messages must not halt the app.
					for c.height < 24 {
						c.block(t, nil)
						p := c.app.PQCAuthKeeper.GetParams(c.app.NewContext(true)).Effective(c.height)
						wantMode := pqctypes.EmergencyMode_EMERGENCY_MODE_NORMAL
						if wantPaused && c.height < 23 {
							wantMode = mode
						}
						require.Equal(t, wantMode, p.EmergencyMode)
						wantEnforcement := pqctypes.EnforcementMode_ENFORCEMENT_MODE_OPTIONAL
						if wantOrdinary && c.height >= 6 {
							wantEnforcement = pqctypes.EnforcementMode_ENFORCEMENT_MODE_REQUIRED_FOR_REGISTERED
						}
						require.Equal(t, wantEnforcement, p.EnforcementMode)
					}
					for id, status := range want {
						p, err := c.app.GovKeeper.Proposals.Get(c.app.NewContext(true), id)
						require.NoError(t, err)
						require.Equal(t, status, p.Status, "failed proposals must not be automatically retried")
					}
					require.True(t, c.app.PQCAuthKeeper.AuditState(c.app.NewContext(true).WithBlockHeight(c.height), 100).Consistent)
					t.Logf("actual gov EndBlock + commits: proposals=%v, pause=%t ordinary=%t, final height=%d", want, wantPaused, wantOrdinary, c.height)
				})
			}
		}
	}
}

func TestPQCAuthGovernanceEmergencyGuardAndResubmission(t *testing.T) {
	for _, mode := range []pqctypes.EmergencyMode{pqctypes.EmergencyMode_EMERGENCY_MODE_PAUSE_NEW_KEYS, pqctypes.EmergencyMode_EMERGENCY_MODE_PAUSE_PQC_TRANSACTIONS} {
		for _, emergencyFirst := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/emergency-first=%t", mode, emergencyFirst), func(t *testing.T) {
				base := pqctypes.DefaultParams()
				base.GovernanceSafetyDelayBlocks = 4
				base.MaxEmergencyDurationBlocks = 20
				c := newPQCChain(t, base)
				base = c.app.PQCAuthKeeper.GetParams(c.app.NewContext(true))
				pause, full := base, base
				pause.EmergencyMode = mode
				full.EnforcementMode = pqctypes.EnforcementMode_ENFORCEMENT_MODE_REQUIRED_FOR_REGISTERED
				authority := c.app.PQCAuthKeeper.Authority()
				ctx := c.app.NewNextBlockContext(tmproto.Header{ChainID: "policy-test", Height: 2, Time: c.stamp.Add(2 * time.Second)})
				pauseID, fullID := uint64(10), uint64(20)
				if !emergencyFirst {
					pauseID, fullID = fullID, pauseID
				}
				seedPQCReadyProposal(t, c, ctx, pauseID, &pqctypes.MsgUpdateParams{Authority: authority, Params: pause, EmergencyOnly: true})
				seedPQCReadyProposal(t, c, ctx, fullID, &pqctypes.MsgUpdateParams{Authority: authority, Params: full})
				c.app.SimWriteState()
				c.block(t, nil)
				paused, err := c.app.GovKeeper.Proposals.Get(c.app.NewContext(true), pauseID)
				require.NoError(t, err)
				require.Equal(t, gov.StatusPassed, paused.Status)
				p, err := c.app.GovKeeper.Proposals.Get(c.app.NewContext(true), fullID)
				require.NoError(t, err)
				want := gov.StatusPassed
				if emergencyFirst {
					want = gov.StatusFailed
					require.Contains(t, p.FailedReason, "wait for the H+1 emergency activation")
				}
				require.Equal(t, want, p.Status)
				// H+1 is evaluated inside real BeginBlock/EndBlock. A NEW proposal
				// can update ordinary parameters while preserving the active pause.
				if emergencyFirst {
					ctx = c.app.NewNextBlockContext(tmproto.Header{ChainID: "policy-test", Height: 3, Time: c.stamp.Add(3 * time.Second)})
					full.EmergencyMode = mode
					seedPQCReadyProposal(t, c, ctx, 30, &pqctypes.MsgUpdateParams{Authority: authority, Params: full})
					c.app.SimWriteState()
				}
				c.block(t, nil)
				state := c.app.PQCAuthKeeper.GetParams(c.app.NewContext(true)).Effective(3)
				require.Nil(t, state.PendingEmergency)
				require.Equal(t, mode, state.EmergencyMode)
				require.Equal(t, uint64(23), state.EmergencyExpiresHeight)
				activation := uint64(6)
				if emergencyFirst {
					activation = 7
					p, err = c.app.GovKeeper.Proposals.Get(c.app.NewContext(true), 30)
					require.NoError(t, err)
					require.Equal(t, gov.StatusPassed, p.Status)
				}
				require.Equal(t, activation, state.PendingActivationHeight)
				for c.height < 24 {
					c.block(t, nil)
					state = c.app.PQCAuthKeeper.GetParams(c.app.NewContext(true)).Effective(c.height)
					wantMode := mode
					if c.height >= 23 {
						wantMode = pqctypes.EmergencyMode_EMERGENCY_MODE_NORMAL
					}
					require.Equal(t, wantMode, state.EmergencyMode)
					if uint64(c.height) >= activation {
						require.Equal(t, pqctypes.EnforcementMode_ENFORCEMENT_MODE_REQUIRED_FOR_REGISTERED, state.EnforcementMode)
					}
				}
				p, err = c.app.GovKeeper.Proposals.Get(c.app.NewContext(true), fullID)
				require.NoError(t, err)
				require.Equal(t, want, p.Status, "the failed original is not retried when the new proposal succeeds")
				require.True(t, c.app.PQCAuthKeeper.AuditState(c.app.NewContext(true).WithBlockHeight(c.height), 100).Consistent)
			})
		}
	}
}
