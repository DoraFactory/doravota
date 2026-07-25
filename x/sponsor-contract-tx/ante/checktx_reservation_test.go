package sponsor

import (
	sdk "github.com/cosmos/cosmos-sdk/types"

	"github.com/DoraFactory/doravota/x/sponsor-contract-tx/types"
)

func (suite *SponsorDecoratorTestSuite) TestCheckTxReservesTicketUsesInCheckState() {
	suite.wasmKeeper.SetContractInfo(suite.contract, suite.admin.String())

	fee := sdk.NewCoins(sdk.NewCoin(types.SponsorshipDenom, sdk.NewInt(100)))
	suite.createAndFundSponsor(
		suite.contract,
		true,
		sdk.NewCoins(sdk.NewCoin(types.SponsorshipDenom, sdk.NewInt(1_000))),
		sdk.NewCoins(sdk.NewCoin(types.SponsorshipDenom, sdk.NewInt(1_000))),
	)

	sponsor, found := suite.keeper.GetSponsor(suite.ctx, suite.contract.String())
	suite.Require().True(found)
	sponsorAddr, err := sdk.AccAddressFromBech32(sponsor.SponsorAddress)
	suite.Require().NoError(err)

	digest := suite.keeper.ComputeMethodDigestSingle(suite.contract.String(), "increment")
	suite.Require().NoError(suite.keeper.SetActivePolicyTicket(suite.ctx, types.PolicyTicket{
		ContractAddress: suite.contract.String(),
		UserAddress:     suite.user.String(),
		Digest:          digest,
		Method:          "increment",
		UsesRemaining:   1,
		ExpiryHeight:    uint64(suite.ctx.BlockHeight()) + 50,
	}))

	payment := SponsorPaymentInfo{
		ContractAddr: suite.contract,
		SponsorAddr:  sponsorAddr,
		UserAddr:     suite.user,
		Fee:          fee,
		IsSponsored:  true,
		DigestCounts: map[string]uint32{digest: 1},
	}
	tx := suite.createContractExecuteTx(suite.contract, suite.user, fee)

	runCheckTx := func(parent sdk.Context) error {
		txCtx, write := parent.CacheContext()
		txCtx = txCtx.
			WithIsCheckTx(true).
			WithValue(sponsorPaymentKey{}, payment)
		_, err := suite.sponsorDecorator.AnteHandle(
			txCtx,
			tx,
			false,
			func(ctx sdk.Context, tx sdk.Tx, simulate bool) (sdk.Context, error) {
				return ctx, nil
			},
		)
		if err == nil {
			write()
		}
		return err
	}

	// BaseApp keeps accepted CheckTx writes in an isolated check-state.
	checkState, _ := suite.ctx.CacheContext()
	checkState = checkState.WithIsCheckTx(true)
	suite.Require().NoError(runCheckTx(checkState))

	reserved, found := suite.keeper.GetActivePolicyTicket(
		checkState,
		suite.contract.String(),
		suite.user.String(),
		digest,
	)
	suite.Require().True(found)
	suite.Require().True(reserved.Consumed)
	suite.Require().Zero(reserved.UsesRemaining)

	// Check-state reservations must never mutate committed DeliverTx state.
	committed, found := suite.keeper.GetActivePolicyTicket(
		suite.ctx,
		suite.contract.String(),
		suite.user.String(),
		digest,
	)
	suite.Require().True(found)
	suite.Require().False(committed.Consumed)
	suite.Require().Equal(uint32(1), committed.UsesRemaining)

	balanceAfterFirst := suite.bankKeeper.SpendableCoins(checkState, sponsorAddr)
	usageAfterFirst := suite.keeper.GetUserGrantUsage(
		checkState,
		suite.user.String(),
		suite.contract.String(),
	)

	// A second mempool transaction cannot reserve the same one-use ticket.
	suite.Require().Error(runCheckTx(checkState))
	suite.Require().Equal(
		balanceAfterFirst,
		suite.bankKeeper.SpendableCoins(checkState, sponsorAddr),
	)
	suite.Require().Equal(
		usageAfterFirst,
		suite.keeper.GetUserGrantUsage(
			checkState,
			suite.user.String(),
			suite.contract.String(),
		),
	)

	// Commit resets CheckTx state before ReCheckTx, so a still-valid transaction
	// reserves exactly once again from the latest committed state.
	recheckState, _ := suite.ctx.CacheContext()
	recheckState = recheckState.WithIsCheckTx(true).WithIsReCheckTx(true)
	suite.Require().NoError(runCheckTx(recheckState))
	rechecked, found := suite.keeper.GetActivePolicyTicket(
		recheckState,
		suite.contract.String(),
		suite.user.String(),
		digest,
	)
	suite.Require().True(found)
	suite.Require().True(rechecked.Consumed)
	suite.Require().Zero(rechecked.UsesRemaining)
}
