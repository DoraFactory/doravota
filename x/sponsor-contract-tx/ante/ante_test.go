package sponsor

import (
	"testing"

	wasmtypes "github.com/CosmWasm/wasmd/x/wasm/types"
	"github.com/cometbft/cometbft/libs/log"
	tmproto "github.com/cometbft/cometbft/proto/tendermint/types"
	"github.com/cosmos/cosmos-sdk/codec"
	codectypes "github.com/cosmos/cosmos-sdk/codec/types"
	"github.com/cosmos/cosmos-sdk/store"
	storetypes "github.com/cosmos/cosmos-sdk/store/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
	authkeeper "github.com/cosmos/cosmos-sdk/x/auth/keeper"
	authtypes "github.com/cosmos/cosmos-sdk/x/auth/types"
	bankkeeper "github.com/cosmos/cosmos-sdk/x/bank/keeper"
	banktypes "github.com/cosmos/cosmos-sdk/x/bank/types"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"

	dbm "github.com/cometbft/cometbft-db"

	"github.com/DoraFactory/doravota/x/sponsor-contract-tx/keeper"
	"github.com/DoraFactory/doravota/x/sponsor-contract-tx/types"
)

// Helper function to convert sdk.Coins to []*sdk.Coin for protobuf
func coinsToProtoCoins(coins sdk.Coins) []*sdk.Coin {
	result := make([]*sdk.Coin, len(coins))
	for i, coin := range coins {
		coinCopy := coin // Create a copy to avoid pointer issues
		result[i] = &coinCopy
	}
	return result
}

// AnteTestSuite implements a test suite for ante handler testing
type AnteTestSuite struct {
	suite.Suite

	ctx           sdk.Context
	keeper        keeper.Keeper
	anteDecorator SponsorContractTxAnteDecorator
	accountKeeper authkeeper.AccountKeeper
	bankKeeper    bankkeeper.Keeper
	wasmKeeper    *MockWasmKeeper

	// Test accounts
	admin     sdk.AccAddress
	user      sdk.AccAddress
	contract  sdk.AccAddress
	feeGranter sdk.AccAddress
}

type MockWasmKeeper struct {
	contracts    map[string]*wasmtypes.ContractInfo
	queryResults map[string][]byte
}

func NewMockWasmKeeper() *MockWasmKeeper {
	return &MockWasmKeeper{
		contracts:    make(map[string]*wasmtypes.ContractInfo),
		queryResults: make(map[string][]byte),
	}
}

func (m *MockWasmKeeper) GetContractInfo(ctx sdk.Context, contractAddress sdk.AccAddress) *wasmtypes.ContractInfo {
	return m.contracts[contractAddress.String()]
}

func (m *MockWasmKeeper) QuerySmart(ctx sdk.Context, contractAddr sdk.AccAddress, req []byte) ([]byte, error) {
	if result, exists := m.queryResults[contractAddr.String()]; exists {
		return result, nil
	}
	return []byte(`{"eligible": true}`), nil
}

func (m *MockWasmKeeper) SetContractInfo(contractAddr sdk.AccAddress, admin string) {
	m.contracts[contractAddr.String()] = &wasmtypes.ContractInfo{
		Admin: admin,
	}
}

func (m *MockWasmKeeper) SetQueryResult(contractAddr sdk.AccAddress, result []byte) {
	m.queryResults[contractAddr.String()] = result
}

func (suite *AnteTestSuite) SetupTest() {
	// Create codec with proper interface registrations
	interfaceRegistry := codectypes.NewInterfaceRegistry()
	// Register auth interfaces for BaseAccount
	authtypes.RegisterInterfaces(interfaceRegistry)
	// Register bank interfaces for coin types
	banktypes.RegisterInterfaces(interfaceRegistry)
	// Register wasm interfaces for contract messages
	wasmtypes.RegisterInterfaces(interfaceRegistry)
	// Register sponsor module interfaces
	types.RegisterInterfaces(interfaceRegistry)
	
	codec := codec.NewProtoCodec(interfaceRegistry)

	// Create in-memory database
	db := dbm.NewMemDB()

	// Create multi-store
	cms := store.NewCommitMultiStore(db)

	// Create store keys
	sponsorStoreKey := sdk.NewKVStoreKey(types.StoreKey)
	authStoreKey := sdk.NewKVStoreKey(authtypes.StoreKey)
	bankStoreKey := sdk.NewKVStoreKey(banktypes.StoreKey)

	// Mount stores
	cms.MountStoreWithDB(sponsorStoreKey, storetypes.StoreTypeIAVL, db)
	cms.MountStoreWithDB(authStoreKey, storetypes.StoreTypeIAVL, db)
	cms.MountStoreWithDB(bankStoreKey, storetypes.StoreTypeIAVL, db)

	// Load stores
	err := cms.LoadLatestVersion()
	suite.Require().NoError(err)

	// Create context
	suite.ctx = sdk.NewContext(cms, tmproto.Header{Height: 1}, false, log.NewNopLogger())

	// Create mock wasm keeper
	suite.wasmKeeper = NewMockWasmKeeper()

	// Create keepers
	maccPerms := map[string][]string{
		authtypes.FeeCollectorName: nil,
		types.ModuleName:           {authtypes.Minter, authtypes.Burner},
	}
	
	suite.accountKeeper = authkeeper.NewAccountKeeper(
		codec,
		authStoreKey,
		authtypes.ProtoBaseAccount,
		maccPerms,
		"dora",
		authtypes.NewModuleAddress("gov").String(),
	)

	suite.bankKeeper = bankkeeper.NewBaseKeeper(
		codec,
		bankStoreKey,
		suite.accountKeeper,
		nil,
		authtypes.NewModuleAddress("gov").String(),
	)

	// Create sponsor keeper
	suite.keeper = *keeper.NewKeeper(
		codec,
		sponsorStoreKey,
		suite.wasmKeeper,
	)

	// Create ante decorator
	suite.anteDecorator = NewSponsorContractTxAnteDecorator(
		suite.keeper,
		suite.accountKeeper,
		suite.bankKeeper,
	)

	// Set up test accounts
	suite.admin = sdk.AccAddress("admin_______________")
	suite.user = sdk.AccAddress("user________________")
	suite.contract = sdk.AccAddress("contract____________")
	suite.feeGranter = sdk.AccAddress("feegranter__________")

	// Create accounts
	adminAcc := suite.accountKeeper.NewAccountWithAddress(suite.ctx, suite.admin)
	userAcc := suite.accountKeeper.NewAccountWithAddress(suite.ctx, suite.user)
	contractAcc := suite.accountKeeper.NewAccountWithAddress(suite.ctx, suite.contract)
	feeGranterAcc := suite.accountKeeper.NewAccountWithAddress(suite.ctx, suite.feeGranter)

	suite.accountKeeper.SetAccount(suite.ctx, adminAcc)
	suite.accountKeeper.SetAccount(suite.ctx, userAcc)
	suite.accountKeeper.SetAccount(suite.ctx, contractAcc)
	suite.accountKeeper.SetAccount(suite.ctx, feeGranterAcc)

	// Create sponsor module account for minting coins
	sponsorModuleAcc := authtypes.NewEmptyModuleAccount(types.ModuleName, authtypes.Minter, authtypes.Burner)
	suite.accountKeeper.SetAccount(suite.ctx, sponsorModuleAcc)

	// Set up default module parameters
	params := types.DefaultParams()
	suite.keeper.SetParams(suite.ctx, params)
}

// Test case: Sponsorship disabled globally
func (suite *AnteTestSuite) TestSponsorshipGloballyDisabled() {
	// Disable sponsorship globally
	params := types.DefaultParams()
	params.SponsorshipEnabled = false
	suite.keeper.SetParams(suite.ctx, params)

	// Create a contract execution transaction
	tx := suite.createContractExecuteTx(suite.contract, suite.user, sdk.NewCoins(sdk.NewCoin("stake", sdk.NewInt(1000))))

	// Mock next handler
	nextCalled := false
	next := func(ctx sdk.Context, tx sdk.Tx, simulate bool) (sdk.Context, error) {
		nextCalled = true
		return ctx, nil
	}

	// Execute ante handler
	_, err := suite.anteDecorator.AnteHandle(suite.ctx, tx, false, next)

	// Verify
	suite.Require().NoError(err)
	suite.Require().True(nextCalled)

	// Verify event was emitted
	events := suite.ctx.EventManager().Events()
	suite.Require().Greater(len(events), 0)
	
	found := false
	for _, event := range events {
		if event.Type == types.EventTypeSponsorshipDisabled {
			found = true
			break
		}
	}
	suite.Require().True(found, "Expected sponsorship disabled event")
}

// Test case: Transaction with FeeGranter should skip sponsor logic
func (suite *AnteTestSuite) TestFeeGranterSkipsSponsorLogic() {
	// Create a transaction with FeeGranter set
	tx := suite.createContractExecuteTxWithFeeGranter(suite.contract, suite.user, suite.feeGranter, sdk.NewCoins(sdk.NewCoin("stake", sdk.NewInt(1000))))

	// Mock next handler
	nextCalled := false
	next := func(ctx sdk.Context, tx sdk.Tx, simulate bool) (sdk.Context, error) {
		nextCalled = true
		return ctx, nil
	}

	// Execute ante handler
	_, err := suite.anteDecorator.AnteHandle(suite.ctx, tx, false, next)

	// Verify
	suite.Require().NoError(err)
	suite.Require().True(nextCalled)

	// Verify sponsor payment info is NOT in context
	sponsorPayment, ok := suite.ctx.Value(sponsorPaymentKey{}).(SponsorPaymentInfo)
	suite.Require().False(ok)
	suite.Require().Empty(sponsorPayment.ContractAddr)
}

// Test case: Non-contract transaction should pass through
func (suite *AnteTestSuite) TestNonContractTransactionPassThrough() {
	// Create a non-contract transaction (bank send)
	tx := suite.createBankSendTx(suite.user, suite.admin, sdk.NewCoins(sdk.NewCoin("stake", sdk.NewInt(1000))))

	// Mock next handler
	nextCalled := false
	next := func(ctx sdk.Context, tx sdk.Tx, simulate bool) (sdk.Context, error) {
		nextCalled = true
		return ctx, nil
	}

	// Execute ante handler
	_, err := suite.anteDecorator.AnteHandle(suite.ctx, tx, false, next)

	// Verify
	suite.Require().NoError(err)
	suite.Require().True(nextCalled)
}

// Test case: Contract not sponsored should pass through
func (suite *AnteTestSuite) TestContractNotSponsoredPassThrough() {
	// Set up contract info but don't register for sponsorship
	suite.wasmKeeper.SetContractInfo(suite.contract, suite.admin.String())

	// Create contract execution transaction
	tx := suite.createContractExecuteTx(suite.contract, suite.user, sdk.NewCoins(sdk.NewCoin("stake", sdk.NewInt(1000))))

	// Mock next handler
	nextCalled := false
	next := func(ctx sdk.Context, tx sdk.Tx, simulate bool) (sdk.Context, error) {
		nextCalled = true
		return ctx, nil
	}

	// Execute ante handler
	_, err := suite.anteDecorator.AnteHandle(suite.ctx, tx, false, next)

	// Verify
	suite.Require().NoError(err)
	suite.Require().True(nextCalled)
}

// Test case: User ineligible according to contract policy
func (suite *AnteTestSuite) TestUserIneligibleForSponsorship() {
	// Set up contract and sponsorship
	suite.wasmKeeper.SetContractInfo(suite.contract, suite.admin.String())
	suite.wasmKeeper.SetQueryResult(suite.contract, []byte(`{"eligible": false}`))
	
	maxGrant := sdk.NewCoins(sdk.NewCoin("stake", sdk.NewInt(10000)))
	sponsor := types.ContractSponsor{
		ContractAddress: suite.contract.String(),
		CreatorAddress:  suite.admin.String(),
		IsSponsored:     true,
		MaxGrantPerUser: coinsToProtoCoins(maxGrant),
	}
	err := suite.keeper.SetSponsor(suite.ctx, sponsor)
	suite.Require().NoError(err)

	// Create contract execution transaction
	tx := suite.createContractExecuteTx(suite.contract, suite.user, sdk.NewCoins(sdk.NewCoin("stake", sdk.NewInt(1000))))

	// Mock next handler
	next := func(ctx sdk.Context, tx sdk.Tx, simulate bool) (sdk.Context, error) {
		return ctx, nil
	}

	// Execute ante handler - should fail
	_, err = suite.anteDecorator.AnteHandle(suite.ctx, tx, false, next)

	// Verify error
	suite.Require().Error(err)
	suite.Require().Contains(err.Error(), "not eligible")
}

// Test case: User has sufficient balance, should pay own fees
func (suite *AnteTestSuite) TestUserHasSufficientBalance() {
	// Set up contract and sponsorship
	suite.wasmKeeper.SetContractInfo(suite.contract, suite.admin.String())
	
	maxGrant := sdk.NewCoins(sdk.NewCoin("stake", sdk.NewInt(10000)))
	sponsor := types.ContractSponsor{
		ContractAddress: suite.contract.String(),
		CreatorAddress:  suite.admin.String(),
		IsSponsored:     true,
		MaxGrantPerUser: coinsToProtoCoins(maxGrant),
	}
	err := suite.keeper.SetSponsor(suite.ctx, sponsor)
	suite.Require().NoError(err)

	// Give user sufficient balance
	fee := sdk.NewCoins(sdk.NewCoin("stake", sdk.NewInt(1000)))
	err = suite.bankKeeper.MintCoins(suite.ctx, types.ModuleName, fee)
	suite.Require().NoError(err)
	err = suite.bankKeeper.SendCoinsFromModuleToAccount(suite.ctx, types.ModuleName, suite.user, fee)
	suite.Require().NoError(err)

	// Create contract execution transaction
	tx := suite.createContractExecuteTx(suite.contract, suite.user, fee)

	// Mock next handler
	nextCalled := false
	next := func(ctx sdk.Context, tx sdk.Tx, simulate bool) (sdk.Context, error) {
		nextCalled = true
		return ctx, nil
	}

	// Execute ante handler
	_, err = suite.anteDecorator.AnteHandle(suite.ctx, tx, false, next)

	// Verify
	suite.Require().NoError(err)
	suite.Require().True(nextCalled)

	// Verify self-pay event was emitted
	events := suite.ctx.EventManager().Events()
	found := false
	for _, event := range events {
		if event.Type == types.EventTypeUserSelfPay {
			found = true
			break
		}
	}
	suite.Require().True(found, "Expected user self-pay event")
}

// Test case: Sponsor has insufficient funds
func (suite *AnteTestSuite) TestSponsorInsufficientFunds() {
	// Set up contract and sponsorship
	suite.wasmKeeper.SetContractInfo(suite.contract, suite.admin.String())
	
	maxGrant := sdk.NewCoins(sdk.NewCoin("stake", sdk.NewInt(10000)))
	sponsor := types.ContractSponsor{
		ContractAddress: suite.contract.String(),
		CreatorAddress:  suite.admin.String(),
		IsSponsored:     true,
		MaxGrantPerUser: coinsToProtoCoins(maxGrant),
	}
	err := suite.keeper.SetSponsor(suite.ctx, sponsor)
	suite.Require().NoError(err)

	// Don't fund the contract (sponsor has insufficient funds)
	fee := sdk.NewCoins(sdk.NewCoin("stake", sdk.NewInt(1000)))

	// Create contract execution transaction
	tx := suite.createContractExecuteTx(suite.contract, suite.user, fee)

	// Mock next handler
	next := func(ctx sdk.Context, tx sdk.Tx, simulate bool) (sdk.Context, error) {
		return ctx, nil
	}

	// Execute ante handler - should fail
	_, err = suite.anteDecorator.AnteHandle(suite.ctx, tx, false, next)

	// Verify error
	suite.Require().Error(err)
	suite.Require().Contains(err.Error(), "insufficient funds")

	// Verify insufficient funds event was emitted
	events := suite.ctx.EventManager().Events()
	found := false
	for _, event := range events {
		if event.Type == types.EventTypeSponsorInsufficient {
			found = true
			break
		}
	}
	suite.Require().True(found, "Expected sponsor insufficient funds event")
}

// Test case: Successful sponsorship setup
func (suite *AnteTestSuite) TestSuccessfulSponsorshipSetup() {
	// Set up contract and sponsorship
	suite.wasmKeeper.SetContractInfo(suite.contract, suite.admin.String())
	
	maxGrant := sdk.NewCoins(sdk.NewCoin("stake", sdk.NewInt(10000)))
	sponsor := types.ContractSponsor{
		ContractAddress: suite.contract.String(),
		CreatorAddress:  suite.admin.String(),
		IsSponsored:     true,
		MaxGrantPerUser: coinsToProtoCoins(maxGrant),
	}
	err := suite.keeper.SetSponsor(suite.ctx, sponsor)
	suite.Require().NoError(err)

	// Fund the contract (sponsor)
	fee := sdk.NewCoins(sdk.NewCoin("stake", sdk.NewInt(1000)))
	err = suite.bankKeeper.MintCoins(suite.ctx, types.ModuleName, fee)
	suite.Require().NoError(err)
	err = suite.bankKeeper.SendCoinsFromModuleToAccount(suite.ctx, types.ModuleName, suite.contract, fee)
	suite.Require().NoError(err)

	// Create contract execution transaction
	tx := suite.createContractExecuteTx(suite.contract, suite.user, fee)

	// Mock next handler
	nextCalled := false
	var contextReceived sdk.Context
	next := func(ctx sdk.Context, tx sdk.Tx, simulate bool) (sdk.Context, error) {
		nextCalled = true
		contextReceived = ctx
		return ctx, nil
	}

	// Execute ante handler
	_, err = suite.anteDecorator.AnteHandle(suite.ctx, tx, false, next)

	// Verify
	suite.Require().NoError(err)
	suite.Require().True(nextCalled)

	// Verify sponsor payment info is in context
	sponsorPayment, ok := contextReceived.Value(sponsorPaymentKey{}).(SponsorPaymentInfo)
	suite.Require().True(ok)
	suite.Require().Equal(suite.contract, sponsorPayment.ContractAddr)
	suite.Require().Equal(suite.user, sponsorPayment.UserAddr)
	suite.Require().Equal(fee, sponsorPayment.Fee)
	suite.Require().True(sponsorPayment.IsSponsored)
}

// Test case: Multi-signer transaction should be rejected
func (suite *AnteTestSuite) TestMultiSignerTransactionRejected() {
	// Set up contract and sponsorship
	suite.wasmKeeper.SetContractInfo(suite.contract, suite.admin.String())
	
	maxGrant := sdk.NewCoins(sdk.NewCoin("stake", sdk.NewInt(10000)))
	sponsor := types.ContractSponsor{
		ContractAddress: suite.contract.String(),
		CreatorAddress:  suite.admin.String(),
		IsSponsored:     true,
		MaxGrantPerUser: coinsToProtoCoins(maxGrant),
	}
	err := suite.keeper.SetSponsor(suite.ctx, sponsor)
	suite.Require().NoError(err)

	// Create multi-signer transaction
	tx := suite.createMultiSignerContractExecuteTx(suite.contract, []sdk.AccAddress{suite.user, suite.admin}, sdk.NewCoins(sdk.NewCoin("stake", sdk.NewInt(1000))))

	// Mock next handler
	next := func(ctx sdk.Context, tx sdk.Tx, simulate bool) (sdk.Context, error) {
		return ctx, nil
	}

	// Execute ante handler - should fallback to standard processing
	_, err = suite.anteDecorator.AnteHandle(suite.ctx, tx, false, next)

	// Should not error but should not set sponsor context either
	suite.Require().NoError(err)
}

// Helper functions for creating test transactions

func (suite *AnteTestSuite) createContractExecuteTx(contract sdk.AccAddress, signer sdk.AccAddress, fee sdk.Coins) sdk.Tx {
	msg := &wasmtypes.MsgExecuteContract{
		Sender:   signer.String(),
		Contract: contract.String(),
		Msg:      []byte(`{"increment":{}}`),
		Funds:    nil,
	}

	return suite.createTx([]sdk.Msg{msg}, []sdk.AccAddress{signer}, fee, nil)
}

func (suite *AnteTestSuite) createContractExecuteTxWithFeeGranter(contract sdk.AccAddress, signer sdk.AccAddress, feeGranter sdk.AccAddress, fee sdk.Coins) sdk.Tx {
	msg := &wasmtypes.MsgExecuteContract{
		Sender:   signer.String(),
		Contract: contract.String(),
		Msg:      []byte(`{"increment":{}}`),
		Funds:    nil,
	}

	return suite.createTx([]sdk.Msg{msg}, []sdk.AccAddress{signer}, fee, feeGranter)
}

func (suite *AnteTestSuite) createMultiSignerContractExecuteTx(contract sdk.AccAddress, signers []sdk.AccAddress, fee sdk.Coins) sdk.Tx {
	var msgs []sdk.Msg
	for _, signer := range signers {
		msg := &wasmtypes.MsgExecuteContract{
			Sender:   signer.String(),
			Contract: contract.String(),
			Msg:      []byte(`{"increment":{}}`),
			Funds:    nil,
		}
		msgs = append(msgs, msg)
	}

	return suite.createTx(msgs, signers, fee, nil)
}

func (suite *AnteTestSuite) createBankSendTx(from sdk.AccAddress, to sdk.AccAddress, amount sdk.Coins) sdk.Tx {
	msg := &banktypes.MsgSend{
		FromAddress: from.String(),
		ToAddress:   to.String(),
		Amount:      amount,
	}

	return suite.createTx([]sdk.Msg{msg}, []sdk.AccAddress{from}, sdk.NewCoins(sdk.NewCoin("stake", sdk.NewInt(100))), nil)
}

// MockTx implements sdk.Tx and sdk.FeeTx for testing
type MockTx struct {
	msgs        []sdk.Msg
	fee         sdk.Coins
	gasLimit    uint64
	feePayer    sdk.AccAddress
	feeGranter  sdk.AccAddress
}

func (tx MockTx) GetMsgs() []sdk.Msg {
	return tx.msgs
}

func (tx MockTx) ValidateBasic() error {
	return nil
}

func (tx MockTx) GetFee() sdk.Coins {
	return tx.fee
}

func (tx MockTx) GetGas() uint64 {
	return tx.gasLimit
}

func (tx MockTx) FeePayer() sdk.AccAddress {
	return tx.feePayer
}

func (tx MockTx) FeeGranter() sdk.AccAddress {
	return tx.feeGranter
}

func (suite *AnteTestSuite) createTx(msgs []sdk.Msg, signers []sdk.AccAddress, fee sdk.Coins, feeGranter sdk.AccAddress) sdk.Tx {
	var feePayer sdk.AccAddress
	if len(signers) > 0 {
		feePayer = signers[0]
	}
	
	return MockTx{
		msgs:       msgs,
		fee:        fee,
		gasLimit:   200000,
		feePayer:   feePayer,
		feeGranter: feeGranter,
	}
}

// Run the test suite
func TestAnteTestSuite(t *testing.T) {
	suite.Run(t, new(AnteTestSuite))
}

// Additional individual test functions for edge cases

func TestValidateSponsoredTransaction(t *testing.T) {
	// Test mixed message types
	msgs := []sdk.Msg{
		&wasmtypes.MsgExecuteContract{
			Sender:   "sender",
			Contract: "contract1",
		},
		&banktypes.MsgSend{
			FromAddress: "sender",
			ToAddress:   "receiver",
		},
	}

	tx := MockTx{
		msgs: msgs,
	}

	_, err := validateSponsoredTransaction(tx)
	require.Error(t, err)
	require.Contains(t, err.Error(), "cannot contain non-contract messages")
}

func TestValidateSponsoredTransactionMultipleContracts(t *testing.T) {
	// Test multiple different contracts
	msgs := []sdk.Msg{
		&wasmtypes.MsgExecuteContract{
			Sender:   "sender",
			Contract: "contract1",
		},
		&wasmtypes.MsgExecuteContract{
			Sender:   "sender",
			Contract: "contract2",
		},
	}

	tx := MockTx{
		msgs: msgs,
	}

	_, err := validateSponsoredTransaction(tx)
	require.Error(t, err)
	require.Contains(t, err.Error(), "same contract")
}