package testutil

import (
	"encoding/json"

	wasmtypes "github.com/CosmWasm/wasmd/x/wasm/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/cosmos/cosmos-sdk/x/auth/signing"
	authtx "github.com/cosmos/cosmos-sdk/x/auth/tx"
	authtypes "github.com/cosmos/cosmos-sdk/x/auth/types"

	"github.com/DoraFactory/doravota/x/sponsor-contract-tx/types"
)

// CoinsToProtoCoins converts sdk.Coins to []*sdk.Coin for protobuf
func CoinsToProtoCoins(coins sdk.Coins) []*sdk.Coin {
	result := make([]*sdk.Coin, len(coins))
	for i, coin := range coins {
		coinCopy := coin // Create a copy to avoid pointer issues
		result[i] = &coinCopy
	}
	return result
}

// ProtoCoinsToCoins converts []*sdk.Coin to sdk.Coins
func ProtoCoinsToCoins(protoCoins []*sdk.Coin) sdk.Coins {
	result := make(sdk.Coins, len(protoCoins))
	for i, coin := range protoCoins {
		if coin != nil {
			result[i] = *coin
		}
	}
	return result
}

// NewTestContractSponsor creates a test contract sponsor
func NewTestContractSponsor(contractAddr, creatorAddr string, isSponsored bool, maxGrant sdk.Coins) types.ContractSponsor {
	return types.ContractSponsor{
		ContractAddress: contractAddr,
		CreatorAddress:  creatorAddr,
		IsSponsored:     isSponsored,
		MaxGrantPerUser: CoinsToProtoCoins(maxGrant),
	}
}

// NewTestUserGrantUsage creates a test user grant usage
func NewTestUserGrantUsage(userAddr, contractAddr string, used sdk.Coins, lastTime int64) types.UserGrantUsage {
	return types.UserGrantUsage{
		UserAddress:     userAddr,
		ContractAddress: contractAddr,
		TotalGrantUsed:  CoinsToProtoCoins(used),
		LastUsedTime:    lastTime,
	}
}

// CreateTestContractExecuteMsg creates a test contract execution message
func CreateTestContractExecuteMsg(sender, contract string, msg string, funds sdk.Coins) *wasmtypes.MsgExecuteContract {
	// Create execute message JSON
	executeMsg := map[string]interface{}{
		"increment": map[string]interface{}{},
	}

	if msg != "" {
		// Parse custom message if provided
		var customMsg map[string]interface{}
		if err := json.Unmarshal([]byte(msg), &customMsg); err == nil {
			executeMsg = customMsg
		}
	}

	msgBytes, _ := json.Marshal(executeMsg)

	return &wasmtypes.MsgExecuteContract{
		Sender:   sender,
		Contract: contract,
		Msg:      msgBytes,
		Funds:    funds,
	}
}

// CreateTestTx creates a test transaction with the given messages, fees, and gas
func CreateTestTx(msgs []sdk.Msg, fees sdk.Coins, gas uint64, signer sdk.AccAddress, feeGranter sdk.AccAddress) sdk.Tx {
	// Create a basic transaction config
	txConfig := authtx.NewTxConfig(nil, authtx.DefaultSignModes)
	txBuilder := txConfig.NewTxBuilder()

	// Set messages
	err := txBuilder.SetMsgs(msgs...)
	if err != nil {
		panic(err)
	}

	// Set fees and gas
	txBuilder.SetFeeAmount(fees)
	txBuilder.SetGasLimit(gas)

	// Set fee granter if provided
	if !feeGranter.Empty() {
		txBuilder.SetFeeGranter(feeGranter)
	}

	// Set fee payer
	txBuilder.SetFeePayer(signer)

	return txBuilder.GetTx()
}

// CreateTestFeeTx creates a test FeeTx (implements sdk.FeeTx interface)
type TestFeeTx struct {
	msgs       []sdk.Msg
	fees       sdk.Coins
	gas        uint64
	feePayer   sdk.AccAddress
	feeGranter sdk.AccAddress
}

// NewTestFeeTx creates a new test fee transaction
func NewTestFeeTx(msgs []sdk.Msg, fees sdk.Coins, gas uint64, feePayer sdk.AccAddress, feeGranter sdk.AccAddress) *TestFeeTx {
	return &TestFeeTx{
		msgs:       msgs,
		fees:       fees,
		gas:        gas,
		feePayer:   feePayer,
		feeGranter: feeGranter,
	}
}

// GetMsgs implements sdk.Tx
func (tx *TestFeeTx) GetMsgs() []sdk.Msg {
	return tx.msgs
}

// ValidateBasic implements sdk.Tx
func (tx *TestFeeTx) ValidateBasic() error {
	return nil
}

// GetFee implements sdk.FeeTx
func (tx *TestFeeTx) GetFee() sdk.Coins {
	return tx.fees
}

// GetGas implements sdk.FeeTx
func (tx *TestFeeTx) GetGas() uint64 {
	return tx.gas
}

// GetFeePayer implements sdk.FeeTx
func (tx *TestFeeTx) GetFeePayer() sdk.AccAddress {
	return tx.feePayer
}

// GetFeeGranter implements sdk.FeeTx
func (tx *TestFeeTx) GetFeeGranter() sdk.AccAddress {
	return tx.feeGranter
}

// Implement additional required methods for sdk.Tx interface
func (tx *TestFeeTx) GetSigners() []sdk.AccAddress {
	signers := make([]sdk.AccAddress, 0)
	for _, msg := range tx.msgs {
		signers = append(signers, msg.GetSigners()...)
	}
	return signers
}

// GetSignBytes - not implemented for test
func (tx *TestFeeTx) GetSignBytes(ctx sdk.Context, signerData signing.SignerData, signerAddr sdk.AccAddress) ([]byte, error) {
	return nil, nil
}

// Test Accounts - Common test account addresses
var (
	TestAdmin      = sdk.AccAddress("admin_______________")
	TestUser1      = sdk.AccAddress("user1_______________")
	TestUser2      = sdk.AccAddress("user2_______________")
	TestContract1  = sdk.AccAddress("contract1___________")
	TestContract2  = sdk.AccAddress("contract2___________")
	TestFeeGranter = sdk.AccAddress("feegranter__________")
)

// Test Coins - Common test coin denominations and amounts
var (
	TestStakeCoins = sdk.NewCoins(sdk.NewCoin("stake", sdk.NewInt(1000000)))
    TestPeakaCoins = sdk.NewCoins(sdk.NewCoin(types.SponsorshipDenom, sdk.NewInt(1000000)))
	TestFeeCoins   = sdk.NewCoins(sdk.NewCoin("stake", sdk.NewInt(100)))
	TestMixedCoins = sdk.NewCoins(
		sdk.NewCoin("stake", sdk.NewInt(1000000)),
        sdk.NewCoin(types.SponsorshipDenom, sdk.NewInt(1000000)),
	)
)

// Test Contract Addresses - Common test contract addresses in bech32 format
var (
	TestContractAddr1 = "dora1contract1____________"
	TestContractAddr2 = "dora1contract2____________"
)

// CreateTestGenesisState creates a test genesis state with sponsors
func CreateTestGenesisState(sponsors []types.ContractSponsor) *types.GenesisState {
	params := types.DefaultParams()

	// Convert to pointer slice
	sponsorPtrs := make([]*types.ContractSponsor, len(sponsors))
	for i := range sponsors {
		sponsorPtrs[i] = &sponsors[i]
	}

	return &types.GenesisState{
		Params:   &params,
		Sponsors: sponsorPtrs,
	}
}

// CreateMockFeeCollectorAccount creates a fee collector account for testing
func CreateMockFeeCollectorAccount() authtypes.AccountI {
	feeCollectorAddr := authtypes.NewModuleAddress(authtypes.FeeCollectorName)
	return authtypes.NewBaseAccount(feeCollectorAddr, nil, 0, 0)
}

// CreateTestModule account creates a test module account
func CreateTestModuleAccount(moduleName string) authtypes.AccountI {
	moduleAddr := authtypes.NewModuleAddress(moduleName)
	return authtypes.NewBaseAccount(moduleAddr, nil, 0, 0)
}
