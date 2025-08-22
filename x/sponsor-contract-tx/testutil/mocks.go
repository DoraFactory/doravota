package testutil

import (
	"fmt"
	
	wasmtypes "github.com/CosmWasm/wasmd/x/wasm/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
)

// MockWasmKeeper implements WasmKeeperInterface for testing
type MockWasmKeeper struct {
	contracts    map[string]*wasmtypes.ContractInfo
	queryResults map[string][]byte
	gasUsed      uint64
}

// NewMockWasmKeeper creates a new mock wasm keeper
func NewMockWasmKeeper() *MockWasmKeeper {
	return &MockWasmKeeper{
		contracts:    make(map[string]*wasmtypes.ContractInfo),
		queryResults: make(map[string][]byte),
		gasUsed:      0,
	}
}

// GetContractInfo returns contract info for the given address
func (m *MockWasmKeeper) GetContractInfo(ctx sdk.Context, contractAddress sdk.AccAddress) *wasmtypes.ContractInfo {
	return m.contracts[contractAddress.String()]
}

// QuerySmart executes a smart contract query
func (m *MockWasmKeeper) QuerySmart(ctx sdk.Context, contractAddr sdk.AccAddress, req []byte) ([]byte, error) {
	// Simulate gas consumption for policy queries
	if m.gasUsed > 0 {
		ctx.GasMeter().ConsumeGas(m.gasUsed, "mock query gas")
	}

	// Check if this should return an error
	if result, exists := m.queryResults[contractAddr.String()]; exists {
		if len(result) > 9 && string(result[:9]) == "__ERROR__" {
			return nil, fmt.Errorf("%s", string(result[9:]))
		}
		return result, nil
	}
	
	// Default response: eligible = true
	return []byte(`{"eligible": true}`), nil
}

// SetQueryError sets a query to return an error (simulating contract without check_policy method)
func (m *MockWasmKeeper) SetQueryError(contractAddr sdk.AccAddress, errMsg string) {
	// Store a special marker that indicates this should return an error
	m.queryResults[contractAddr.String()] = []byte("__ERROR__:" + errMsg)
}


// SetContractInfo sets contract info for testing
func (m *MockWasmKeeper) SetContractInfo(contractAddr sdk.AccAddress, admin string) {
	m.contracts[contractAddr.String()] = &wasmtypes.ContractInfo{
		Admin: admin,
	}
}

// SetContractInfoByString sets contract info by string address for testing
func (m *MockWasmKeeper) SetContractInfoByString(contractAddr string, admin string) {
	accAddr, _ := sdk.AccAddressFromBech32(contractAddr)
	m.contracts[accAddr.String()] = &wasmtypes.ContractInfo{
		Admin: admin,
	}
}

// SetQueryResult sets a specific query result for a contract
func (m *MockWasmKeeper) SetQueryResult(contractAddr sdk.AccAddress, result []byte) {
	m.queryResults[contractAddr.String()] = result
}

// SetQueryResultByString sets a specific query result for a contract by string address
func (m *MockWasmKeeper) SetQueryResultByString(contractAddr string, result []byte) {
	accAddr, _ := sdk.AccAddressFromBech32(contractAddr)
	m.queryResults[accAddr.String()] = result
}

// SetQueryResultEligible sets the contract as eligible for sponsorship
func (m *MockWasmKeeper) SetQueryResultEligible(contractAddr sdk.AccAddress, eligible bool) {
	var result []byte
	if eligible {
		result = []byte(`{"eligible": true}`)
	} else {
		result = []byte(`{"eligible": false}`)
	}
	m.queryResults[contractAddr.String()] = result
}

// SetGasUsage sets the amount of gas to consume on each query (for testing gas limits)
func (m *MockWasmKeeper) SetGasUsage(gas uint64) {
	m.gasUsed = gas
}

// Reset clears all stored data
func (m *MockWasmKeeper) Reset() {
	m.contracts = make(map[string]*wasmtypes.ContractInfo)
	m.queryResults = make(map[string][]byte)
	m.gasUsed = 0
}

// MockTxFeeChecker implements ante.TxFeeChecker for testing
func MockTxFeeChecker(ctx sdk.Context, tx sdk.Tx) (sdk.Coins, int64, error) {
	// Return minimum fee for testing
	minFee := sdk.NewCoins(sdk.NewCoin("stake", sdk.NewInt(100)))
	priority := int64(1)
	return minFee, priority, nil
}

// MockTxFeeCheckerHighFee implements ante.TxFeeChecker with higher required fees
func MockTxFeeCheckerHighFee(ctx sdk.Context, tx sdk.Tx) (sdk.Coins, int64, error) {
	// Return higher minimum fee for testing fee validation
	minFee := sdk.NewCoins(sdk.NewCoin("stake", sdk.NewInt(1000)))
	priority := int64(1)
	return minFee, priority, nil
}

// MockTxFeeCheckerZero implements ante.TxFeeChecker with zero required fees
func MockTxFeeCheckerZero(ctx sdk.Context, tx sdk.Tx) (sdk.Coins, int64, error) {
	// Return zero fees for testing
	minFee := sdk.NewCoins()
	priority := int64(0)
	return minFee, priority, nil
}