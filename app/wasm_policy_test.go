package app_test

import (
	"crypto/sha256"
	"encoding/json"
	"testing"
	"time"

	wasmkeeper "github.com/CosmWasm/wasmd/x/wasm/keeper"
	"github.com/CosmWasm/wasmd/x/wasm/keeper/testdata"
	wasmtypes "github.com/CosmWasm/wasmd/x/wasm/types"
	"github.com/DoraFactory/doravota/app"
	abci "github.com/cometbft/cometbft/abci/types"
	"github.com/cometbft/cometbft/crypto/ed25519"
	tmtypes "github.com/cometbft/cometbft/types"
	simtestutil "github.com/cosmos/cosmos-sdk/testutil/sims"
	sdk "github.com/cosmos/cosmos-sdk/types"
	authtypes "github.com/cosmos/cosmos-sdk/x/auth/types"
	banktypes "github.com/cosmos/cosmos-sdk/x/bank/types"
	transfertypes "github.com/cosmos/ibc-go/v11/modules/apps/transfer/types"
	"github.com/stretchr/testify/require"
)

// Import a real existing hackatom contract, with funds still in its account.
// No upload/instantiate permission is needed for restoring committed state.
func TestRestrictedWasmStillExecutesExistingContract(t *testing.T) {
	a := policyTestApp(t)
	creator := sdk.AccAddress(ed25519.GenPrivKey().PubKey().Address())
	beneficiary := sdk.AccAddress(ed25519.GenPrivKey().PubKey().Address())
	contract := sdk.AccAddress(ed25519.GenPrivKey().PubKey().Address())
	val := ed25519.GenPrivKey().PubKey()
	cp := tmtypes.DefaultConsensusParams().ToProto()
	genesis, err := simtestutil.GenesisStateWithValSet(a.AppCodec(), app.NewDefaultGenesisState(a.AppCodec()),
		tmtypes.NewValidatorSet([]*tmtypes.Validator{tmtypes.NewValidator(val, 1)}),
		[]authtypes.GenesisAccount{authtypes.NewBaseAccountWithAddress(creator), authtypes.NewBaseAccountWithAddress(contract)},
		banktypes.Balance{Address: contract.String(), Coins: sdk.NewCoins(sdk.NewInt64Coin(sdk.DefaultBondDenom, 11))})
	require.NoError(t, err)
	code := testdata.HackatomContractWasm()
	hash := sha256.Sum256(code)
	config, err := json.Marshal(map[string]string{"verifier": creator.String(), "beneficiary": beneficiary.String(), "funder": creator.String()})
	require.NoError(t, err)
	pos := &wasmtypes.AbsoluteTxPosition{BlockHeight: 1, TxIndex: 1}
	state := wasmtypes.GenesisState{
		Params: wasmtypes.DefaultParams(),
		Codes:  []wasmtypes.Code{{CodeID: 1, CodeInfo: wasmtypes.CodeInfo{CodeHash: hash[:], Creator: creator.String(), InstantiateConfig: wasmtypes.AllowEverybody}, CodeBytes: code}},
		Contracts: []wasmtypes.Contract{{ContractAddress: contract.String(), ContractInfo: wasmtypes.ContractInfo{CodeID: 1, Creator: creator.String(), Admin: creator.String(), Label: "retained", Created: pos},
			ContractState:       []wasmtypes.Model{{Key: []byte("config"), Value: config}},
			ContractCodeHistory: []wasmtypes.ContractCodeHistoryEntry{{Operation: wasmtypes.ContractCodeHistoryOperationTypeInit, CodeID: 1, Updated: pos, Msg: []byte(`{}`)}}}},
		Sequences: []wasmtypes.Sequence{{IDKey: wasmtypes.KeySequenceCodeID, Value: 2}, {IDKey: wasmtypes.KeySequenceInstanceID, Value: 2}},
	}
	require.NoError(t, state.ValidateBasic())
	genesis[wasmtypes.ModuleName] = a.AppCodec().MustMarshalJSON(&state)
	raw, err := json.Marshal(genesis)
	require.NoError(t, err)
	stamp := time.Unix(1700000000, 0)
	_, err = a.InitChain(&abci.RequestInitChain{ChainId: "policy-test", InitialHeight: 1, Time: stamp, ConsensusParams: &cp, AppStateBytes: raw})
	require.NoError(t, err)
	ctx := a.NewContext(false).WithBlockTime(stamp).WithBlockHeight(1).WithChainID("policy-test")
	require.Equal(t, wasmtypes.AllowNobody, a.WasmKeeper.GetParams(ctx).CodeUploadAccess)
	require.Equal(t, wasmtypes.AccessTypeNobody, a.WasmKeeper.GetParams(ctx).InstantiateDefaultPermission)
	require.Equal(t, wasmtypes.AllowNobody, a.WasmKeeper.GetCodeInfo(ctx, 1).InstantiateConfig)
	require.Equal(t, config, a.WasmKeeper.QueryRaw(ctx, contract, []byte("config")))
	query, err := a.WasmKeeper.QuerySmart(ctx, contract, []byte(`{"verifier":{}}`))
	require.NoError(t, err)
	require.JSONEq(t, `{"verifier":"`+creator.String()+`"}`, string(query))
	for _, keeper := range []*wasmkeeper.PermissionedKeeper{wasmkeeper.NewDefaultPermissionKeeper(a.WasmKeeper), wasmkeeper.NewGovPermissionKeeper(a.WasmKeeper)} {
		_, _, err = keeper.Create(ctx, creator, code, nil)
		require.ErrorContains(t, err, "deployment is disabled")
		_, _, err = keeper.Instantiate(ctx, 1, creator, creator, []byte(`{}`), "blocked", nil)
		require.ErrorContains(t, err, "deployment is disabled")
		_, _, err = keeper.Instantiate2(ctx, 1, creator, creator, []byte(`{}`), "blocked", nil, []byte("salt"), false)
		require.ErrorContains(t, err, "deployment is disabled")
		_, err = keeper.Migrate(ctx, contract, creator, 1, []byte(`{}`))
		require.ErrorContains(t, err, "migration is disabled")
	}
	// Import is permitted and the normal asset exit path really enters WasmVM.
	_, err = wasmkeeper.NewDefaultPermissionKeeper(a.WasmKeeper).Execute(ctx, contract, creator, []byte(`{"release":{}}`), nil)
	require.NoError(t, err)
	require.True(t, a.BankKeeper.GetBalance(ctx, contract, sdk.DefaultBondDenom).IsZero())
	require.EqualValues(t, 11, a.BankKeeper.GetBalance(ctx, beneficiary, sdk.DefaultBondDenom).Amount.Int64())
	require.Equal(t, []string{"ed25519"}, a.GetConsensusParams(ctx).Validator.PubKeyTypes)
	// IBC runtime and transfer are present; this is NOT a two-chain relay test.
	require.NotNil(t, a.MsgServiceRouter().Handler(&transfertypes.MsgTransfer{}))
	require.NotNil(t, a.GetKey("ibc"))
	require.NotNil(t, a.GetKey("transfer"))
	require.NotNil(t, a.GetKey("wasm"))
	exported := wasmkeeper.ExportGenesis(ctx, &a.WasmKeeper)
	require.Len(t, exported.Contracts, 1)
	require.Len(t, exported.Codes, 1)
	require.Equal(t, code, exported.Codes[0].CodeBytes)
}
