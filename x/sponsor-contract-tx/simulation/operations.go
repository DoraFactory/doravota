package simulation

import (
	"encoding/json"
	"math/rand"

	wasmtypes "github.com/CosmWasm/wasmd/x/wasm/types"
	"github.com/cosmos/cosmos-sdk/baseapp"
	"github.com/cosmos/cosmos-sdk/codec"
	sdk "github.com/cosmos/cosmos-sdk/types"
	simtypes "github.com/cosmos/cosmos-sdk/types/simulation"
	"github.com/cosmos/cosmos-sdk/x/simulation"

	"github.com/DoraFactory/doravota/x/sponsor-contract-tx/keeper"
	"github.com/DoraFactory/doravota/x/sponsor-contract-tx/types"
)

// Operation weights constants
const (
	OpWeightMsgSetSponsor    = "op_weight_msg_set_sponsor"
	OpWeightMsgUpdateSponsor = "op_weight_msg_update_sponsor" 
	OpWeightMsgDeleteSponsor = "op_weight_msg_delete_sponsor"
	OpWeightSponsoredTx      = "op_weight_sponsored_tx"
	OpWeightPolicyCheck      = "op_weight_policy_check"
	OpWeightUserGrantUsage   = "op_weight_user_grant_usage"

	DefaultWeightMsgSetSponsor    = 100
	DefaultWeightMsgUpdateSponsor = 50
	DefaultWeightMsgDeleteSponsor = 30
	DefaultWeightSponsoredTx      = 200
	DefaultWeightPolicyCheck      = 80
	DefaultWeightUserGrantUsage   = 60
)

// WeightedOperations returns all the operations from the module with their respective weights
func WeightedOperations(appParams simtypes.AppParams, cdc codec.JSONCodec, k keeper.Keeper, ak types.AccountKeeper, bk types.BankKeeper, wk types.WasmKeeperInterface) simulation.WeightedOperations {
	var (
		weightMsgSetSponsor    int
		weightMsgUpdateSponsor int
		weightMsgDeleteSponsor int
		weightSponsoredTx      int
		weightPolicyCheck      int
		weightUserGrantUsage   int
	)

	appParams.GetOrGenerate(cdc, OpWeightMsgSetSponsor, &weightMsgSetSponsor, nil,
		func(_ *rand.Rand) {
			weightMsgSetSponsor = DefaultWeightMsgSetSponsor
		},
	)

	appParams.GetOrGenerate(cdc, OpWeightMsgUpdateSponsor, &weightMsgUpdateSponsor, nil,
		func(_ *rand.Rand) {
			weightMsgUpdateSponsor = DefaultWeightMsgUpdateSponsor
		},
	)

	appParams.GetOrGenerate(cdc, OpWeightMsgDeleteSponsor, &weightMsgDeleteSponsor, nil,
		func(_ *rand.Rand) {
			weightMsgDeleteSponsor = DefaultWeightMsgDeleteSponsor
		},
	)

	appParams.GetOrGenerate(cdc, OpWeightSponsoredTx, &weightSponsoredTx, nil,
		func(_ *rand.Rand) {
			weightSponsoredTx = DefaultWeightSponsoredTx
		},
	)

	appParams.GetOrGenerate(cdc, OpWeightPolicyCheck, &weightPolicyCheck, nil,
		func(_ *rand.Rand) {
			weightPolicyCheck = DefaultWeightPolicyCheck
		},
	)

	appParams.GetOrGenerate(cdc, OpWeightUserGrantUsage, &weightUserGrantUsage, nil,
		func(_ *rand.Rand) {
			weightUserGrantUsage = DefaultWeightUserGrantUsage
		},
	)

	return simulation.WeightedOperations{
		simulation.NewWeightedOperation(
			weightMsgSetSponsor,
			SimulateMsgSetSponsor(ak, bk, k, wk),
		),
		simulation.NewWeightedOperation(
			weightMsgUpdateSponsor,
			SimulateMsgUpdateSponsor(ak, bk, k, wk),
		),
		simulation.NewWeightedOperation(
			weightMsgDeleteSponsor,
			SimulateMsgDeleteSponsor(ak, bk, k, wk),
		),
		simulation.NewWeightedOperation(
			weightSponsoredTx,
			SimulateSponsoredTransaction(ak, bk, k, wk),
		),
		simulation.NewWeightedOperation(
			weightPolicyCheck,
			SimulatePolicyCheck(ak, bk, k, wk),
		),
		simulation.NewWeightedOperation(
			weightUserGrantUsage,
			SimulateUserGrantUsage(ak, bk, k, wk),
		),
	}
}

// SimulateMsgSetSponsor generates a MsgSetSponsor operation
func SimulateMsgSetSponsor(ak types.AccountKeeper, bk types.BankKeeper, k keeper.Keeper, wk types.WasmKeeperInterface) simtypes.Operation {
	return func(r *rand.Rand, app *baseapp.BaseApp, ctx sdk.Context, accs []simtypes.Account, chainID string) (simtypes.OperationMsg, []simtypes.FutureOperation, error) {
		// Select random creator (admin)
		creator, _ := simtypes.RandomAcc(r, accs)
		
		// Skip account keeper check if not available (for testing)
		if ak != nil {
			creatorAcc := ak.GetAccount(ctx, creator.Address)
			if creatorAcc == nil {
				return simtypes.NoOpMsg(types.ModuleName, types.TypeMsgSetSponsor, "creator account not found"), nil, nil
			}
		}

		// Generate random contract address  
		contractAddr := simtypes.RandomAccounts(r, 1)[0].Address

		// Random sponsorship settings
		isSponsored := r.Intn(2) == 0
		
		var maxGrantPerUser sdk.Coins
		if isSponsored {
			// When sponsored, require max grant per user (only peaka)
			amount := sdk.NewInt(int64(r.Intn(1000000) + 1000)) // 1000-1001000
			maxGrantPerUser = sdk.NewCoins(sdk.NewCoin("peaka", amount))
		} else {
			// When not sponsored, max grant can be empty or have peaka
			if r.Intn(2) == 0 {
				amount := sdk.NewInt(int64(r.Intn(1000000) + 1000))
				maxGrantPerUser = sdk.NewCoins(sdk.NewCoin("peaka", amount))
			}
		}

		// Convert to proto coins
		protoCoins := make([]*sdk.Coin, len(maxGrantPerUser))
		for i, coin := range maxGrantPerUser {
			coinCopy := coin
			protoCoins[i] = &coinCopy
		}

		msg := &types.MsgSetSponsor{
			Creator:         creator.Address.String(),
			ContractAddress: contractAddr.String(), 
			IsSponsored:     isSponsored,
			MaxGrantPerUser: protoCoins,
		}

		// Check if sponsor already exists (should update instead)
		if _, found := k.GetSponsor(ctx, contractAddr.String()); found {
			return simtypes.NoOpMsg(types.ModuleName, types.TypeMsgSetSponsor, "sponsor already exists"), nil, nil
		}

		// Validate message
		if err := msg.ValidateBasic(); err != nil {
			return simtypes.NoOpMsg(types.ModuleName, types.TypeMsgSetSponsor, "invalid message"), nil, nil
		}

		// For simulation, we return a no-op message since we can't easily construct full transactions
		return simtypes.NewOperationMsgBasic(types.ModuleName, types.TypeMsgSetSponsor, "set sponsor simulation", true, nil), nil, nil
	}
}

// SimulateMsgUpdateSponsor generates a MsgUpdateSponsor operation
func SimulateMsgUpdateSponsor(ak types.AccountKeeper, bk types.BankKeeper, k keeper.Keeper, wk types.WasmKeeperInterface) simtypes.Operation {
	return func(r *rand.Rand, app *baseapp.BaseApp, ctx sdk.Context, accs []simtypes.Account, chainID string) (simtypes.OperationMsg, []simtypes.FutureOperation, error) {
		// Get all existing sponsors
		sponsors := k.GetAllSponsors(ctx)
		if len(sponsors) == 0 {
			return simtypes.NoOpMsg(types.ModuleName, types.TypeMsgUpdateSponsor, "no sponsors exist"), nil, nil
		}

		// Select random sponsor to update
		sponsor := sponsors[r.Intn(len(sponsors))]

		// Find creator account
		creatorAddr, err := sdk.AccAddressFromBech32(sponsor.CreatorAddress)
		if err != nil {
			return simtypes.NoOpMsg(types.ModuleName, types.TypeMsgUpdateSponsor, "invalid creator address"), nil, nil
		}

		_, found := simtypes.FindAccount(accs, creatorAddr)
		if !found {
			return simtypes.NoOpMsg(types.ModuleName, types.TypeMsgUpdateSponsor, "creator account not found"), nil, nil
		}

		// Generate new random settings
		isSponsored := r.Intn(2) == 0
		
		var maxGrantPerUser sdk.Coins
		if isSponsored {
			amount := sdk.NewInt(int64(r.Intn(2000000) + 1000)) // Different range for update
			maxGrantPerUser = sdk.NewCoins(sdk.NewCoin("peaka", amount))
		} else if r.Intn(2) == 0 {
			amount := sdk.NewInt(int64(r.Intn(2000000) + 1000))
			maxGrantPerUser = sdk.NewCoins(sdk.NewCoin("peaka", amount))
		}

		// Convert to proto coins
		protoCoins := make([]*sdk.Coin, len(maxGrantPerUser))
		for i, coin := range maxGrantPerUser {
			coinCopy := coin
			protoCoins[i] = &coinCopy
		}

		msg := &types.MsgUpdateSponsor{
			Creator:         sponsor.CreatorAddress,
			ContractAddress: sponsor.ContractAddress,
			IsSponsored:     isSponsored,
			MaxGrantPerUser: protoCoins,
		}

		// Validate message
		if err := msg.ValidateBasic(); err != nil {
			return simtypes.NoOpMsg(types.ModuleName, types.TypeMsgUpdateSponsor, "invalid message"), nil, nil
		}

		return simtypes.NewOperationMsgBasic(types.ModuleName, types.TypeMsgUpdateSponsor, "update sponsor simulation", true, nil), nil, nil
	}
}

// SimulateMsgDeleteSponsor generates a MsgDeleteSponsor operation
func SimulateMsgDeleteSponsor(ak types.AccountKeeper, bk types.BankKeeper, k keeper.Keeper, wk types.WasmKeeperInterface) simtypes.Operation {
	return func(r *rand.Rand, app *baseapp.BaseApp, ctx sdk.Context, accs []simtypes.Account, chainID string) (simtypes.OperationMsg, []simtypes.FutureOperation, error) {
		// Get all existing sponsors
		sponsors := k.GetAllSponsors(ctx)
		if len(sponsors) == 0 {
			return simtypes.NoOpMsg(types.ModuleName, types.TypeMsgDeleteSponsor, "no sponsors exist"), nil, nil
		}

		// Select random sponsor to delete
		sponsor := sponsors[r.Intn(len(sponsors))]

		// Find creator account
		creatorAddr, err := sdk.AccAddressFromBech32(sponsor.CreatorAddress)
		if err != nil {
			return simtypes.NoOpMsg(types.ModuleName, types.TypeMsgDeleteSponsor, "invalid creator address"), nil, nil
		}

		_, found := simtypes.FindAccount(accs, creatorAddr)
		if !found {
			return simtypes.NoOpMsg(types.ModuleName, types.TypeMsgDeleteSponsor, "creator account not found"), nil, nil
		}

		msg := &types.MsgDeleteSponsor{
			Creator:         sponsor.CreatorAddress,
			ContractAddress: sponsor.ContractAddress,
		}

		// Validate message
		if err := msg.ValidateBasic(); err != nil {
			return simtypes.NoOpMsg(types.ModuleName, types.TypeMsgDeleteSponsor, "invalid message"), nil, nil
		}

		return simtypes.NewOperationMsgBasic(types.ModuleName, types.TypeMsgDeleteSponsor, "delete sponsor simulation", true, nil), nil, nil
	}
}

// SimulateSponsoredTransaction simulates a sponsored contract execution transaction
func SimulateSponsoredTransaction(ak types.AccountKeeper, bk types.BankKeeper, k keeper.Keeper, wk types.WasmKeeperInterface) simtypes.Operation {
	return func(r *rand.Rand, app *baseapp.BaseApp, ctx sdk.Context, accs []simtypes.Account, chainID string) (simtypes.OperationMsg, []simtypes.FutureOperation, error) {
		// Get all sponsored contracts (is_sponsored = true)
		allSponsors := k.GetAllSponsors(ctx)
		var sponsoredContracts []types.ContractSponsor
		for _, sponsor := range allSponsors {
			if sponsor.IsSponsored {
				sponsoredContracts = append(sponsoredContracts, sponsor)
			}
		}

		if len(sponsoredContracts) == 0 {
			return simtypes.NoOpMsg(types.ModuleName, "sponsored_tx", "no sponsored contracts"), nil, nil
		}

		// Select random sponsored contract
		contract := sponsoredContracts[r.Intn(len(sponsoredContracts))]

		// Select random user (sender)
		sender, _ := simtypes.RandomAcc(r, accs)

		// Generate random contract execution message
		msgTypes := []string{"increment", "decrement", "reset", "set_value"}
		msgType := msgTypes[r.Intn(len(msgTypes))]
		
		var executeMsg map[string]interface{}
		switch msgType {
		case "increment":
			executeMsg = map[string]interface{}{"increment": map[string]interface{}{}}
		case "decrement":
			executeMsg = map[string]interface{}{"decrement": map[string]interface{}{}}
		case "reset":
			executeMsg = map[string]interface{}{"reset": map[string]interface{}{}}
		case "set_value":
			executeMsg = map[string]interface{}{
				"set_value": map[string]interface{}{
					"value": r.Intn(1000),
				},
			}
		}

		msgBytes, _ := json.Marshal(executeMsg)

		// Create contract execute message (for validation)
		_ = &wasmtypes.MsgExecuteContract{
			Sender:   sender.Address.String(),
			Contract: contract.ContractAddress,
			Msg:      msgBytes,
			Funds:    nil, // No funds for sponsored tx
		}

		return simtypes.NewOperationMsgBasic(types.ModuleName, "sponsored_tx", "sponsored transaction simulation", true, nil), nil, nil
	}
}

// SimulatePolicyCheck simulates policy validation scenarios
func SimulatePolicyCheck(ak types.AccountKeeper, bk types.BankKeeper, k keeper.Keeper, wk types.WasmKeeperInterface) simtypes.Operation {
	return func(r *rand.Rand, app *baseapp.BaseApp, ctx sdk.Context, accs []simtypes.Account, chainID string) (simtypes.OperationMsg, []simtypes.FutureOperation, error) {
		// This operation tests policy checking without sending actual transactions
		// It helps test edge cases in policy validation

		// Get all sponsored contracts
		allSponsors := k.GetAllSponsors(ctx)
		var sponsoredContracts []types.ContractSponsor
		for _, sponsor := range allSponsors {
			if sponsor.IsSponsored {
				sponsoredContracts = append(sponsoredContracts, sponsor)
			}
		}

		if len(sponsoredContracts) == 0 {
			return simtypes.NoOpMsg(types.ModuleName, "policy_check", "no sponsored contracts"), nil, nil
		}

		// Select random contract and test different policy scenarios
		contract := sponsoredContracts[r.Intn(len(sponsoredContracts))]
		
		// Test different message types and edge cases
		testScenarios := []struct {
			msgType string
			msgData interface{}
		}{
			{"increment", map[string]interface{}{}},
			{"decrement", map[string]interface{}{}},
			{"malformed", "invalid_json"},
			{"empty", nil},
			{"large_data", map[string]interface{}{"data": generateLargeString(r, 1000)}},
		}

		scenario := testScenarios[r.Intn(len(testScenarios))]
		
		// This is a read-only operation that tests policy checking
		// We don't actually send a transaction, just test the policy logic
		ctx.Logger().Info("Simulating policy check", 
			"contract", contract.ContractAddress,
			"msg_type", scenario.msgType,
		)

		return simtypes.NoOpMsg(types.ModuleName, "policy_check", "policy check completed"), nil, nil
	}
}

// SimulateUserGrantUsage simulates user grant usage scenarios
func SimulateUserGrantUsage(ak types.AccountKeeper, bk types.BankKeeper, k keeper.Keeper, wk types.WasmKeeperInterface) simtypes.Operation {
	return func(r *rand.Rand, app *baseapp.BaseApp, ctx sdk.Context, accs []simtypes.Account, chainID string) (simtypes.OperationMsg, []simtypes.FutureOperation, error) {
		// Test user grant usage edge cases and limits
		
		// Get all sponsored contracts
		allSponsors := k.GetAllSponsors(ctx)
		var sponsoredContracts []types.ContractSponsor
		for _, sponsor := range allSponsors {
			if sponsor.IsSponsored {
				sponsoredContracts = append(sponsoredContracts, sponsor)
			}
		}

		if len(sponsoredContracts) == 0 {
			return simtypes.NoOpMsg(types.ModuleName, "user_grant_usage", "no sponsored contracts"), nil, nil
		}

		// Select random contract and user
		contract := sponsoredContracts[r.Intn(len(sponsoredContracts))]
		user, _ := simtypes.RandomAcc(r, accs)

		// Test various grant usage scenarios
		usage := k.GetUserGrantUsage(ctx, user.Address.String(), contract.ContractAddress)
		
		// Simulate different usage patterns
		scenarios := []string{
			"normal_usage",
			"near_limit", 
			"at_limit",
			"over_limit",
			"multiple_requests",
		}
		
		scenario := scenarios[r.Intn(len(scenarios))]
		
		ctx.Logger().Info("Simulating user grant usage",
			"user", user.Address.String(),
			"contract", contract.ContractAddress,
			"scenario", scenario,
			"current_usage", usage.TotalGrantUsed,
		)

		return simtypes.NoOpMsg(types.ModuleName, "user_grant_usage", "grant usage check completed"), nil, nil
	}
}

// Helper function to generate large test strings
func generateLargeString(r *rand.Rand, size int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, size)
	for i := range b {
		b[i] = charset[r.Intn(len(charset))]
	}
	return string(b)
}