package simulation

import (
	"encoding/json"
	"math/rand"

	wasmtypes "github.com/CosmWasm/wasmd/x/wasm/types"
	"github.com/cosmos/cosmos-sdk/baseapp"
	"github.com/cosmos/cosmos-sdk/codec"
	codectypes "github.com/cosmos/cosmos-sdk/codec/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
	simtypes "github.com/cosmos/cosmos-sdk/types/simulation"
	authtx "github.com/cosmos/cosmos-sdk/x/auth/tx"
	banktypes "github.com/cosmos/cosmos-sdk/x/bank/types"
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

const (
	simulationMethod = "reflect"
	fundSponsorType  = "fund_sponsor"
)

// contractInfoIterator is implemented by the production Wasm keeper. Keeping
// it local avoids expanding the Sponsor keeper's runtime dependency solely for
// simulations.
type contractInfoIterator interface {
	IterateContractInfo(ctx sdk.Context, cb func(sdk.AccAddress, wasmtypes.ContractInfo) bool)
}

type managedContract struct {
	address sdk.AccAddress
	admin   simtypes.Account
}

// simulationMsg is the common shape of all messages delivered by this module's
// randomized operations.
type simulationMsg interface {
	sdk.Msg
	Type() string
}

func deliverSimulationMsg(
	r *rand.Rand,
	app *baseapp.BaseApp,
	ctx sdk.Context,
	msg simulationMsg,
	simAccount simtypes.Account,
	ak types.AccountKeeper,
	bk types.BankKeeper,
	coinsSpent sdk.Coins,
) (simtypes.OperationMsg, []simtypes.FutureOperation, error) {
	if app == nil || ak == nil || bk == nil {
		return simtypes.NoOpMsg(types.ModuleName, msg.Type(), "simulation dependencies are not configured"), nil, nil
	}

	registry := codectypes.NewInterfaceRegistry()
	types.RegisterInterfaces(registry)
	wasmtypes.RegisterInterfaces(registry)
	banktypes.RegisterInterfaces(registry)
	protoCodec := codec.NewProtoCodec(registry)

	return simulation.GenAndDeliverTxWithRandFees(simulation.OperationInput{
		R:               r,
		App:             app,
		TxGen:           authtx.NewTxConfig(protoCodec, authtx.DefaultSignModes),
		Cdc:             protoCodec,
		Msg:             msg,
		MsgType:         msg.Type(),
		CoinsSpentInMsg: coinsSpent,
		Context:         ctx,
		SimAccount:      simAccount,
		AccountKeeper:   ak,
		Bankkeeper:      bk,
		ModuleName:      types.ModuleName,
	})
}

func findSimulationAccount(accs []simtypes.Account, address string) (simtypes.Account, bool) {
	admin, err := types.AccAddressFromCanonicalBech32(address)
	if err != nil {
		return simtypes.Account{}, false
	}
	return simtypes.FindAccount(accs, admin)
}

func currentManager(
	ctx sdk.Context,
	wk types.WasmKeeperInterface,
	contractAddress string,
	accs []simtypes.Account,
) (simtypes.Account, bool) {
	if wk == nil {
		return simtypes.Account{}, false
	}
	contract, err := types.AccAddressFromCanonicalBech32(contractAddress)
	if err != nil {
		return simtypes.Account{}, false
	}
	info := wk.GetContractInfo(ctx, contract)
	if info == nil || info.Admin == "" {
		return simtypes.Account{}, false
	}
	return findSimulationAccount(accs, info.Admin)
}

func availableManagedContracts(
	ctx sdk.Context,
	k keeper.Keeper,
	wk types.WasmKeeperInterface,
	accs []simtypes.Account,
) []managedContract {
	if wk == nil {
		return nil
	}

	candidates := make([]managedContract, 0)
	addCandidate := func(contract sdk.AccAddress, info *wasmtypes.ContractInfo) {
		if info == nil || info.Admin == "" {
			return
		}
		if _, found := k.GetSponsor(ctx, contract.String()); found {
			return
		}
		admin, found := findSimulationAccount(accs, info.Admin)
		if !found {
			return
		}
		candidates = append(candidates, managedContract{address: contract, admin: admin})
	}

	if iterator, ok := wk.(contractInfoIterator); ok {
		iterator.IterateContractInfo(ctx, func(contract sdk.AccAddress, info wasmtypes.ContractInfo) bool {
			infoCopy := info
			addCandidate(contract, &infoCopy)
			return false
		})
		return candidates
	}

	// Test doubles may not expose iteration. Looking up simulation-account
	// addresses preserves useful unit coverage without weakening production
	// contract selection.
	for _, account := range accs {
		addCandidate(account.Address, wk.GetContractInfo(ctx, account.Address))
	}
	return candidates
}

func randomGrant(r *rand.Rand, max int64) sdk.Coins {
	return sdk.NewCoins(sdk.NewCoin(
		types.SponsorshipDenom,
		sdk.NewInt(r.Int63n(max)+1),
	))
}

func reflectOwner(
	ctx sdk.Context,
	wk types.WasmKeeperInterface,
	contract sdk.AccAddress,
	accs []simtypes.Account,
) (simtypes.Account, bool) {
	if wk == nil {
		return simtypes.Account{}, false
	}
	response, err := wk.QuerySmart(ctx, contract, []byte(`{"owner":{}}`))
	if err != nil {
		return simtypes.Account{}, false
	}
	var owner struct {
		Owner string `json:"owner"`
	}
	if err := json.Unmarshal(response, &owner); err != nil || owner.Owner == "" {
		return simtypes.Account{}, false
	}
	return findSimulationAccount(accs, owner.Owner)
}

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
		candidates := availableManagedContracts(ctx, k, wk, accs)
		if len(candidates) == 0 {
			return simtypes.NoOpMsg(types.ModuleName, types.TypeMsgSetSponsor, "no unmanaged contract with a simulation admin"), nil, nil
		}
		selected := candidates[r.Intn(len(candidates))]

		isSponsored := r.Intn(4) != 0
		maxGrantPerUser := randomGrant(r, 1_000_000)
		if !isSponsored && r.Intn(2) == 0 {
			maxGrantPerUser = nil
		}
		msg := types.NewMsgSetSponsor(
			selected.admin.Address.String(),
			selected.address.String(),
			isSponsored,
			maxGrantPerUser,
		)
		if err := msg.ValidateBasic(); err != nil {
			return simtypes.NoOpMsg(types.ModuleName, msg.Type(), err.Error()), nil, nil
		}

		operationMsg, _, err := deliverSimulationMsg(
			r, app, ctx, msg, selected.admin, ak, bk, nil,
		)
		if err != nil || !operationMsg.OK {
			return operationMsg, nil, err
		}

		// A deterministic sponsor account is not part of the simulator account
		// set, so generic bank operations will almost never fund it. Schedule a
		// real MsgSend after creation to make sponsored execution reachable.
		future := simtypes.FutureOperation{
			BlockHeight: int(ctx.BlockHeight()) + 1,
			Op: fundSpecificSponsor(
				selected.address.String(),
				selected.admin,
				ak,
				bk,
				k,
			),
		}
		return operationMsg, []simtypes.FutureOperation{future}, nil
	}
}

// SimulateMsgUpdateSponsor generates a MsgUpdateSponsor operation
func SimulateMsgUpdateSponsor(ak types.AccountKeeper, bk types.BankKeeper, k keeper.Keeper, wk types.WasmKeeperInterface) simtypes.Operation {
	return func(r *rand.Rand, app *baseapp.BaseApp, ctx sdk.Context, accs []simtypes.Account, chainID string) (simtypes.OperationMsg, []simtypes.FutureOperation, error) {
		sponsors := k.GetAllSponsors(ctx)
		type candidate struct {
			sponsor types.ContractSponsor
			manager simtypes.Account
		}
		candidates := make([]candidate, 0, len(sponsors))
		for _, sponsor := range sponsors {
			manager, found := currentManager(ctx, wk, sponsor.ContractAddress, accs)
			if found {
				candidates = append(candidates, candidate{sponsor: sponsor, manager: manager})
			}
		}
		if len(candidates) == 0 {
			return simtypes.NoOpMsg(types.ModuleName, types.TypeMsgUpdateSponsor, "no sponsor controlled by a simulation account"), nil, nil
		}
		selected := candidates[r.Intn(len(candidates))]

		isSponsored := r.Intn(2) == 0
		maxGrantPerUser := randomGrant(r, 2_000_000)
		msg := types.NewMsgUpdateSponsor(
			selected.manager.Address.String(),
			selected.sponsor.ContractAddress,
			isSponsored,
			maxGrantPerUser,
		)
		if err := msg.ValidateBasic(); err != nil {
			return simtypes.NoOpMsg(types.ModuleName, msg.Type(), err.Error()), nil, nil
		}

		return deliverSimulationMsg(r, app, ctx, msg, selected.manager, ak, bk, nil)
	}
}

// SimulateMsgDeleteSponsor generates a MsgDeleteSponsor operation
func SimulateMsgDeleteSponsor(ak types.AccountKeeper, bk types.BankKeeper, k keeper.Keeper, wk types.WasmKeeperInterface) simtypes.Operation {
	return func(r *rand.Rand, app *baseapp.BaseApp, ctx sdk.Context, accs []simtypes.Account, chainID string) (simtypes.OperationMsg, []simtypes.FutureOperation, error) {
		sponsors := k.GetAllSponsors(ctx)
		type candidate struct {
			sponsor types.ContractSponsor
			manager simtypes.Account
		}
		candidates := make([]candidate, 0, len(sponsors))
		for _, sponsor := range sponsors {
			manager, found := currentManager(ctx, wk, sponsor.ContractAddress, accs)
			if found {
				candidates = append(candidates, candidate{sponsor: sponsor, manager: manager})
			}
		}
		if len(candidates) == 0 {
			return simtypes.NoOpMsg(types.ModuleName, types.TypeMsgDeleteSponsor, "no sponsor controlled by a simulation account"), nil, nil
		}
		selected := candidates[r.Intn(len(candidates))]

		sponsorAddress, err := types.AccAddressFromCanonicalBech32(selected.sponsor.SponsorAddress)
		if err != nil {
			return simtypes.NoOpMsg(types.ModuleName, types.TypeMsgDeleteSponsor, "invalid sponsor address"), nil, nil
		}
		if bk != nil && !bk.SpendableCoins(ctx, sponsorAddress).Empty() {
			withdraw := &types.MsgWithdrawSponsorFunds{
				Creator:         selected.manager.Address.String(),
				ContractAddress: selected.sponsor.ContractAddress,
				Recipient:       selected.manager.Address.String(),
			}
			operationMsg, _, deliverErr := deliverSimulationMsg(
				r, app, ctx, withdraw, selected.manager, ak, bk, nil,
			)
			if deliverErr != nil || !operationMsg.OK {
				return operationMsg, nil, deliverErr
			}
			return operationMsg, []simtypes.FutureOperation{{
				BlockHeight: int(ctx.BlockHeight()) + 1,
				Op: deleteSpecificSponsor(
					selected.sponsor.ContractAddress,
					ak,
					bk,
					k,
					wk,
				),
			}}, nil
		}

		msg := types.NewMsgDeleteSponsor(
			selected.manager.Address.String(),
			selected.sponsor.ContractAddress,
		)
		if err := msg.ValidateBasic(); err != nil {
			return simtypes.NoOpMsg(types.ModuleName, msg.Type(), err.Error()), nil, nil
		}
		return deliverSimulationMsg(r, app, ctx, msg, selected.manager, ak, bk, nil)
	}
}

// SimulateSponsoredTransaction simulates a sponsored contract execution transaction
func SimulateSponsoredTransaction(ak types.AccountKeeper, bk types.BankKeeper, k keeper.Keeper, wk types.WasmKeeperInterface) simtypes.Operation {
	return func(r *rand.Rand, app *baseapp.BaseApp, ctx sdk.Context, accs []simtypes.Account, chainID string) (simtypes.OperationMsg, []simtypes.FutureOperation, error) {
		type candidate struct {
			ticket   types.PolicyTicket
			sender   simtypes.Account
			contract sdk.AccAddress
		}
		candidates := make([]candidate, 0)
		k.IteratePolicyTickets(ctx, func(_ []byte, ticket types.PolicyTicket) bool {
			if ticket.Method != simulationMethod || ticket.Consumed ||
				uint64(ctx.BlockHeight()) > ticket.ExpiryHeight {
				return false
			}
			sponsor, found := k.GetSponsor(ctx, ticket.ContractAddress)
			if !found || !sponsor.IsSponsored || sponsor.Generation != ticket.Generation {
				return false
			}
			sponsorAddress, err := types.AccAddressFromCanonicalBech32(sponsor.SponsorAddress)
			if err != nil || bk == nil || bk.SpendableCoins(ctx, sponsorAddress).Empty() {
				return false
			}
			sender, found := findSimulationAccount(accs, ticket.UserAddress)
			if !found {
				return false
			}
			contract, err := types.AccAddressFromCanonicalBech32(ticket.ContractAddress)
			if err != nil {
				return false
			}
			owner, found := reflectOwner(ctx, wk, contract, accs)
			if !found || !owner.Address.Equals(sender.Address) {
				return false
			}
			candidates = append(candidates, candidate{
				ticket: ticket, sender: sender, contract: contract,
			})
			return false
		})
		if len(candidates) == 0 {
			return simtypes.NoOpMsg(types.ModuleName, "sponsored_tx", "no funded sponsor with an active reflect ticket"), nil, nil
		}
		selected := candidates[r.Intn(len(candidates))]

		msgBytes, err := json.Marshal(map[string]interface{}{
			simulationMethod: map[string]interface{}{
				"msgs": []interface{}{},
			},
		})
		if err != nil {
			return simtypes.NoOpMsg(types.ModuleName, "sponsored_tx", "failed to build reflect payload"), nil, err
		}
		msg := &wasmtypes.MsgExecuteContract{
			Sender:   selected.sender.Address.String(),
			Contract: selected.contract.String(),
			Msg:      msgBytes,
		}
		return deliverSimulationMsg(r, app, ctx, msg, selected.sender, ak, bk, nil)
	}
}

// SimulatePolicyCheck prepares the two-phase sponsorship path by issuing a
// real policy ticket for a reflect-contract owner.
func SimulatePolicyCheck(ak types.AccountKeeper, bk types.BankKeeper, k keeper.Keeper, wk types.WasmKeeperInterface) simtypes.Operation {
	return func(r *rand.Rand, app *baseapp.BaseApp, ctx sdk.Context, accs []simtypes.Account, chainID string) (simtypes.OperationMsg, []simtypes.FutureOperation, error) {
		type candidate struct {
			sponsor types.ContractSponsor
			manager simtypes.Account
			owner   simtypes.Account
		}
		candidates := make([]candidate, 0)
		for _, sponsor := range k.GetAllSponsors(ctx) {
			if !sponsor.IsSponsored {
				continue
			}
			manager, found := currentManager(ctx, wk, sponsor.ContractAddress, accs)
			if !found {
				continue
			}
			contract, err := types.AccAddressFromCanonicalBech32(sponsor.ContractAddress)
			if err != nil {
				continue
			}
			owner, found := reflectOwner(ctx, wk, contract, accs)
			if !found {
				continue
			}
			digest := k.ComputeMethodDigestSingle(sponsor.ContractAddress, simulationMethod)
			if _, found := k.GetActivePolicyTicket(
				ctx,
				sponsor.ContractAddress,
				owner.Address.String(),
				digest,
			); found {
				continue
			}
			candidates = append(candidates, candidate{
				sponsor: sponsor,
				manager: manager,
				owner:   owner,
			})
		}
		if len(candidates) == 0 {
			return simtypes.NoOpMsg(types.ModuleName, "policy_check", "no sponsored reflect contract needs a ticket"), nil, nil
		}
		selected := candidates[r.Intn(len(candidates))]

		msg := &types.MsgIssuePolicyTicket{
			Creator:         selected.manager.Address.String(),
			ContractAddress: selected.sponsor.ContractAddress,
			UserAddress:     selected.owner.Address.String(),
			Method:          simulationMethod,
			Uses:            uint32(r.Intn(3) + 1),
		}
		if err := msg.ValidateBasic(); err != nil {
			return simtypes.NoOpMsg(types.ModuleName, msg.Type(), err.Error()), nil, nil
		}
		return deliverSimulationMsg(r, app, ctx, msg, selected.manager, ak, bk, nil)
	}
}

// SimulateUserGrantUsage simulates user grant usage scenarios
func SimulateUserGrantUsage(ak types.AccountKeeper, bk types.BankKeeper, k keeper.Keeper, wk types.WasmKeeperInterface) simtypes.Operation {
	return func(r *rand.Rand, app *baseapp.BaseApp, ctx sdk.Context, accs []simtypes.Account, chainID string) (simtypes.OperationMsg, []simtypes.FutureOperation, error) {
		type candidate struct {
			sponsor   types.ContractSponsor
			user      simtypes.Account
			remaining sdk.Int
		}
		candidates := make([]candidate, 0)
		for _, sponsor := range k.GetAllSponsors(ctx) {
			if !sponsor.IsSponsored {
				continue
			}
			maxGrant, err := k.GetMaxGrantPerUser(ctx, sponsor.ContractAddress)
			if err != nil {
				continue
			}
			for _, user := range accs {
				usage := k.GetUserGrantUsage(ctx, user.Address.String(), sponsor.ContractAddress)
				used := sdk.Coins{}
				for _, coin := range usage.TotalGrantUsed {
					if coin != nil {
						used = used.Add(*coin)
					}
				}
				remaining := maxGrant.AmountOf(types.SponsorshipDenom).
					Sub(used.AmountOf(types.SponsorshipDenom))
				if remaining.IsPositive() {
					candidates = append(candidates, candidate{
						sponsor:   sponsor,
						user:      user,
						remaining: remaining,
					})
				}
			}
		}
		if len(candidates) == 0 {
			return simtypes.NoOpMsg(types.ModuleName, "user_grant_usage", "no user has remaining sponsor grant"), nil, nil
		}
		selected := candidates[r.Intn(len(candidates))]
		upper := selected.remaining
		if upper.GT(sdk.NewInt(100_000)) {
			upper = sdk.NewInt(100_000)
		}
		amount := sdk.NewInt(r.Int63n(upper.Int64()) + 1)
		consumed := sdk.NewCoins(sdk.NewCoin(types.SponsorshipDenom, amount))
		if err := k.CheckUserGrantLimit(
			ctx,
			selected.user.Address.String(),
			selected.sponsor.ContractAddress,
			consumed,
		); err != nil {
			return simtypes.NoOpMsg(types.ModuleName, "user_grant_usage", err.Error()), nil, nil
		}
		if err := k.UpdateUserGrantUsage(
			ctx,
			selected.user.Address.String(),
			selected.sponsor.ContractAddress,
			consumed,
		); err != nil {
			return simtypes.NoOpMsg(types.ModuleName, "user_grant_usage", err.Error()), nil, err
		}
		msg, err := json.Marshal(map[string]string{
			"contract": selected.sponsor.ContractAddress,
			"user":     selected.user.Address.String(),
			"amount":   consumed.String(),
		})
		if err != nil {
			return simtypes.NoOpMsg(types.ModuleName, "user_grant_usage", "failed to encode transition"), nil, err
		}
		return simtypes.NewOperationMsgBasic(
			types.ModuleName,
			"user_grant_usage",
			"updated sponsor grant usage",
			true,
			msg,
		), nil, nil
	}
}

func fundSpecificSponsor(
	contractAddress string,
	funder simtypes.Account,
	ak types.AccountKeeper,
	bk types.BankKeeper,
	k keeper.Keeper,
) simtypes.Operation {
	return func(
		r *rand.Rand,
		app *baseapp.BaseApp,
		ctx sdk.Context,
		_ []simtypes.Account,
		_ string,
	) (simtypes.OperationMsg, []simtypes.FutureOperation, error) {
		sponsor, found := k.GetSponsor(ctx, contractAddress)
		if !found {
			return simtypes.NoOpMsg(types.ModuleName, fundSponsorType, "sponsor was removed before funding"), nil, nil
		}
		sponsorAddress, err := types.AccAddressFromCanonicalBech32(sponsor.SponsorAddress)
		if err != nil {
			return simtypes.NoOpMsg(types.ModuleName, fundSponsorType, "invalid sponsor address"), nil, nil
		}
		if bk == nil {
			return simtypes.NoOpMsg(types.ModuleName, fundSponsorType, "bank keeper is not configured"), nil, nil
		}
		available := bk.SpendableCoins(ctx, funder.Address).AmountOf(types.SponsorshipDenom)
		if available.LTE(sdk.OneInt()) {
			return simtypes.NoOpMsg(types.ModuleName, fundSponsorType, "admin has no funds available for sponsor"), nil, nil
		}

		upper := available.QuoRaw(4)
		if upper.IsZero() {
			upper = sdk.OneInt()
		}
		if upper.GT(sdk.NewInt(1_000_000)) {
			upper = sdk.NewInt(1_000_000)
		}
		amount := sdk.NewInt(r.Int63n(upper.Int64()) + 1)
		funds := sdk.NewCoins(sdk.NewCoin(types.SponsorshipDenom, amount))
		msg := banktypes.NewMsgSend(funder.Address, sponsorAddress, funds)
		return deliverSimulationMsg(r, app, ctx, msg, funder, ak, bk, funds)
	}
}

func deleteSpecificSponsor(
	contractAddress string,
	ak types.AccountKeeper,
	bk types.BankKeeper,
	k keeper.Keeper,
	wk types.WasmKeeperInterface,
) simtypes.Operation {
	return func(
		r *rand.Rand,
		app *baseapp.BaseApp,
		ctx sdk.Context,
		accs []simtypes.Account,
		_ string,
	) (simtypes.OperationMsg, []simtypes.FutureOperation, error) {
		sponsor, found := k.GetSponsor(ctx, contractAddress)
		if !found {
			return simtypes.NoOpMsg(types.ModuleName, types.TypeMsgDeleteSponsor, "sponsor already removed"), nil, nil
		}
		manager, found := currentManager(ctx, wk, contractAddress, accs)
		if !found {
			return simtypes.NoOpMsg(types.ModuleName, types.TypeMsgDeleteSponsor, "current admin is not a simulation account"), nil, nil
		}
		sponsorAddress, err := types.AccAddressFromCanonicalBech32(sponsor.SponsorAddress)
		if err != nil {
			return simtypes.NoOpMsg(types.ModuleName, types.TypeMsgDeleteSponsor, "invalid sponsor address"), nil, nil
		}
		if bk != nil && !bk.SpendableCoins(ctx, sponsorAddress).Empty() {
			return simtypes.NoOpMsg(types.ModuleName, types.TypeMsgDeleteSponsor, "sponsor still has funds"), nil, nil
		}
		msg := types.NewMsgDeleteSponsor(manager.Address.String(), contractAddress)
		return deliverSimulationMsg(r, app, ctx, msg, manager, ak, bk, nil)
	}
}
