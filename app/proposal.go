package app

import (
	"fmt"

	pqcauthante "github.com/DoraFactory/doravota/x/pqcauth/ante"
	abci "github.com/cometbft/cometbft/abci/types"
	"github.com/cosmos/cosmos-sdk/baseapp"
	"github.com/cosmos/cosmos-sdk/client"
	sdk "github.com/cosmos/cosmos-sdk/types"
)

// Keep the current SDK proposal policy and governed gas/byte limits. Only add
// PQC verification budgets; do not restore the old bridge's 100M gas ceiling.
func (app *App) setProposalHandlers(config client.TxConfig) {
	defaults := baseapp.NewDefaultProposalHandler(app.Mempool(), app.BaseApp)
	prepare := defaults.PrepareProposalHandler()
	process := defaults.ProcessProposalHandler()
	decoder := pqcauthante.CanonicalPQCAuthTxDecoder(config.TxDecoder())
	app.SetPrepareProposal(func(ctx sdk.Context, req *abci.RequestPrepareProposal) (*abci.ResponsePrepareProposal, error) {
		response, err := prepare(ctx, req)
		if err != nil {
			return nil, err
		}
		selected, err := app.limitPQCProposal(ctx, decoder, response.Txs, false)
		if err != nil {
			return nil, err
		}
		response.Txs = selected
		return response, nil
	})
	app.SetProcessProposal(func(ctx sdk.Context, req *abci.RequestProcessProposal) (*abci.ResponseProcessProposal, error) {
		if _, err := app.limitPQCProposal(ctx, decoder, req.Txs, true); err != nil {
			return &abci.ResponseProcessProposal{Status: abci.ResponseProcessProposal_REJECT}, nil
		}
		return process(ctx, req)
	})
}

func (app *App) limitPQCProposal(ctx sdk.Context, decoder sdk.TxDecoder, txs [][]byte, reject bool) ([][]byte, error) {
	params := app.PQCAuthKeeper.GetParams(ctx).Effective(ctx.BlockHeight())
	tracker := pqcauthante.NewPQCVerificationBudgetTracker(app.AccountKeeper)
	var total uint64
	limit := uint64(params.EffectiveMaxPQCVerificationsPerBlock())
	selected := make([][]byte, 0, len(txs))
	for _, raw := range txs {
		tx, err := decoder(raw)
		if err != nil {
			if reject {
				return nil, err
			}
			continue
		}
		inspection, err := tracker.Inspect(ctx, tx, params)
		cost := inspection.Cost.Total()
		if err != nil || cost > uint64(params.EffectiveMaxPQCVerificationsPerTx()) || cost > limit-total {
			if reject {
				return nil, fmt.Errorf("PQC proposal verification budget or structure invalid")
			}
			continue
		}
		total += cost
		tracker.Commit(inspection)
		selected = append(selected, raw)
	}
	return selected, nil
}
