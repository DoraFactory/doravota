package app

import (
	"fmt"

	pqcauthante "github.com/DoraFactory/doravota/x/pqcauth/ante"
	pqctypes "github.com/DoraFactory/doravota/x/pqcauth/types"
	abci "github.com/cometbft/cometbft/abci/types"
	"github.com/cosmos/cosmos-sdk/baseapp"
	"github.com/cosmos/cosmos-sdk/client"
	sdk "github.com/cosmos/cosmos-sdk/types"
	authsigning "github.com/cosmos/cosmos-sdk/x/auth/signing"
)

// Keep the current SDK proposal policy and governed gas/byte limits. Only add
// PQC verification budgets; do not restore the old bridge's 100M gas ceiling.
func (app *App) setProposalHandlers(config client.TxConfig) {
	defaults := baseapp.NewDefaultProposalHandler(app.Mempool(), app.BaseApp)
	prepare := defaults.PrepareProposalHandler()
	process := defaults.ProcessProposalHandler()
	decoder := pqcauthante.CanonicalPQCAuthTxDecoder(config.TxDecoder())
	app.SetPrepareProposal(func(ctx sdk.Context, req *abci.RequestPrepareProposal) (response *abci.ResponsePrepareProposal, err error) {
		// BaseApp falls back to the ORIGINAL request on handler error/panic.
		// That can reintroduce malformed or over-budget transactions which our
		// ProcessProposal rejects. An empty proposal is safe and permits progress.
		defer func() {
			if recovered := recover(); recovered != nil {
				ctx.Logger().Error("PQC PrepareProposal panicked; proposing empty block", "panic", recovered)
				response, err = &abci.ResponsePrepareProposal{}, nil
			}
		}()
		filtered := *req
		filtered.Txs = make([][]byte, 0, len(req.Txs))
		for _, raw := range req.Txs {
			if _, decodeErr := decoder(raw); decodeErr == nil {
				filtered.Txs = append(filtered.Txs, raw)
			}
		}
		response, err = prepare(ctx, &filtered)
		if err != nil {
			ctx.Logger().Error("SDK PrepareProposal failed; proposing empty block", "err", err)
			return &abci.ResponsePrepareProposal{}, nil
		}
		selected, err := app.limitPQCProposal(ctx, decoder, response.Txs, false)
		if err != nil {
			ctx.Logger().Error("PQC PrepareProposal failed; proposing empty block", "err", err)
			return &abci.ResponsePrepareProposal{}, nil
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
	// A budget omission must not strand a later sequence from any of its
	// signers. Keep this local to selection: it is not an authentication cache
	// or a consensus rule against unrelated transactions later in the list.
	blocked := make(map[string]bool)
	for _, raw := range txs {
		tx, err := decoder(raw)
		if err != nil {
			if reject {
				return nil, err
			}
			continue
		}
		inspection, err := tracker.Inspect(ctx, tx, params)
		parameterLimited := false
		if err != nil {
			if reject {
				return nil, err
			}
			// A previously valid candidate may exceed newly activated signer or
			// byte limits. Recheck within the immutable wire ceilings to distinguish
			// that case from malformed input/key poisoning. Never commit discoveries
			// from this retry, nor relax ProcessProposal's actual governed limits.
			ceilings := params
			ceilings.MaxPqcSigners = pqctypes.AbsoluteMaxPQCSigners
			ceilings.MaxPqcAuthBytes = pqctypes.AbsoluteMaxPQCAuthBytes
			inspection, err = tracker.Inspect(ctx, tx, ceilings)
			if err != nil {
				continue
			}
			parameterLimited = true
		}
		// Inspect has already checked this interface and metadata. GetSigners
		// derives addresses from messages and includes an independent fee payer;
		// extension entries and the fee granter are not a signer authority.
		signers, err := tx.(authsigning.SigVerifiableTx).GetSigners()
		if err != nil {
			if reject {
				return nil, err
			}
			continue
		}
		dependent := false
		for _, signer := range signers {
			dependent = dependent || blocked[string(signer)]
		}
		cost := inspection.Cost.Total()
		if cost > uint64(params.EffectiveMaxPQCVerificationsPerTx()) || cost > limit-total {
			if reject {
				return nil, fmt.Errorf("PQC proposal verification budget or structure invalid")
			}
			parameterLimited = true
		}
		if parameterLimited || dependent {
			// Propagate across all co-signers: omitting A+B after an omitted A
			// also strands B's next sequence. Unrelated zero-cost work can proceed
			// even when the PQC block budget is exhausted.
			for _, signer := range signers {
				blocked[string(signer)] = true
			}
			continue
		}
		total += cost
		tracker.Commit(inspection)
		selected = append(selected, raw)
	}
	return selected, nil
}
