package sponsor

import (
    "bytes"
    "encoding/json"
    "fmt"

    errorsmod "cosmossdk.io/errors"
    wasmtypes "github.com/CosmWasm/wasmd/x/wasm/types"
    sdk "github.com/cosmos/cosmos-sdk/types"
    sdkerrors "github.com/cosmos/cosmos-sdk/types/errors"
    ante "github.com/cosmos/cosmos-sdk/x/auth/ante"
    authkeeper "github.com/cosmos/cosmos-sdk/x/auth/keeper"
    bankkeeper "github.com/cosmos/cosmos-sdk/x/bank/keeper"

    "github.com/DoraFactory/doravota/x/sponsor-contract-tx/types"
)

// Context key for sponsor payment information
type sponsorPaymentKey struct{}

// SponsorPaymentInfo holds all sponsor payment context information
type SponsorPaymentInfo struct {
    ContractAddr sdk.AccAddress
    SponsorAddr  sdk.AccAddress // The actual sponsor address that pays fees
    UserAddr     sdk.AccAddress
    Fee          sdk.Coins
    IsSponsored  bool
    // Two-phase add-ons
    // Digest identifies the ticket to consume on success
    Digest       string
    // DigestCounts holds required method digests and the number of times to consume
    DigestCounts map[string]uint32
}

// ExecTicketGateInfo marks that a transaction has a valid policy ticket in CheckTx.
// Presence of this value in context indicates authorization to bypass standard fee checks in CheckTx.
type execTicketGateKey struct{}

type ExecTicketGateInfo struct {
    Digest       string
    ContractAddr string
    UserAddr     string
}

// computeMethodDigestTx extracts method names (top-level keys) from each MsgExecuteContract
// for the target contract. It enforces exactly one top-level key per message without fully
// unmarshalling nested JSON (only scans top-level structure) and returns the method digest.
// extractMethodKeysTx returns the ordered list of top-level method names for all
// MsgExecuteContract targeting the given contract in this tx. Returns ok=false
// when no such messages exist or any message does not have exactly one top-level key.
func (sctd SponsorContractTxAnteDecorator) extractMethodKeysTx(ctx sdk.Context, contractAddr string, tx sdk.Tx) (keys []string, ok bool) {
    found := false
    // Enforce method name size limit from params to avoid hashing/processing very large keys
    p := sctd.keeper.GetParams(ctx)
    limit := p.MaxMethodNameBytes
    depthLimit := p.MaxMethodJsonDepth
    for _, m := range tx.GetMsgs() {
        if msg, match := m.(*wasmtypes.MsgExecuteContract); match && msg.Contract == contractAddr {
            found = true
            if k, ok := firstTopLevelKey([]byte(msg.Msg), depthLimit); ok {
                if limit != 0 && uint32(len(k)) > limit {
                    return nil, false
                }
                keys = append(keys, k)
            } else {
                return nil, false
            }
        }
    }
    if !found { return nil, false }
    return keys, true
}

// firstTopLevelKey scans only the top-level JSON object and returns the sole key
// when exactly one top-level key is present; otherwise returns ok=false. It does
// not unmarshal nested structures to avoid unnecessary CPU/memory overhead.
func firstTopLevelKey(data []byte, depthLimit uint32) (string, bool) {
    dec := json.NewDecoder(bytes.NewReader(data))
    // Expect '{'
    tok, err := dec.Token()
    if err != nil { return "", false }
    if d, ok := tok.(json.Delim); !ok || d != '{' { return "", false }

    var first string
    keyCount := 0
    // Read key-value pairs at top-level only
    for dec.More() {
        t, err := dec.Token()
        if err != nil { return "", false }
        k, ok := t.(string)
        if !ok { return "", false }
        // skip the corresponding value efficiently
        if err := skipValue(dec, depthLimit); err != nil { return "", false }
        keyCount++
        if keyCount == 1 { first = k }
        if keyCount > 1 { // more than one top-level key
            // consume rest of top-level to leave decoder consistent
            for dec.More() { if err := skipPair(dec, depthLimit); err != nil { break } }
            // read closing '}'
            _, _ = dec.Token()
            return "", false
        }
    }
    // read closing '}'
    _, _ = dec.Token()
    if keyCount != 1 { return "", false }
    return first, true
}

// skipValue skips the next JSON value from decoder
func skipValue(dec *json.Decoder, limit uint32) error { return skipValueDepth(dec, 0, limit) }

func skipValueDepth(dec *json.Decoder, depth int, limit uint32) error {
    if limit == 0 { limit = 20 }
    if depth > int(limit) { return fmt.Errorf("json depth exceeds maximum: %d", limit) }
    t, err := dec.Token()
    if err != nil { return err }
    if d, ok := t.(json.Delim); ok {
        switch d {
        case '{':
            for dec.More() { if err := skipPairDepth(dec, depth+1, limit); err != nil { return err } }
            _, err = dec.Token() // '}'
            return err
        case '[':
            for dec.More() { if err := skipValueDepth(dec, depth+1, limit); err != nil { return err } }
            _, err = dec.Token() // ']'
            return err
        default:
            return nil
        }
    }
    return nil
}

// skipPair skips a single key-value pair in an object
func skipPair(dec *json.Decoder, limit uint32) error { return skipPairDepth(dec, 0, limit) }
func skipPairDepth(dec *json.Decoder, depth int, limit uint32) error {
    if limit == 0 { limit = 20 }
    if depth > int(limit) { return fmt.Errorf("json depth exceeds maximum: %d", limit) }
    t, err := dec.Token() // key
    if err != nil { return err }
    if _, ok := t.(string); !ok { return fmt.Errorf("invalid object key") }
    return skipValueDepth(dec, depth, limit)
}

// SponsorContractTxAnteDecorator handles sponsoring contract transactions
type SponsorContractTxAnteDecorator struct {
	keeper        types.SponsorKeeperInterface
	accountKeeper authkeeper.AccountKeeper
	bankKeeper    bankkeeper.Keeper
	txFeeChecker  ante.TxFeeChecker
}

// sanitizeForLog trims and strips control characters to avoid log amplification/injection.
// It is intended for log/event fields only and does not affect returned error strings.
func sanitizeForLog(s string) string {
    // Replace common control characters with spaces and cap length
    const max = 256
    out := make([]rune, 0, len(s))
    for _, r := range s {
        if r == '\n' || r == '\r' || r == '\t' || r < 32 {
            r = ' '
        }
        out = append(out, r)
        if len(out) >= max {
            break
        }
    }
    return string(out)
}

// NewSponsorContractTxAnteDecorator creates a new ante decorator for sponsored contract transactions (two‑phase: requires ticket)
func NewSponsorContractTxAnteDecorator(k types.SponsorKeeperInterface, ak authkeeper.AccountKeeper, bk bankkeeper.Keeper, txFeeChecker ante.TxFeeChecker) SponsorContractTxAnteDecorator {
	if txFeeChecker == nil {
		txFeeChecker = SponsorTxFeeCheckerWithValidatorMinGasPrices
	}
	return SponsorContractTxAnteDecorator{
		keeper:        k,
		accountKeeper: ak,
		bankKeeper:    bk,
		txFeeChecker:  txFeeChecker,
	}
}

// AnteHandle implements the ante handler for sponsored contract transactions.
// Security and processing flow (audit-friendly summary):
// - Feegrant precedence: if tx sets FeeGranter, sponsorship is skipped and standard fee handling applies.
// - Transaction shape: only single-contract CosmWasm executions are considered; mixed or non-contract messages pass through and may emit a skip event.
// - Contract existence: verified up-front; in CheckTx returns error, in DeliverTx falls back to user payment and emits a skip event.
// - Global toggle: respects module params; when disabled, sponsorship is skipped with informative events/errors.
// - Signer model: single-signer only; FeePayer must match the validated signer to prevent spoofing.
// - Self-pay preference: if user has sufficient balance for the declared fee, sponsorship is skipped (see note below).
// - Two-phase rule: does NOT run policy checks here. ExecuteTx requires a valid ticket; policy checks run only in MsgProbeSponsorship (DeliverTx).
// - Success path: verify grant limit and sponsor balance, then inject SponsorPaymentInfo for the sponsor-aware fee decorator to deduct/reimburse.
// - Self-pay preference: if the user balance covers fees, skip sponsorship and let the user pay.
func (sctd SponsorContractTxAnteDecorator) AnteHandle(
	ctx sdk.Context,
	tx sdk.Tx,
	simulate bool,
	next sdk.AnteHandler,
) (newCtx sdk.Context, err error) {
	// Check for feegrant first - if present, delegate to standard processing
	if feeTx, ok := tx.(sdk.FeeTx); ok {
		feeGranter := feeTx.FeeGranter()
		if feeGranter != nil && !feeGranter.Empty() {
			// Transaction has feegrant set, skip sponsor logic entirely
			// Let standard fee processing handle feegrant behavior
			ctx.Logger().With("module", "sponsor-contract-tx").Info(
				"transaction has feegrant set, skipping sponsor logic",
				"granter", feeGranter.String(),
			)
			return next(ctx, tx, simulate)
		}
	}

    // Global toggle: if sponsorship is disabled, skip immediately before any contract-specific work
    params := sctd.keeper.GetParams(ctx)
    if !params.SponsorshipEnabled {
        if !ctx.IsCheckTx() {
            // Best-effort: if there is a contract execute message, attach its address for observability
            contractForEvent := ""
            for _, m := range tx.GetMsgs() {
                if msg, ok := m.(*wasmtypes.MsgExecuteContract); ok {
                    contractForEvent = msg.Contract
                    break
                }
            }
            ev := sdk.NewEvent(types.EventTypeSponsorshipDisabled,
                sdk.NewAttribute(types.AttributeKeyReason, "global_sponsorship_disabled"),
            )
            if contractForEvent != "" {
                ev = ev.AppendAttributes(sdk.NewAttribute(types.AttributeKeyContractAddress, contractForEvent))
            }
            ctx.EventManager().EmitEvent(ev)
        }
        ctx.Logger().With("module", "sponsor-contract-tx").Info(
            "sponsorship globally disabled, using standard fee processing",
        )
        return next(ctx, tx, simulate)
    }

	// Find and validate contract execution messages
	validation := validateSponsoredTransaction(tx)

	// If no sponsorship should be attempted, pass through with context-aware UX
	if !validation.SuggestSponsor {
		if validation.SkipReason != "" {
			// Emit event only in DeliverTx so it is indexed on-chain
			if !ctx.IsCheckTx() {
				ctx.EventManager().EmitEvent(
					sdk.NewEvent(
						types.EventTypeSponsorshipSkipped,
						sdk.NewAttribute(types.AttributeKeyReason, validation.SkipReason),
					),
				)
			}

			ctx.Logger().With("module", "sponsor-contract-tx").Info(
				"sponsorship skipped",
				"reason", sanitizeForLog(validation.SkipReason),
			)
		}
		return next(ctx, tx, simulate)
	}

    contractAddr := validation.ContractAddress

    // Determine the user address (validated signer / feepayer) once and reuse.
    // If we cannot determine it, most sponsor paths will fall back to standard processing.
    userAddr, userAddrErr := sctd.getUserAddressForSponsorship(tx)

	// Validate contract exists before proceeding (early exit):
	// - In CheckTx: return an error to avoid entering mempool with a non-existent contract.
	// - In DeliverTx: emit a skip event and fall back to standard fee processing.
	if err := sctd.keeper.ValidateContractExists(ctx, contractAddr); err != nil {
		ctx.Logger().With("module", "sponsor-contract-tx").Info(
			"contract not found; skipping sponsorship",
			"contract", contractAddr,
			"error", err.Error(),
		)
		if ctx.IsCheckTx() {
			return ctx, errorsmod.Wrapf(types.ErrContractNotFound, "contract address %s not found", contractAddr)
		}

		// In DeliverTx, fall back to user payment immediately to avoid extra queries
		if feeTx, ok := tx.(sdk.FeeTx); ok {
			if userAddrErr == nil {
				if !ctx.IsCheckTx() {
					ctx.EventManager().EmitEvent(
						sdk.NewEvent(
							types.EventTypeSponsorshipSkipped,
							sdk.NewAttribute(types.AttributeKeyContractAddress, contractAddr),
							sdk.NewAttribute(types.AttributeKeyReason, "contract_not_found"),
						),
					)
				}
				return sctd.handleSponsorshipFallback(ctx, tx, simulate, next, contractAddr, userAddr, "contract_not_found")
			}
			ctx.Logger().With("module", "sponsor-contract-tx").Info(
				"unable to determine user address during contract-not-found fallback",
				"contract", contractAddr,
				"error", userAddrErr,
			)
			if fee := feeTx.GetFee(); fee.IsZero() {
				return next(ctx, tx, simulate)
			}
		}

		return next(ctx, tx, simulate)
	}

	// If contract exsit, check if contract is set as a sponsor
	sponsor, found := sctd.keeper.GetSponsor(ctx, contractAddr)

	// If found and sponsored, proceed with sponsorship logic
	if found && sponsor.IsSponsored {
        // Reuse the determined user address; if unavailable, fall back
        if userAddrErr != nil {
			// If we can't determine a consistent user address, fall back to standard processing
			ctx.Logger().With("module", "sponsor-contract-tx").Info(
				"falling back to standard fee processing due to signer inconsistency",
				"contract", contractAddr,
				"error", userAddrErr.Error(),
			)
			return next(ctx, tx, simulate)
		}

		if userAddr.Empty() {
			return ctx, errorsmod.Wrap(sdkerrors.ErrInvalidRequest, "no signers found in transaction")
		}

        // Enforce per-tx cap on MsgExecuteContract count for sponsored transactions (same contract)
        if params.MaxExecMsgsPerTxForSponsor > 0 {
            execCount := 0
            for _, m := range tx.GetMsgs() {
                if msg, ok := m.(*wasmtypes.MsgExecuteContract); ok && msg.Contract == contractAddr {
                    execCount++
                }
            }
            if uint32(execCount) > params.MaxExecMsgsPerTxForSponsor {
                reason := fmt.Sprintf("too_many_exec_messages:%d>%d", execCount, params.MaxExecMsgsPerTxForSponsor)
                // Emit skip event only in DeliverTx
                if !ctx.IsCheckTx() {
                    ctx.EventManager().EmitEvent(
                        sdk.NewEvent(
                            types.EventTypeSponsorshipSkipped,
                            sdk.NewAttribute(types.AttributeKeyContractAddress, contractAddr),
                            sdk.NewAttribute(types.AttributeKeyReason, reason),
                        ),
                    )
                }
                // Fallback to standard processing with explicit reason
                return sctd.handleSponsorshipFallback(ctx, tx, simulate, next, contractAddr, userAddr, reason)
            }
        }

        // Enforce per-message raw JSON payload size (bytes) before any JSON parsing to prevent CPU amplification.
        // 0 disables this guard.
        if params.MaxPolicyExecMsgBytes > 0 {
            var tooLarge bool
            for _, m := range tx.GetMsgs() {
                if msg, ok := m.(*wasmtypes.MsgExecuteContract); ok && msg.Contract == contractAddr {
                    if uint32(len(msg.Msg)) > params.MaxPolicyExecMsgBytes {
                        tooLarge = true
                        break
                    }
                }
            }
            if tooLarge {
                // Emit skip event only in DeliverTx
                if !ctx.IsCheckTx() {
                    ctx.EventManager().EmitEvent(
                        sdk.NewEvent(
                            types.EventTypeSponsorshipSkipped,
                            sdk.NewAttribute(types.AttributeKeyContractAddress, contractAddr),
                            sdk.NewAttribute(types.AttributeKeyReason, "policy_payload_too_large"),
                        ),
                    )
                }
                // Fallback to standard processing; provide reason for observability
                return sctd.handleSponsorshipFallback(ctx, tx, simulate, next, contractAddr, userAddr, "policy_payload_too_large")
            }
        }

        // Compute digest coverage before deciding self-pay early exit (DeliverTx prefers sponsor when a valid ticket exists)
        haveValidTicket := false
        selectedDigest := ""
        var requiredCounts map[string]uint32
        if !(ctx.IsCheckTx() && !sctd.keeper.HasAnyLiveMethodTicket(ctx, contractAddr, userAddr.String())) {
            if keys, ok := sctd.extractMethodKeysTx(ctx, contractAddr, tx); ok {
                // Count required uses per digest (same method may appear multiple times)
                required := make(map[string]uint32)
                var firstDigest string
                for i, k := range keys {
                    md := sctd.keeper.ComputeMethodDigest(contractAddr, []string{k})
                    required[md]++
                    if i == 0 { firstDigest = md }
                }
                // Validate tickets cover required multiplicity
                now := uint64(ctx.BlockHeight())
                allCovered := true
                for md, cnt := range required {
                    t, ok := sctd.keeper.GetPolicyTicket(ctx, contractAddr, userAddr.String(), md)
                    if !ok || t.Consumed || now > t.ExpiryHeight || t.UsesRemaining < cnt {
                        allCovered = false
                        break
                    }
                }
                if allCovered {
                    haveValidTicket, selectedDigest = true, firstDigest
                    requiredCounts = required
                }
            }
        }

        // Always enforce validator min gas price in CheckTx to prevent low-fee spam.
        if ctx.IsCheckTx() && !simulate {
            checker := sctd.txFeeChecker
            if checker == nil {
                checker = SponsorTxFeeCheckerWithValidatorMinGasPrices
            }
            if _, _, feeErr := checker(ctx, tx); feeErr != nil {
                return ctx, feeErr
            }
        }

        // Basic fee/self-pay check before deciding early exit
        if feeTx, ok := tx.(sdk.FeeTx); ok {
            declaredFee := feeTx.GetFee()
			// 1. Zero fee early exit: Only effective in mempool (CheckTx), does not affect simulate/DeliverTx.
			if declaredFee.IsZero() && ctx.IsCheckTx() && !simulate {
				ctx.Logger().With("module", "sponsor-contract-tx").Info(
					"zero-fee tx; skipping sponsorship checks",
					"contract", contractAddr,
					"user", userAddr.String(),
				)
				return next(ctx, tx, simulate)
			}
			// 2. Non-zero fee and early exit allowed: Only determined when fee>0; both simulate and DeliverTx allow skipping (events are only emitted in DeliverTx)
			if !declaredFee.IsZero() {
				feeCheck := declaredFee
				for _, c := range feeCheck {
					if c.Denom != types.SponsorshipDenom {
						return ctx, errorsmod.Wrapf(sdkerrors.ErrInvalidRequest, "only supports 'peaka' as fee denom; found: %s", c.Denom)
					}
				}

				// Self-pay early exit takes precedence when user can afford the fee (both CheckTx and DeliverTx)
                userBalance := sctd.bankKeeper.SpendableCoins(ctx, userAddr)
                if userBalance.IsAllGTE(declaredFee) {
                    ctx.Logger().With("module", "sponsor-contract-tx").Info(
                        "user can self-pay; skipping sponsorship checks",
                        "contract", contractAddr,
                        "user", userAddr.String(),
                        "user_balance", userBalance.String(),
                        "required_fee", declaredFee.String(),
                    )
                    if !ctx.IsCheckTx() {
                        ctx.EventManager().EmitEvent(
                            sdk.NewEvent(
                                types.EventTypeUserSelfPay,
                                sdk.NewAttribute(types.AttributeKeyContractAddress, contractAddr),
                                sdk.NewAttribute(types.AttributeKeyUser, userAddr.String()),
                                sdk.NewAttribute(types.AttributeKeyReason, "user has sufficient balance to pay fees themselves, skipping sponsor"),
                                sdk.NewAttribute(types.AttributeKeyFeeAmount, declaredFee.String()),
                            ),
                        )
                    }
                    return next(ctx, tx, simulate)
                }

                // When a valid ticket exists, enforce sponsor-specific pre-checks using declared fee (only when user cannot self-pay)
                if haveValidTicket {
                    // Validate user grant limit for this fee
                    if err := sctd.keeper.CheckUserGrantLimit(ctx, userAddr.String(), contractAddr, declaredFee); err != nil {
                        return ctx, errorsmod.Wrapf(err, "user grant limit exceeded")
                    }
                    // Validate sponsor account exists and balance covers declared fee
                    if sponsor.SponsorAddress != "" {
                        if sAddr, err := sdk.AccAddressFromBech32(sponsor.SponsorAddress); err == nil {
                            if sctd.accountKeeper.GetAccount(ctx, sAddr) == nil {
                                return ctx, sdkerrors.ErrUnknownAddress.Wrapf("sponsor address: %s does not exist", sAddr.String())
                            }
                            if spendable := sctd.bankKeeper.SpendableCoins(ctx, sAddr); !spendable.IsAllGTE(declaredFee) {
                                return ctx, errorsmod.Wrapf(sdkerrors.ErrInsufficientFunds, "sponsor insufficient funds: need %s, have %s", declaredFee.String(), spendable.String())
                            }
                        }
                    }
                }

                // Two-phase: further sponsor-specific checks (grant limit, sponsor balance) only apply when a valid ticket is present
            }
        }

        // (sponsor-specific pre-checks executed earlier inside fee block when haveValidTicket)
        // Two-phase flow: inject sponsor info only in DeliverTx; in CheckTx, mark authorization when a valid ticket exists.
        if ctx.IsCheckTx() {
            if haveValidTicket && selectedDigest != "" {
                ctx = ctx.WithValue(execTicketGateKey{}, ExecTicketGateInfo{Digest: selectedDigest, ContractAddr: contractAddr, UserAddr: userAddr.String()})
            }
        } else {
            // Only inject using the pre-selected method digest
            if haveValidTicket && selectedDigest != "" {
                dg := selectedDigest
                tkt, ok := sctd.keeper.GetPolicyTicket(ctx, contractAddr, userAddr.String(), dg)
                if ok && !tkt.Consumed && tkt.UsesRemaining >= 1 && uint64(ctx.BlockHeight()) <= tkt.ExpiryHeight {
                    contractAccAddr, _ := sdk.AccAddressFromBech32(contractAddr)
                    sponsorAccAddr, _ := sdk.AccAddressFromBech32(sponsor.SponsorAddress)
                    fee := sdk.NewCoins()
                    if feeTx, ok := tx.(sdk.FeeTx); ok { fee = feeTx.GetFee() }
                    sInfo := SponsorPaymentInfo{
                        ContractAddr: contractAccAddr,
                        SponsorAddr:  sponsorAccAddr,
                        UserAddr:     userAddr,
                        Fee:          fee,
                        IsSponsored:  true,
                        Digest:       dg,
                        DigestCounts: requiredCounts,
                    }
                    ctx = ctx.WithValue(sponsorPaymentKey{}, sInfo)
                }
            }
        }

        // Two‑phase requires ticket: after (optional) sponsor injection via ticket,
        // continue to next ante without running legacy policy checks here.
        return next(ctx, tx, simulate)
	} else if found && !sponsor.IsSponsored { // If not found or not sponsored, skip sponsorship logic
		// Sponsorship is disabled for this contract
		// Emit an informative skip event for observability (DeliverTx only)
		if !ctx.IsCheckTx() {
			ctx.EventManager().EmitEvent(
				sdk.NewEvent(
					types.EventTypeSponsorshipSkipped,
					sdk.NewAttribute(types.AttributeKeyContractAddress, contractAddr),
					sdk.NewAttribute(types.AttributeKeyReason, "contract_sponsorship_disabled"),
				),
			)
		}

			// If the user cannot afford the fee themselves, return a clearer error
			if feeTx, ok := tx.(sdk.FeeTx); ok {
			declaredFee := feeTx.GetFee()
			if !declaredFee.IsZero() {
                // Align with fee policy using txFeeChecker
                effectiveFee := sctd.getEffectiveFee(ctx, tx)
				if userAddrErr == nil && !userAddr.Empty() {
					userBalance := sctd.bankKeeper.SpendableCoins(ctx, userAddr)
					if !userBalance.IsAllGTE(effectiveFee) {
						// Provide a user-facing reason to explain lack of sponsorship
						return ctx, errorsmod.Wrapf(
							sdkerrors.ErrInsufficientFunds,
							"sponsorship disabled for contract %s; user %s has insufficient balance to pay fees. Required: %s, Available: %s",
							contractAddr,
							userAddr.String(),
							effectiveFee.String(),
							userBalance.String(),
						)
					}
					// If user can self-pay, record a helpful event in DeliverTx
					if !ctx.IsCheckTx() {
						ctx.EventManager().EmitEvent(
							sdk.NewEvent(
								types.EventTypeUserSelfPay,
								sdk.NewAttribute(types.AttributeKeyContractAddress, contractAddr),
								sdk.NewAttribute(types.AttributeKeyUser, userAddr.String()),
								sdk.NewAttribute(types.AttributeKeyReason, "contract_sponsorship_disabled"),
								sdk.NewAttribute(types.AttributeKeyFeeAmount, effectiveFee.String()),
							),
						)
					}
				}
			}
		}

		ctx.Logger().With("module", "sponsor-contract-tx").Info(
			"sponsorship disabled for contract; using standard fee processing",
			"contract", contractAddr,
		)
	}

	return next(ctx, tx, simulate)
}

// TransactionValidationResult holds the result of transaction validation
type TransactionValidationResult struct {
	ContractAddress string // Empty if no sponsorship should be attempted
	SuggestSponsor  bool   // Is there only one contract address?
	SkipReason      string // Reason why sponsorship was skipped (for events)
}

// validateSponsoredTransaction validates that the transaction meets sponsor requirements
// Returns validation result instead of error to allow fallback to user payment
func validateSponsoredTransaction(tx sdk.Tx) *TransactionValidationResult {
	msgs := tx.GetMsgs()
	if len(msgs) == 0 {
		return &TransactionValidationResult{
			ContractAddress: "",
			SuggestSponsor:  false,
			SkipReason:      "",
		}
	}

    // We record a normalized(bech32) contract address only after successful validation.
    // This avoids echoing raw, potentially malicious input into logs or reasons.
    var sponsoredContract string

	// Check messages - for sponsored transactions, only allow MsgExecuteContract to the same sponsored contract
	for _, msg := range msgs {
		msgType := sdk.MsgTypeURL(msg)

		switch execMsg := msg.(type) {
		// contract execution message
        case *wasmtypes.MsgExecuteContract:
            // Normalize incoming address first; if invalid, skip sponsorship without echoing raw input
            if acc, err := sdk.AccAddressFromBech32(execMsg.Contract); err != nil {
                return &TransactionValidationResult{
                    ContractAddress: "",
                    SuggestSponsor:  false,
                    SkipReason:      "invalid_contract_address",
                }
            } else {
                normalized := acc.String()
                if sponsoredContract == "" {
                    // First valid contract message - record normalized address
                    sponsoredContract = normalized
                } else {
                    // Additional contract message - must match first (normalized) address
                    if normalized != sponsoredContract {
                        return &TransactionValidationResult{
                            ContractAddress: "",
                            SuggestSponsor:  false,
                            SkipReason:      "multiple contracts in tx",
                        }
                    }
                }
            }
        default:
			// Found non-contract message firstly in the transaction, pass through(no sponsor needed)
			// If the first transaction is a non-contract transaction, it indicates a normal regular transaction.
			// We do not need to mark the event, just execute it like a regular transaction, and the user will not perceive it.
			if sponsoredContract == "" {
				return &TransactionValidationResult{
					ContractAddress: "",
					SuggestSponsor:  false,
					SkipReason:      "",
				}
			} else {
				// Found non-contract message later in the transaction - skip sponsorship
				return &TransactionValidationResult{
					ContractAddress: "",
					SuggestSponsor:  false,
					SkipReason:      fmt.Sprintf("transaction contains mixed messages: contract + non-contract (%s)", msgType),
				}
			}
		}
	}

	// If we get here, all messages are contract messages for the same contract
	return &TransactionValidationResult{
		ContractAddress: sponsoredContract, // normalized bech32 string
		SuggestSponsor:  true,
		SkipReason:      "",
	}
}

// handleSponsorshipFallback handles the case when sponsorship is denied but user might pay themselves
// It checks user balance and provides clear error messages if they can't afford the fees
func (sctd SponsorContractTxAnteDecorator) handleSponsorshipFallback(
	ctx sdk.Context,
	tx sdk.Tx,
	simulate bool,
	next sdk.AnteHandler,
	contractAddr string,
	userAddr sdk.AccAddress,
	reason string,
) (newCtx sdk.Context, err error) {
	// Get transaction fee to check if user can afford it
	feeTx, ok := tx.(sdk.FeeTx)
	if !ok {
		// If we can't get fee info, just proceed with standard processing
		return next(ctx, tx, simulate)
	}

    // Compute effective/required fee using txFeeChecker for consistent behavior
    declaredFee := feeTx.GetFee()
    if declaredFee.IsZero() {
        // Zero fee transaction, just proceed
        return next(ctx, tx, simulate)
    }
    effectiveFee := sctd.getEffectiveFee(ctx, tx)

	// Check if user has sufficient balance to pay the fee themselves
	userBalance := sctd.bankKeeper.SpendableCoins(ctx, userAddr)
	if !userBalance.IsAllGTE(effectiveFee) {
		// User cannot afford the fee and sponsorship was denied
		// Return a clear error message explaining the situation
		return ctx, errorsmod.Wrapf(
			sdkerrors.ErrInsufficientFunds,
			"sponsorship denied for contract %s (reason: %s) and user %s has insufficient balance to pay fees. Required: %s, Available: %s. User needs either sponsorship approval or sufficient balance to pay transaction fees",
			contractAddr,
			reason,
			userAddr.String(),
			effectiveFee.String(),
			userBalance.String(),
		)
	}

	// User has sufficient balance, proceed with fallback to standard fee processing
	ctx.Logger().With("module", "sponsor-contract-tx").Info(
		"sponsorship denied but user has sufficient balance, falling back to standard fee processing",
		"contract", contractAddr,
		"user", userAddr.String(),
		"reason", sanitizeForLog(reason),
		"user_balance", userBalance.String(),
		"required_fee", effectiveFee.String(),
	)

	// Emit event to notify that sponsorship was attempted but user will pay themselves
	if !ctx.IsCheckTx() {
		ctx.EventManager().EmitEvent(
			sdk.NewEvent(
				types.EventTypeUserSelfPay,
				sdk.NewAttribute(types.AttributeKeyContractAddress, contractAddr),
				sdk.NewAttribute(types.AttributeKeyUser, userAddr.String()),
				sdk.NewAttribute(types.AttributeKeyReason, sanitizeForLog(reason)),
				sdk.NewAttribute(types.AttributeKeyFeeAmount, effectiveFee.String()),
			),
		)
	}

	return next(ctx, tx, simulate)
}

// getUserAddressForSponsorship determines the appropriate user address for sponsorship.
// Invariants enforced for auditability:
// - All messages must have signers and the signer sets must be identical across messages.
// - Multi-signer transactions are rejected for sponsorship.
// - If a FeePayer is provided by the tx, it MUST equal the validated signer to prevent spoofing.
func (sctd SponsorContractTxAnteDecorator) getUserAddressForSponsorship(tx sdk.Tx) (sdk.AccAddress, error) {
	msgs := tx.GetMsgs()
	if len(msgs) == 0 {
		return sdk.AccAddress{}, errorsmod.Wrap(sdkerrors.ErrInvalidRequest, "transaction has no messages")
	}

	// First, validate all message signers are consistent for security
	var validatedSigner sdk.AccAddress
	var allSigners []sdk.AccAddress

	for i, msg := range msgs {
		msgSigners := msg.GetSigners()
		if len(msgSigners) == 0 {
			return sdk.AccAddress{}, errorsmod.Wrapf(sdkerrors.ErrInvalidRequest, "message at index %d has no signers", i)
		}

		// For the first message, record all its signers
		if i == 0 {
			validatedSigner = msgSigners[0]
			allSigners = append(allSigners, msgSigners...)
		} else {
			// For subsequent messages, ensure signers match the first message
			if len(msgSigners) != len(allSigners) {
				return sdk.AccAddress{}, errorsmod.Wrap(sdkerrors.ErrUnauthorized,
					"inconsistent signer count across messages - sponsored transactions require consistent signers")
			}

			for j, signer := range msgSigners {
				if !signer.Equals(allSigners[j]) {
					return sdk.AccAddress{}, errorsmod.Wrapf(sdkerrors.ErrUnauthorized,
						"signer mismatch at message %d, position %d - sponsored transactions require consistent signers", i, j)
				}
			}
		}
	}

	// Reject multi-signer transactions for security reasons
	if len(allSigners) > 1 {
		return sdk.AccAddress{}, errorsmod.Wrap(sdkerrors.ErrUnauthorized,
			"multi-signer transactions are not supported for sponsorship - please use single signer transactions or separate transactions")
	}

	// Now check FeePayer, but it must be consistent with validated signers for security
	if feeTx, ok := tx.(sdk.FeeTx); ok {
		feePayer := feeTx.FeePayer()
		if !feePayer.Empty() {
			// Security check: FeePayer must match the validated signer to prevent abuse
			// This prevents users from setting arbitrary FeePayer addresses
			if !feePayer.Equals(validatedSigner) {
				return sdk.AccAddress{}, errorsmod.Wrapf(sdkerrors.ErrUnauthorized,
					"FeePayer %s does not match message signer %s - potential security risk in sponsored transactions",
					feePayer.String(), validatedSigner.String())
			}
			return feePayer, nil
		}
	}

	return validatedSigner, nil
}

// getEffectiveFee computes the effective/required fee for a tx using the configured
// txFeeChecker when available; falls back to the declared fee. This keeps self-pay
// checks, grant-limit checks, and sponsor balance checks consistent with fee policy.
func (sctd SponsorContractTxAnteDecorator) getEffectiveFee(ctx sdk.Context, tx sdk.Tx) sdk.Coins {
    feeTx, ok := tx.(sdk.FeeTx)
    if !ok {
        return sdk.Coins{}
    }
    declaredFee := feeTx.GetFee()
    if sctd.txFeeChecker != nil {
        if eff, _, err := sctd.txFeeChecker(ctx, tx); err == nil {
            return eff
        }
    }
    return declaredFee
}
