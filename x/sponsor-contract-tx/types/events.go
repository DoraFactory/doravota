package types

// Event types for the sponsor module
const (
	EventTypeSetSponsor            = "set_sponsor"
	EventTypeUpdateSponsor         = "update_sponsor"
	EventTypeDeleteSponsor         = "delete_sponsor"
	EventTypeSponsoredTx           = "sponsored_transaction"
	EventTypeSponsorUsage          = "sponsor_usage_updated"      // New: track usage updates
	EventTypeSponsorInsufficient   = "sponsor_insufficient_funds" // New: sponsor can't pay
	EventTypeUserSelfPay           = "user_self_pay"              // New: user paid themselves
	EventTypeSponsorshipSkipped    = "sponsorship_skipped"        // New: sponsorship skipped due to transaction structure
	EventTypeSponsorshipDisabled   = "sponsorship_disabled"       // New: sponsorship globally disabled
	EventTypeUpdateParams          = "update_params"              // New: governance parameter updates
    EventTypeSponsorWithdrawal     = "sponsor_withdraw_funds"     // New: sponsor funds withdrawal

)

// Event attribute keys
const (
	AttributeKeyCreator              = "creator"
	AttributeKeySponsorAddress       = "sponsor_address"
	AttributeKeyContractAddress      = "contract_address"
	AttributeKeyIsSponsored          = "is_sponsored"
	AttributeKeyUser                 = "user"
	AttributeKeySponsorAmount        = "sponsor_amount"
	AttributeKeyFeeAmount            = "fee_amount"
	AttributeKeyReason               = "reason"
	AttributeKeyTransactionType      = "transaction_type"
	AttributeKeyAuthority            = "authority"
	AttributeKeySponsorshipEnabled   = "sponsorship_enabled"
	AttributeKeyMaxGasPerSponsorship = "max_gas_per_sponsorship"
	AttributeKeyRecipient            = "recipient"
	AttributeKeyUntilHeight          = "until_height"
	AttributeValueTrue               = "true"
)
