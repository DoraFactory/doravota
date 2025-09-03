package types

// Event types for the sponsor module
const (
	EventTypeSetSponsor          = "set_sponsor"
	EventTypeUpdateSponsor       = "update_sponsor"
	EventTypeDeleteSponsor       = "delete_sponsor"
	EventTypeSponsoredTx         = "sponsored_transaction"
	EventTypeSponsorUsage        = "sponsor_usage_updated"      // New: track usage updates
	EventTypeSponsorInsufficient = "sponsor_insufficient_funds" // New: sponsor can't pay
	EventTypeUserSelfPay         = "user_self_pay"              // New: user paid themselves
	EventTypeSponsorshipDisabled = "sponsorship_disabled"       // New: sponsorship globally disabled
	EventTypeUpdateParams        = "update_params"              // New: governance parameter updates

	// Read operation events
	EventTypeGetSponsor        = "get_sponsor"
	EventTypeGetUserGrantUsage = "get_user_grant_usage"
	EventTypeGetParams         = "get_params"
	EventTypeQuerySponsors     = "query_sponsors"
	EventTypeCheckSponsorship  = "check_sponsorship"
)

// Event attribute keys
const (
	AttributeKeyCreator         = "creator"
	AttributeKeySponsorAddress  = "sponsor_address"
	AttributeKeyContractAddress = "contract_address"
	AttributeKeyIsSponsored     = "is_sponsored"
	AttributeKeyTxHash          = "tx_hash"
	AttributeKeyUser            = "user"
	AttributeKeySponsorAmount   = "sponsor_amount"
	AttributeKeyGasUsed         = "gas_used"
	AttributeKeyFeeAmount       = "fee_amount"
	AttributeKeyFeeDenom        = "fee_denom"
	AttributeKeyPolicyCheck     = "policy_check"
	AttributeKeyFound           = "found"
	AttributeKeyCount           = "count"
	AttributeKeyQueryType              = "query_type"
	AttributeKeyReason                 = "reason"
	AttributeKeyAuthority              = "authority"
	AttributeKeySponsorshipEnabled     = "sponsorship_enabled"
	AttributeKeyMaxGasPerSponsorship   = "max_gas_per_sponsorship"
)

// Event attribute values
const (
	AttributeValueCategory = ModuleName
	AttributeValueSuccess  = "success"
	AttributeValueFailed   = "failed"
)
