package types

// Event types for the sponsor module
const (
	EventTypeSetSponsor    = "set_sponsor"
	EventTypeUpdateSponsor = "update_sponsor"
	EventTypeDeleteSponsor = "delete_sponsor"
	EventTypeSponsoredTx   = "sponsored_transaction"
)

// Event attribute keys
const (
	AttributeKeyCreator         = "creator"
	AttributeKeyContractAddress = "contract_address"
	AttributeKeyIsSponsored     = "is_sponsored"
	AttributeKeyTxHash          = "tx_hash"
	AttributeKeyUser            = "user"
	AttributeKeySponsorAmount   = "sponsor_amount"
	AttributeKeyGasUsed         = "gas_used"
	AttributeKeyFeeAmount       = "fee_amount"
	AttributeKeyFeeDenom        = "fee_denom"
	AttributeKeyPolicyCheck     = "policy_check"
)

// Event attribute values
const (
	AttributeValueCategory = ModuleName
	AttributeValueSuccess  = "success"
	AttributeValueFailed   = "failed"
)
