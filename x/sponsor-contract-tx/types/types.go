package types

import (
	"fmt"

	errorsmod "cosmossdk.io/errors"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/cosmos/cosmos-sdk/types/address"
	sdkerrors "github.com/cosmos/cosmos-sdk/types/errors"
)

const (
	// Message types
	TypeMsgSetSponsor    = "set_sponsor"
	TypeMsgUpdateSponsor = "update_sponsor"
	TypeMsgDeleteSponsor = "delete_sponsor"
)

// BaseSponsorMsg defines common fields and methods for sponsor messages
type BaseSponsorMsg struct {
	Creator         string
	ContractAddress string
}

// ValidateBasicFields performs common validation for sponsor messages
func (b BaseSponsorMsg) ValidateBasicFields() error {
	// Validate creator address
	if err := ValidateCanonicalAddress(b.Creator); err != nil {
		return errorsmod.Wrapf(sdkerrors.ErrInvalidAddress, "invalid creator address: %s", b.Creator)
	}

	// Validate contract address format
	if err := ValidateContractAddress(b.ContractAddress); err != nil {
		return err
	}

	return nil
}

// NormalizeMaxGrantPerUser normalizes and validates MaxGrantPerUser coins
// It merges duplicate denominations, sorts, and validates the result
func NormalizeMaxGrantPerUser(maxGrantPerUser []*sdk.Coin) ([]*sdk.Coin, error) {
	if len(maxGrantPerUser) == 0 {
		return []*sdk.Coin{}, nil
	}

	// Convert to sdk.Coins for normalization
	coins := make(sdk.Coins, len(maxGrantPerUser))
	for i, coin := range maxGrantPerUser {
		if coin == nil {
			return nil, errorsmod.Wrap(sdkerrors.ErrInvalidCoins, "coin cannot be nil")
		}
		coins[i] = *coin
	}

	// First validate and manually merge duplicates
	denominationTotals := make(map[string]sdk.Int)

	for _, coin := range coins {
		if coin.Denom != SponsorshipDenom {
			return nil, errorsmod.Wrap(sdkerrors.ErrInvalidCoins, fmt.Sprintf("invalid denomination '%s': only 'peaka' is supported", coin.Denom))
		}
		if !coin.Amount.IsPositive() {
			return nil, errorsmod.Wrap(sdkerrors.ErrInvalidCoins, "coin amount must be positive")
		}

		// Accumulate amounts for same denomination
		if existing, found := denominationTotals[coin.Denom]; found {
			total, err := existing.SafeAdd(coin.Amount)
			if err != nil {
				return nil, errorsmod.Wrap(
					sdkerrors.ErrInvalidCoins,
					"max_grant_per_user amount overflow",
				)
			}
			denominationTotals[coin.Denom] = total
		} else {
			denominationTotals[coin.Denom] = coin.Amount
		}
	}

	// Convert back to coins slice with merged amounts
	mergedCoins := make(sdk.Coins, 0, len(denominationTotals))
	for denom, amount := range denominationTotals {
		mergedCoins = append(mergedCoins, sdk.NewCoin(denom, amount))
	}

	// Sort the final result
	coins = mergedCoins.Sort()
	if !coins.IsValid() {
		return nil, errorsmod.Wrap(sdkerrors.ErrInvalidCoins, "invalid coins after normalization")
	}

	// Convert back to []*sdk.Coin
	result := make([]*sdk.Coin, len(coins))
	for i, coin := range coins {
		coinCopy := coin // Create a copy to avoid pointer issues
		result[i] = &coinCopy
	}

	return result, nil
}

// ValidateMaxGrantPerUser validates that MaxGrantPerUser is required and only contains peaka denomination
func ValidateMaxGrantPerUser(maxGrantPerUser []*sdk.Coin) error {
	normalized, err := NormalizeMaxGrantPerUser(maxGrantPerUser)
	if err != nil {
		return err
	}

	if len(normalized) == 0 {
		return errorsmod.Wrap(sdkerrors.ErrInvalidRequest, "max_grant_per_user is required and cannot be empty")
	}

	return nil
}

// ValidateMaxGrantPerUserConditional validates MaxGrantPerUser based on sponsorship status
// If isSponsored is true, MaxGrantPerUser is required
// If isSponsored is false, MaxGrantPerUser can be empty
func ValidateMaxGrantPerUserConditional(maxGrantPerUser []*sdk.Coin, isSponsored bool) error {
	if !isSponsored {
		// When sponsorship is disabled, max_grant_per_user can be empty
		// But if provided, it should still be valid
		if len(maxGrantPerUser) == 0 {
			return nil // Allow empty when sponsorship is disabled
		}
		// If provided when sponsorship is disabled, validate the format but don't require it
		return validateMaxGrantPerUserFormat(maxGrantPerUser)
	}

	// When sponsorship is enabled, require and validate max_grant_per_user
	return ValidateMaxGrantPerUser(maxGrantPerUser)
}

// validateMaxGrantPerUserFormat validates only the format of MaxGrantPerUser without requiring it to be non-empty
func validateMaxGrantPerUserFormat(maxGrantPerUser []*sdk.Coin) error {
	for _, coin := range maxGrantPerUser {
		if coin == nil {
			return errorsmod.Wrap(sdkerrors.ErrInvalidCoins, "coin cannot be nil")
		}

		if coin.Denom != SponsorshipDenom {
			return errorsmod.Wrap(sdkerrors.ErrInvalidCoins, fmt.Sprintf("invalid denomination '%s': only 'peaka' is supported", coin.Denom))
		}

		if !coin.Amount.IsPositive() {
			return errorsmod.Wrap(sdkerrors.ErrInvalidCoins, "coin amount must be positive")
		}
	}

	return nil
}

// GetCommonSigners returns the signers for sponsor messages
func (b BaseSponsorMsg) GetCommonSigners() []sdk.AccAddress {
	signer, err := sdk.AccAddressFromBech32(b.Creator)
	if err != nil {
		panic(err)
	}
	return []sdk.AccAddress{signer}
}

// GetCommonRoute returns the message route
func (b BaseSponsorMsg) GetCommonRoute() string {
	return RouterKey
}

// MsgProbeSponsorship implementations removed: probing path disabled.

// === Message implementations for MsgIssuePolicyTicket ===

// Route returns the message route
func (msg MsgIssuePolicyTicket) Route() string { return RouterKey }

// Type returns the message type
func (msg MsgIssuePolicyTicket) Type() string { return "issue_policy_ticket" }

// GetSigners returns the signers
func (msg MsgIssuePolicyTicket) GetSigners() []sdk.AccAddress {
	signer, err := sdk.AccAddressFromBech32(msg.Creator)
	if err != nil {
		panic(err)
	}
	return []sdk.AccAddress{signer}
}

// MsgIssueMethodPolicyTicket removed: method-only issuance is handled by MsgIssuePolicyTicket.

// GetSignBytes returns the sign bytes
func (msg MsgIssuePolicyTicket) GetSignBytes() []byte {
	bz := ModuleCdc.MustMarshalJSON(&msg)
	return sdk.MustSortJSON(bz)
}

// ValidateBasic performs basic validation
func (msg MsgIssuePolicyTicket) ValidateBasic() error {
	if err := ValidateCanonicalAddress(msg.Creator); err != nil {
		return errorsmod.Wrapf(sdkerrors.ErrInvalidAddress, "invalid creator address: %s", msg.Creator)
	}
	if err := ValidateContractAddress(msg.ContractAddress); err != nil {
		return err
	}
	if err := ValidateCanonicalAddress(msg.UserAddress); err != nil {
		return errorsmod.Wrapf(sdkerrors.ErrInvalidAddress, "invalid user address: %s", msg.UserAddress)
	}
	if msg.Method == "" {
		return errorsmod.Wrap(sdkerrors.ErrInvalidRequest, "method is required")
	}
	return nil
}

// === Message implementations for MsgRevokePolicyTicket ===

// Route returns the message route
func (msg MsgRevokePolicyTicket) Route() string { return RouterKey }

// Type returns the message type
func (msg MsgRevokePolicyTicket) Type() string { return "revoke_policy_ticket" }

// GetSigners returns the signers
func (msg MsgRevokePolicyTicket) GetSigners() []sdk.AccAddress {
	signer, err := sdk.AccAddressFromBech32(msg.Creator)
	if err != nil {
		panic(err)
	}
	return []sdk.AccAddress{signer}
}

// GetSignBytes returns the sign bytes
func (msg MsgRevokePolicyTicket) GetSignBytes() []byte {
	bz := ModuleCdc.MustMarshalJSON(&msg)
	return sdk.MustSortJSON(bz)
}

// ValidateBasic performs basic validation
func (msg MsgRevokePolicyTicket) ValidateBasic() error {
	if err := ValidateCanonicalAddress(msg.Creator); err != nil {
		return errorsmod.Wrapf(sdkerrors.ErrInvalidAddress, "invalid creator address: %s", msg.Creator)
	}
	if err := ValidateContractAddress(msg.ContractAddress); err != nil {
		return err
	}
	if err := ValidateCanonicalAddress(msg.UserAddress); err != nil {
		return errorsmod.Wrapf(sdkerrors.ErrInvalidAddress, "invalid user address: %s", msg.UserAddress)
	}
	if msg.Method == "" {
		return errorsmod.Wrap(sdkerrors.ErrInvalidRequest, "method is required")
	}
	return nil
}

// === User Grant Usage Structures ===

// NewUserGrantUsage creates a new UserGrantUsage instance
func NewUserGrantUsage(userAddr, contractAddr string) UserGrantUsage {
	return UserGrantUsage{
		UserAddress:     userAddr,
		ContractAddress: contractAddr,
		TotalGrantUsed:  []*sdk.Coin{},
		LastUsedTime:    0,
	}
}

// NewMsgSetSponsor creates a new MsgSetSponsor instance
func NewMsgSetSponsor(creator, contractAddress string, isSponsored bool, maxGrantPerUser sdk.Coins) *MsgSetSponsor {
	// Convert sdk.Coins to protobuf coins
	pbCoins := make([]*sdk.Coin, len(maxGrantPerUser))
	for i, coin := range maxGrantPerUser {
		newCoin := sdk.Coin{
			Denom:  coin.Denom,
			Amount: coin.Amount,
		}
		pbCoins[i] = &newCoin
	}

	return &MsgSetSponsor{
		Creator:         creator,
		ContractAddress: contractAddress,
		IsSponsored:     isSponsored,
		MaxGrantPerUser: pbCoins,
	}
}

// Route returns the message route
func (msg MsgSetSponsor) Route() string {
	base := BaseSponsorMsg{Creator: msg.Creator, ContractAddress: msg.ContractAddress}
	return base.GetCommonRoute()
}

// Type returns the message type
func (msg MsgSetSponsor) Type() string {
	return "set_sponsor"
}

// GetSigners returns the signers
func (msg MsgSetSponsor) GetSigners() []sdk.AccAddress {
	base := BaseSponsorMsg{Creator: msg.Creator, ContractAddress: msg.ContractAddress}
	return base.GetCommonSigners()
}

// GetSignBytes returns the sign bytes
func (msg MsgSetSponsor) GetSignBytes() []byte {
	bz := ModuleCdc.MustMarshalJSON(&msg)
	return sdk.MustSortJSON(bz)
}

// ValidateBasic performs basic validation
func (msg MsgSetSponsor) ValidateBasic() error {
	base := BaseSponsorMsg{Creator: msg.Creator, ContractAddress: msg.ContractAddress}
	if err := base.ValidateBasicFields(); err != nil {
		return err
	}

	// Validate optional ticket issuer address when provided
	if msg.TicketIssuerAddress != "" {
		if err := ValidateCanonicalAddress(msg.TicketIssuerAddress); err != nil {
			return errorsmod.Wrapf(sdkerrors.ErrInvalidAddress, "invalid ticket issuer address: %s", msg.TicketIssuerAddress)
		}
	}

	// Validate MaxGrantPerUser field based on sponsorship status
	// For SetSponsor, we require max_grant_per_user when is_sponsored=true
	// and allow empty when is_sponsored=false (still validating format if provided).
	if err := ValidateMaxGrantPerUserConditional(msg.MaxGrantPerUser, msg.IsSponsored); err != nil {
		return err
	}

	return nil
}

// TypeURL returns the TypeURL for this message
func (msg *MsgSetSponsor) XXX_MessageName() string {
	return "doravota.sponsor.v1.MsgSetSponsor"
}

// === Message implementations for MsgUpdateSponsor ===

// NewMsgUpdateSponsor creates a new MsgUpdateSponsor instance
func NewMsgUpdateSponsor(creator, contractAddress string, isSponsored bool, maxGrantPerUser sdk.Coins) *MsgUpdateSponsor {
	// Convert sdk.Coins to protobuf coins
	pbCoins := make([]*sdk.Coin, len(maxGrantPerUser))
	for i, coin := range maxGrantPerUser {
		newCoin := sdk.Coin{
			Denom:  coin.Denom,
			Amount: coin.Amount,
		}
		pbCoins[i] = &newCoin
	}

	return &MsgUpdateSponsor{
		Creator:         creator,
		ContractAddress: contractAddress,
		IsSponsored:     isSponsored,
		MaxGrantPerUser: pbCoins,
	}
}

// Route returns the message route
func (msg MsgUpdateSponsor) Route() string {
	base := BaseSponsorMsg{Creator: msg.Creator, ContractAddress: msg.ContractAddress}
	return base.GetCommonRoute()
}

// Type returns the message type
func (msg MsgUpdateSponsor) Type() string {
	return "update_sponsor"
}

// GetSigners returns the signers
func (msg MsgUpdateSponsor) GetSigners() []sdk.AccAddress {
	base := BaseSponsorMsg{Creator: msg.Creator, ContractAddress: msg.ContractAddress}
	return base.GetCommonSigners()
}

// GetSignBytes returns the sign bytes
func (msg MsgUpdateSponsor) GetSignBytes() []byte {
	bz := ModuleCdc.MustMarshalJSON(&msg)
	return sdk.MustSortJSON(bz)
}

// ValidateBasic performs basic validation
func (msg MsgUpdateSponsor) ValidateBasic() error {
	base := BaseSponsorMsg{Creator: msg.Creator, ContractAddress: msg.ContractAddress}
	if err := base.ValidateBasicFields(); err != nil {
		return err
	}

	// Validate optional ticket issuer address when provided
	if msg.TicketIssuerAddress != "" {
		if err := ValidateCanonicalAddress(msg.TicketIssuerAddress); err != nil {
			return errorsmod.Wrapf(sdkerrors.ErrInvalidAddress, "invalid ticket issuer address: %s", msg.TicketIssuerAddress)
		}
	}

	// Validate MaxGrantPerUser only when explicitly provided to allow partial updates
	if len(msg.MaxGrantPerUser) > 0 {
		if err := ValidateMaxGrantPerUserConditional(msg.MaxGrantPerUser, msg.IsSponsored); err != nil {
			return err
		}
	}

	return nil
}

// TypeURL returns the TypeURL for this message
func (msg *MsgUpdateSponsor) XXX_MessageName() string {
	return "doravota.sponsor.v1.MsgUpdateSponsor"
}

// === Message implementations for MsgDeleteSponsor ===

// NewMsgDeleteSponsor creates a new MsgDeleteSponsor instance
func NewMsgDeleteSponsor(creator, contractAddress string) *MsgDeleteSponsor {
	return &MsgDeleteSponsor{
		Creator:         creator,
		ContractAddress: contractAddress,
	}
}

// Route returns the message route
func (msg MsgDeleteSponsor) Route() string {
	base := BaseSponsorMsg{Creator: msg.Creator, ContractAddress: msg.ContractAddress}
	return base.GetCommonRoute()
}

// Type returns the message type
func (msg MsgDeleteSponsor) Type() string {
	return "delete_sponsor"
}

// GetSigners returns the signers
func (msg MsgDeleteSponsor) GetSigners() []sdk.AccAddress {
	base := BaseSponsorMsg{Creator: msg.Creator, ContractAddress: msg.ContractAddress}
	return base.GetCommonSigners()
}

// GetSignBytes returns the sign bytes
func (msg MsgDeleteSponsor) GetSignBytes() []byte {
	bz := ModuleCdc.MustMarshalJSON(&msg)
	return sdk.MustSortJSON(bz)
}

// ValidateBasic performs basic validation
func (msg MsgDeleteSponsor) ValidateBasic() error {
	base := BaseSponsorMsg{Creator: msg.Creator, ContractAddress: msg.ContractAddress}
	return base.ValidateBasicFields()
}

// TypeURL returns the TypeURL for this message
func (msg *MsgDeleteSponsor) XXX_MessageName() string {
	return "doravota.sponsor.v1.MsgDeleteSponsor"
}

// === Genesis State ===

// NewGenesisState creates a new GenesisState instance
func NewGenesisState(sponsors []*ContractSponsor, userGrantUsages []*UserGrantUsage) *GenesisState {
	return &GenesisState{
		Sponsors:        sponsors,
		UserGrantUsages: userGrantUsages,
	}
}

// DefaultGenesisState returns a default genesis state
func DefaultGenesisState() *GenesisState {
	params := DefaultParams()
	return &GenesisState{
		Sponsors:        []*ContractSponsor{},
		Params:          &params,
		UserGrantUsages: []*UserGrantUsage{},
		PolicyTickets:   []*PolicyTicket{},
	}
}

// ValidateGenesis validates the genesis state
func ValidateGenesis(data GenesisState) error {
	// Validate sponsors: duplicates + deep validation
	sponsorsByContract := make(map[string]*ContractSponsor)
	for _, sponsor := range data.Sponsors {
		if sponsor == nil {
			return errorsmod.Wrap(sdkerrors.ErrInvalidRequest, "sponsor cannot be nil")
		}
		if err := ValidateContractSponsorState(*sponsor, false); err != nil {
			return err
		}

		// Contract address validation (non-empty + bech32)
		if err := ValidateContractAddress(sponsor.ContractAddress); err != nil {
			return err
		}
		if _, exists := sponsorsByContract[sponsor.ContractAddress]; exists {
			return errorsmod.Wrapf(sdkerrors.ErrInvalidRequest, "duplicate sponsor contract address: %s", sponsor.ContractAddress)
		}
		sponsorsByContract[sponsor.ContractAddress] = sponsor

		// Creator address validation
		if sponsor.CreatorAddress == "" {
			return errorsmod.Wrap(sdkerrors.ErrInvalidAddress, "sponsor creator address cannot be empty")
		}
		if err := ValidateCanonicalAddress(sponsor.CreatorAddress); err != nil {
			return errorsmod.Wrapf(sdkerrors.ErrInvalidAddress, "invalid sponsor creator address: %s", sponsor.CreatorAddress)
		}

		// Sponsor address validation (must be valid bech32 and derived from contract address)
		if sponsor.SponsorAddress == "" {
			return errorsmod.Wrap(sdkerrors.ErrInvalidAddress, "sponsor address cannot be empty")
		}
		if err := ValidateCanonicalAddress(sponsor.SponsorAddress); err != nil {
			return errorsmod.Wrapf(sdkerrors.ErrInvalidAddress, "invalid sponsor address: %s", sponsor.SponsorAddress)
		}
		sponsorAcc, _ := sdk.AccAddressFromBech32(sponsor.SponsorAddress)
		contractAcc, err := sdk.AccAddressFromBech32(sponsor.ContractAddress)
		if err != nil {
			return errorsmod.Wrapf(sdkerrors.ErrInvalidAddress, "invalid contract address: %s", sponsor.ContractAddress)
		}
		expectedSponsor := sdk.AccAddress(address.Derive(contractAcc, []byte("sponsor")))
		if !expectedSponsor.Equals(sponsorAcc) {
			return errorsmod.Wrapf(
				sdkerrors.ErrInvalidAddress,
				"sponsor address must be derived from contract address; expected %s, got %s",
				expectedSponsor.String(), sponsor.SponsorAddress,
			)
		}

		// Optional ticket issuer address validation when provided
		if sponsor.TicketIssuerAddress != "" {
			if err := ValidateCanonicalAddress(sponsor.TicketIssuerAddress); err != nil {
				return errorsmod.Wrapf(sdkerrors.ErrInvalidAddress, "invalid ticket issuer address: %s", sponsor.TicketIssuerAddress)
			}
		}

		// Temporal consistency
		if sponsor.CreatedAt < 0 {
			return errorsmod.Wrap(sdkerrors.ErrInvalidRequest, "created_at cannot be negative")
		}
		if sponsor.UpdatedAt < 0 {
			return errorsmod.Wrap(sdkerrors.ErrInvalidRequest, "updated_at cannot be negative")
		}
		if sponsor.CreatedAt > sponsor.UpdatedAt {
			return errorsmod.Wrap(sdkerrors.ErrInvalidRequest, "created_at must be <= updated_at")
		}

		// MaxGrantPerUser validation
		if err := ValidateMaxGrantPerUserConditional(sponsor.MaxGrantPerUser, sponsor.IsSponsored); err != nil {
			return err
		}
	}

	// Validate user grant usages
	// First pass: light validation + duplicate detection prioritized
	seenUsage := make(map[string]struct{})
	for _, usage := range data.UserGrantUsages {
		if usage == nil {
			return errorsmod.Wrap(sdkerrors.ErrInvalidRequest, "user grant usage cannot be nil")
		}
		if err := ValidateUserGrantUsageState(*usage, false); err != nil {
			return err
		}
		if usage.UserAddress == "" {
			return errorsmod.Wrap(sdkerrors.ErrInvalidRequest, "user grant usage user address cannot be empty")
		}
		if err := ValidateCanonicalAddress(usage.UserAddress); err != nil {
			return errorsmod.Wrapf(sdkerrors.ErrInvalidAddress, "invalid user grant usage user address: %s", usage.UserAddress)
		}
		if err := ValidateContractAddress(usage.ContractAddress); err != nil {
			return err
		}
		key := usage.UserAddress + "/" + usage.ContractAddress
		if _, found := seenUsage[key]; found {
			return errorsmod.Wrapf(sdkerrors.ErrInvalidRequest, "duplicate user grant usage for user %s and contract %s", usage.UserAddress, usage.ContractAddress)
		}
		seenUsage[key] = struct{}{}
	}

	// Second pass: deep validation and semantic checks
	for _, usage := range data.UserGrantUsages {
		// Time sanity
		if usage.LastUsedTime < 0 {
			return errorsmod.Wrap(sdkerrors.ErrInvalidRequest, "last_used_time cannot be negative")
		}

		// Validate TotalGrantUsed
		used := sdk.Coins{}
		for _, c := range usage.TotalGrantUsed {
			if c == nil {
				return errorsmod.Wrap(sdkerrors.ErrInvalidCoins, "user grant usage coin cannot be nil")
			}
			if c.Denom != SponsorshipDenom {
				return errorsmod.Wrapf(sdkerrors.ErrInvalidCoins, "invalid denomination '%s': only 'peaka' is supported", c.Denom)
			}
			if c.Amount.IsNegative() {
				return errorsmod.Wrap(sdkerrors.ErrInvalidCoins, "user grant usage amount cannot be negative")
			}
			if len(used) == 0 {
				if !c.IsZero() {
					used = sdk.NewCoins(*c)
				}
				continue
			}
			total, err := used[0].Amount.SafeAdd(c.Amount)
			if err != nil {
				return errorsmod.Wrap(sdkerrors.ErrInvalidCoins, "user grant usage amount overflow")
			}
			used[0] = sdk.NewCoin(SponsorshipDenom, total)
		}
		if !used.IsValid() {
			return errorsmod.Wrap(sdkerrors.ErrInvalidCoins, "invalid user grant usage coins")
		}

		// Usage is cumulative accounting for one Sponsor generation. It may be
		// greater than the Sponsor's current max_grant_per_user when an admin
		// lowers the limit after fees have already been sponsored. New charges
		// enforce the current limit; genesis validation must preserve the
		// historical total so exported state can always be imported again.
		sponsor, ok := sponsorsByContract[usage.ContractAddress]
		if !ok {
			if usage.Generation == 0 {
				return errorsmod.Wrapf(sdkerrors.ErrInvalidRequest, "user grant usage references unknown sponsor contract: %s", usage.ContractAddress)
			}
			continue
		}
		sponsorGeneration := sponsor.Generation
		if sponsorGeneration == 0 {
			sponsorGeneration = 1
		}
		usageGeneration := usage.Generation
		if usageGeneration == 0 {
			usageGeneration = sponsorGeneration
		}
		if usageGeneration > sponsorGeneration {
			return errorsmod.Wrapf(
				sdkerrors.ErrInvalidRequest,
				"user grant usage generation %d exceeds sponsor generation %d for contract %s",
				usageGeneration,
				sponsorGeneration,
				usage.ContractAddress,
			)
		}
		if usageGeneration < sponsorGeneration {
			continue
		}
	}

	// Validate policy tickets: basic fields + duplicate detection on (contract,user,digest)
	// Determine method length limit (use params if provided, else defaults)
	methodLimit := DefaultMaxMethodNameBytes
	if data.Params != nil {
		methodLimit = data.Params.EffectiveMaxMethodBytes()
	}
	seenTickets := make(map[string]struct{})
	for _, t := range data.PolicyTickets {
		if t == nil {
			return errorsmod.Wrap(sdkerrors.ErrInvalidRequest, "policy ticket cannot be nil")
		}
		if err := ValidatePolicyTicketState(*t, methodLimit, false); err != nil {
			return err
		}
		// Basic field checks (keep in sync with InitGenesis defensive checks)
		if err := ValidateContractAddress(t.ContractAddress); err != nil {
			return err
		}
		if err := ValidateCanonicalAddress(t.UserAddress); err != nil {
			return errorsmod.Wrapf(sdkerrors.ErrInvalidAddress, "invalid policy ticket user address: %s", t.UserAddress)
		}
		if t.Digest == "" {
			return errorsmod.Wrap(sdkerrors.ErrInvalidRequest, "policy ticket digest cannot be empty")
		}
		// Optional method display length check
		if t.Method != "" && uint32(len(t.Method)) > methodLimit {
			return errorsmod.Wrap(sdkerrors.ErrInvalidRequest, "policy ticket method too long")
		}
		if sponsor, found := sponsorsByContract[t.ContractAddress]; found {
			sponsorGeneration := sponsor.Generation
			if sponsorGeneration == 0 {
				sponsorGeneration = 1
			}
			ticketGeneration := t.Generation
			if ticketGeneration == 0 {
				ticketGeneration = sponsorGeneration
			}
			if ticketGeneration > sponsorGeneration {
				return errorsmod.Wrapf(
					sdkerrors.ErrInvalidRequest,
					"policy ticket generation %d exceeds sponsor generation %d for contract %s",
					ticketGeneration,
					sponsorGeneration,
					t.ContractAddress,
				)
			}
		}
		// Duplicate detection
		key := t.ContractAddress + "/" + t.UserAddress + "/" + t.Digest
		if _, exists := seenTickets[key]; exists {
			return errorsmod.Wrapf(sdkerrors.ErrInvalidRequest, "duplicate policy ticket for contract %s user %s digest %s", t.ContractAddress, t.UserAddress, t.Digest)
		}
		seenTickets[key] = struct{}{}
	}

	// Validate parameters
	if data.Params != nil {
		if err := data.Params.Validate(); err != nil {
			return err
		}
	}

	return nil
}

// === Parameters ===

// DefaultParams returns default parameters
func DefaultParams() Params {
	return Params{
		SponsorshipEnabled:          true,
		PolicyTicketTtlBlocks:       30,
		MaxExecMsgsPerTxForSponsor:  DefaultMaxExecMsgsPerTxForSponsor,
		MaxPolicyExecMsgBytes:       DefaultMaxPolicyExecMsgBytes,
		MaxMethodTicketUsesPerIssue: 50,
		TicketGcPerBlock:            200,
		MaxMethodNameBytes:          DefaultMaxMethodNameBytes,
		MaxMethodJsonDepth:          20,
	}
}

// Validate validates the parameters
func (p Params) Validate() error {
	if p.PolicyTicketTtlBlocks == 0 {
		return errorsmod.Wrap(ErrInvalidParams, "policy ticket TTL must be greater than 0")
	}
	if p.PolicyTicketTtlBlocks > 1000 {
		return errorsmod.Wrap(ErrInvalidParams, "policy ticket TTL exceeds maximum (1000)")
	}
	if p.MaxExecMsgsPerTxForSponsor == 0 || p.MaxExecMsgsPerTxForSponsor > MaxExecMsgsPerTxForSponsor {
		return errorsmod.Wrapf(
			ErrInvalidParams,
			"max_exec_msgs_per_tx_for_sponsor must be within [1, %d]",
			MaxExecMsgsPerTxForSponsor,
		)
	}
	if p.MaxPolicyExecMsgBytes == 0 || p.MaxPolicyExecMsgBytes > MaxPolicyExecMsgBytes {
		return errorsmod.Wrapf(
			ErrInvalidParams,
			"max_policy_exec_msg_bytes must be within [1, %d]",
			MaxPolicyExecMsgBytes,
		)
	}
	// Method ticket uses per issue must be within [1, 100]
	if p.MaxMethodTicketUsesPerIssue < 1 || p.MaxMethodTicketUsesPerIssue > 100 {
		return errorsmod.Wrap(ErrInvalidParams, "max_method_ticket_uses_per_issue must be within [1, 100]")
	}

	// GC per block may be zero to disable, but must remain bounded because it
	// runs in BeginBlock on every validator.
	if p.TicketGcPerBlock > MaxTicketGCPerBlock {
		return errorsmod.Wrapf(ErrInvalidParams, "ticket_gc_per_block exceeds maximum (%d)", MaxTicketGCPerBlock)
	}

	if p.MaxMethodNameBytes == 0 || p.MaxMethodNameBytes > MaxMethodNameBytes {
		return errorsmod.Wrapf(
			ErrInvalidParams,
			"max_method_name_bytes must be within [1, %d]",
			MaxMethodNameBytes,
		)
	}

	// MaxMethodJsonDepth: 0 means use default; otherwise must be within [1, 64]
	if p.MaxMethodJsonDepth > 64 {
		return errorsmod.Wrap(ErrInvalidParams, "max_method_json_depth must be within [1, 64]")
	}

	return nil
}

// === Message implementations for MsgUpdateParams ===

// Route returns the message route
func (msg MsgUpdateParams) Route() string {
	return RouterKey
}

// Type returns the message type
func (msg MsgUpdateParams) Type() string {
	return "update_params"
}

// GetSigners returns the signers
func (msg MsgUpdateParams) GetSigners() []sdk.AccAddress {
	signer, err := sdk.AccAddressFromBech32(msg.Authority)
	if err != nil {
		panic(err)
	}
	return []sdk.AccAddress{signer}
}

// GetSignBytes returns the sign bytes
func (msg MsgUpdateParams) GetSignBytes() []byte {
	bz := ModuleCdc.MustMarshalJSON(&msg)
	return sdk.MustSortJSON(bz)
}

// ValidateBasic performs basic validation
func (msg MsgUpdateParams) ValidateBasic() error {
	// Validate authority address
	if err := ValidateCanonicalAddress(msg.Authority); err != nil {
		return errorsmod.Wrapf(sdkerrors.ErrInvalidAddress, "invalid authority address: %s", msg.Authority)
	}

	// Validate parameters
	return msg.Params.Validate()
}

// TypeURL returns the TypeURL for this message
func (msg *MsgUpdateParams) XXX_MessageName() string {
	return "doravota.sponsor.v1.MsgUpdateParams"
}

// === Message implementations for MsgWithdrawSponsorFunds ===

// NewMsgWithdrawSponsorFunds creates a new MsgWithdrawSponsorFunds instance
func NewMsgWithdrawSponsorFunds(creator, contractAddress, recipient string, amount sdk.Coins) *MsgWithdrawSponsorFunds {
	// Convert sdk.Coins to protobuf coins
	pbCoins := make([]*sdk.Coin, len(amount))
	for i, coin := range amount {
		newCoin := sdk.Coin{Denom: coin.Denom, Amount: coin.Amount}
		pbCoins[i] = &newCoin
	}

	return &MsgWithdrawSponsorFunds{
		Creator:         creator,
		ContractAddress: contractAddress,
		Recipient:       recipient,
		Amount:          pbCoins,
	}
}

// Route returns the message route
func (msg MsgWithdrawSponsorFunds) Route() string {
	base := BaseSponsorMsg{Creator: msg.Creator, ContractAddress: msg.ContractAddress}
	return base.GetCommonRoute()
}

// Type returns the message type
func (msg MsgWithdrawSponsorFunds) Type() string { return "withdraw_sponsor_funds" }

// GetSigners returns the signers
func (msg MsgWithdrawSponsorFunds) GetSigners() []sdk.AccAddress {
	base := BaseSponsorMsg{Creator: msg.Creator, ContractAddress: msg.ContractAddress}
	return base.GetCommonSigners()
}

// GetSignBytes returns the sign bytes
func (msg MsgWithdrawSponsorFunds) GetSignBytes() []byte {
	bz := ModuleCdc.MustMarshalJSON(&msg)
	return sdk.MustSortJSON(bz)
}

// ValidateBasic performs basic validation
func (msg MsgWithdrawSponsorFunds) ValidateBasic() error {
	base := BaseSponsorMsg{Creator: msg.Creator, ContractAddress: msg.ContractAddress}
	if err := base.ValidateBasicFields(); err != nil {
		return err
	}

	// Validate recipient
	if err := ValidateCanonicalAddress(msg.Recipient); err != nil {
		return errorsmod.Wrapf(sdkerrors.ErrInvalidAddress, "invalid recipient address: %s", msg.Recipient)
	}

	if len(msg.Amount) > 0 {
		if _, err := msg.NormalizedAmount(); err != nil {
			return err
		}
	} else {
		// Len==0 is allowed: means withdraw entire balance, handled server-side
	}

	return nil
}

// TypeURL returns the TypeURL for this message
func (msg *MsgWithdrawSponsorFunds) XXX_MessageName() string {
	return "doravota.sponsor.v1.MsgWithdrawSponsorFunds"
}

// NormalizedAmount returns a canonical sdk.Coins representation even when
// Amount is empty. Duplicate entries are merged with checked arithmetic.
func (msg MsgWithdrawSponsorFunds) NormalizedAmount() (sdk.Coins, error) {
	total := sdk.ZeroInt()
	for _, c := range msg.Amount {
		if c == nil {
			return nil, errorsmod.Wrap(sdkerrors.ErrInvalidCoins, "coin cannot be nil")
		}
		if c.Denom != SponsorshipDenom {
			return nil, errorsmod.Wrap(sdkerrors.ErrInvalidCoins, "only 'peaka' denomination is supported")
		}
		if !c.Amount.IsPositive() {
			return nil, errorsmod.Wrap(sdkerrors.ErrInvalidCoins, "amount must be positive")
		}
		next, err := total.SafeAdd(c.Amount)
		if err != nil {
			return nil, errorsmod.Wrap(sdkerrors.ErrInvalidCoins, "withdraw amount overflow")
		}
		total = next
	}
	if total.IsZero() {
		return sdk.Coins{}, nil
	}
	return sdk.NewCoins(sdk.NewCoin(SponsorshipDenom, total)), nil
}
