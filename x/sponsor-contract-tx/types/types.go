package types

import (
	"fmt"

	sdk "github.com/cosmos/cosmos-sdk/types"
	sdkerrors "github.com/cosmos/cosmos-sdk/types/errors"
)

// BaseSponsorMsg defines common fields and methods for sponsor messages
type BaseSponsorMsg struct {
	Creator         string
	ContractAddress string
}

// ValidateBasicFields performs common validation for sponsor messages
func (b BaseSponsorMsg) ValidateBasicFields() error {
	// Validate creator address
	_, err := sdk.AccAddressFromBech32(b.Creator)
	if err != nil {
		return sdkerrors.Wrapf(sdkerrors.ErrInvalidAddress, "invalid creator address: %s", b.Creator)
	}

	// Validate contract address format
	if err := ValidateContractAddress(b.ContractAddress); err != nil {
		return err
	}

	return nil
}

// ValidateMaxGrantPerUser validates that MaxGrantPerUser is required and only contains peaka denomination
func ValidateMaxGrantPerUser(maxGrantPerUser []*sdk.Coin) error {
	if len(maxGrantPerUser) == 0 {
		return sdkerrors.Wrap(sdkerrors.ErrInvalidRequest, "max_grant_per_user is required and cannot be empty")
	}

	for _, coin := range maxGrantPerUser {
		if coin == nil {
			return sdkerrors.Wrap(sdkerrors.ErrInvalidCoins, "coin cannot be nil")
		}

		if coin.Denom != "peaka" {
			return sdkerrors.Wrap(sdkerrors.ErrInvalidCoins, fmt.Sprintf("invalid denomination '%s': only 'peaka' is supported", coin.Denom))
		}

		if !coin.Amount.IsPositive() {
			return sdkerrors.Wrap(sdkerrors.ErrInvalidCoins, "coin amount must be positive")
		}
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
			return sdkerrors.Wrap(sdkerrors.ErrInvalidCoins, "coin cannot be nil")
		}

		if coin.Denom != "peaka" {
			return sdkerrors.Wrap(sdkerrors.ErrInvalidCoins, fmt.Sprintf("invalid denomination '%s': only 'peaka' is supported", coin.Denom))
		}

		if !coin.Amount.IsPositive() {
			return sdkerrors.Wrap(sdkerrors.ErrInvalidCoins, "coin amount must be positive")
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

	// Validate MaxGrantPerUser field based on sponsorship status
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

	// Validate MaxGrantPerUser field based on sponsorship status
	if err := ValidateMaxGrantPerUserConditional(msg.MaxGrantPerUser, msg.IsSponsored); err != nil {
		return err
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
func NewGenesisState(sponsors []*ContractSponsor) *GenesisState {
	return &GenesisState{
		Sponsors: sponsors,
	}
}

// DefaultGenesisState returns a default genesis state
func DefaultGenesisState() *GenesisState {
	params := DefaultParams()
	return &GenesisState{
		Sponsors: []*ContractSponsor{},
		Params:   &params,
	}
}

// ValidateGenesis validates the genesis state
func ValidateGenesis(data GenesisState) error {
	// Check for duplicate sponsors
	seenSponsors := make(map[string]bool)
	for _, sponsor := range data.Sponsors {
		if sponsor == nil {
			return sdkerrors.Wrap(sdkerrors.ErrInvalidRequest, "sponsor cannot be nil")
		}

		if seenSponsors[sponsor.ContractAddress] {
			return sdkerrors.Wrapf(sdkerrors.ErrInvalidRequest, "duplicate sponsor contract address: %s", sponsor.ContractAddress)
		}
		seenSponsors[sponsor.ContractAddress] = true

		if sponsor.ContractAddress == "" {
			return sdkerrors.Wrap(sdkerrors.ErrInvalidRequest, "sponsor contract address cannot be empty")
		}
	}

	// Validate parameters
	if data.Params != nil {
		return data.Params.Validate()
	}

	return nil
}

// === Parameters ===

// DefaultParams returns default parameters
func DefaultParams() Params {
	return Params{
		SponsorshipEnabled:   true,
		MaxGasPerSponsorship: 1000000, // 1M gas
	}
}

// Validate validates the parameters
func (p Params) Validate() error {
	if p.MaxGasPerSponsorship == 0 {
		return sdkerrors.Wrap(ErrInvalidParams, "max gas per sponsorship must be greater than 0")
	}
	if p.MaxGasPerSponsorship > 50000000 { // 50M gas upper limit
		return sdkerrors.Wrap(ErrInvalidParams, "max gas per sponsorship cannot exceed 50,000,000")
	}

	return nil
}
