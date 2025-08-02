package types

import (
	sdk "github.com/cosmos/cosmos-sdk/types"
	sdkerrors "github.com/cosmos/cosmos-sdk/types/errors"
)

// NewMsgSetSponsor creates a new MsgSetSponsor instance
func NewMsgSetSponsor(creator, contractAddress string, isSponsored bool) *MsgSetSponsor {
	return &MsgSetSponsor{
		Creator:         creator,
		ContractAddress: contractAddress,
		IsSponsored:     isSponsored,
	}
}

// Route returns the message route
func (msg MsgSetSponsor) Route() string {
	return RouterKey
}

// Type returns the message type
func (msg MsgSetSponsor) Type() string {
	return "set_sponsor"
}

// GetSigners returns the signers
func (msg MsgSetSponsor) GetSigners() []sdk.AccAddress {
	signer, err := sdk.AccAddressFromBech32(msg.Creator)
	if err != nil {
		panic(err)
	}
	return []sdk.AccAddress{signer}
}

// GetSignBytes returns the sign bytes
func (msg MsgSetSponsor) GetSignBytes() []byte {
	bz := ModuleCdc.MustMarshalJSON(&msg)
	return sdk.MustSortJSON(bz)
}

// ValidateBasic performs basic validation
func (msg MsgSetSponsor) ValidateBasic() error {
	_, err := sdk.AccAddressFromBech32(msg.Creator)
	if err != nil {
		return sdkerrors.Wrapf(sdkerrors.ErrInvalidAddress, "invalid creator address: %s", msg.Creator)
	}
	if msg.ContractAddress == "" {
		return sdkerrors.Wrap(sdkerrors.ErrInvalidRequest, "contract address cannot be empty")
	}
	return nil
}

// TypeURL returns the TypeURL for this message
func (msg *MsgSetSponsor) XXX_MessageName() string {
	return "doravota.sponsor.v1.MsgSetSponsor"
}

// === Message implementations for MsgUpdateSponsor ===

// NewMsgUpdateSponsor creates a new MsgUpdateSponsor instance
func NewMsgUpdateSponsor(creator, contractAddress string, isSponsored bool) *MsgUpdateSponsor {
	return &MsgUpdateSponsor{
		Creator:         creator,
		ContractAddress: contractAddress,
		IsSponsored:     isSponsored,
	}
}

// Route returns the message route
func (msg MsgUpdateSponsor) Route() string {
	return RouterKey
}

// Type returns the message type
func (msg MsgUpdateSponsor) Type() string {
	return "update_sponsor"
}

// GetSigners returns the signers
func (msg MsgUpdateSponsor) GetSigners() []sdk.AccAddress {
	signer, err := sdk.AccAddressFromBech32(msg.Creator)
	if err != nil {
		panic(err)
	}
	return []sdk.AccAddress{signer}
}

// GetSignBytes returns the sign bytes
func (msg MsgUpdateSponsor) GetSignBytes() []byte {
	bz := ModuleCdc.MustMarshalJSON(&msg)
	return sdk.MustSortJSON(bz)
}

// ValidateBasic performs basic validation
func (msg MsgUpdateSponsor) ValidateBasic() error {
	_, err := sdk.AccAddressFromBech32(msg.Creator)
	if err != nil {
		return sdkerrors.Wrapf(sdkerrors.ErrInvalidAddress, "invalid creator address: %s", msg.Creator)
	}
	if msg.ContractAddress == "" {
		return sdkerrors.Wrap(sdkerrors.ErrInvalidRequest, "contract address cannot be empty")
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
	return RouterKey
}

// Type returns the message type
func (msg MsgDeleteSponsor) Type() string {
	return "delete_sponsor"
}

// GetSigners returns the signers
func (msg MsgDeleteSponsor) GetSigners() []sdk.AccAddress {
	signer, err := sdk.AccAddressFromBech32(msg.Creator)
	if err != nil {
		panic(err)
	}
	return []sdk.AccAddress{signer}
}

// GetSignBytes returns the sign bytes
func (msg MsgDeleteSponsor) GetSignBytes() []byte {
	bz := ModuleCdc.MustMarshalJSON(&msg)
	return sdk.MustSortJSON(bz)
}

// ValidateBasic performs basic validation
func (msg MsgDeleteSponsor) ValidateBasic() error {
	_, err := sdk.AccAddressFromBech32(msg.Creator)
	if err != nil {
		return sdkerrors.Wrapf(sdkerrors.ErrInvalidAddress, "invalid creator address: %s", msg.Creator)
	}
	if msg.ContractAddress == "" {
		return sdkerrors.Wrap(sdkerrors.ErrInvalidRequest, "contract address cannot be empty")
	}
	return nil
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
		MaxSponsorsPerContract: 1,
		SponsorshipEnabled:     true,
		MaxGasPerSponsorship:   1000000, // 1M gas
		MinContractAge:         0,       // No minimum age requirement
	}
}

// Validate validates the parameters
func (p Params) Validate() error {
	if p.MaxSponsorsPerContract == 0 {
		return sdkerrors.Wrap(ErrInvalidParams, "max sponsors per contract must be greater than 0")
	}
	
	if p.MaxGasPerSponsorship == 0 {
		return sdkerrors.Wrap(ErrInvalidParams, "max gas per sponsorship must be greater than 0")
	}
	
	return nil
}
