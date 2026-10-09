// Package types contains legacy wire formats only. No Wasm runtime or handlers.
package types

import (
	"context"
	"encoding/json"
	"errors"
	ct "github.com/cosmos/cosmos-sdk/codec/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/cosmos/cosmos-sdk/x/authz"
	"github.com/cosmos/gogoproto/proto"
)

var ErrRetired = errors.New("Wasm execution is retired; legacy types are decode-only")

type RawContractMessage []byte

func (m RawContractMessage) MarshalJSON() ([]byte, error) {
	if len(m) == 0 {
		return []byte("null"), nil
	}
	return json.RawMessage(m).MarshalJSON()
}
func (m *RawContractMessage) UnmarshalJSON(b []byte) error { *m = append((*m)[:0], b...); return nil }

type ContractInfoExtension interface{ proto.Message }
type ContractAuthzFilterX interface {
	proto.Message
	legacyFilter()
}
type ContractAuthzLimitX interface {
	proto.Message
	legacyLimit()
}

func (*AllowAllMessagesFilter) legacyFilter()    {}
func (*AcceptedMessageKeysFilter) legacyFilter() {}
func (*AcceptedMessagesFilter) legacyFilter()    {}
func (*MaxCallsLimit) legacyLimit()              {}
func (*MaxFundsLimit) legacyLimit()              {}
func (*CombinedLimit) legacyLimit()              {}
func (g ContractGrant) UnpackInterfaces(u ct.AnyUnpacker) error {
	var limit ContractAuthzLimitX
	if err := u.UnpackAny(g.Limit, &limit); err != nil {
		return err
	}
	var filter ContractAuthzFilterX
	return u.UnpackAny(g.Filter, &filter)
}
func (a ContractExecutionAuthorization) UnpackInterfaces(u ct.AnyUnpacker) error {
	for _, g := range a.Grants {
		if err := g.UnpackInterfaces(u); err != nil {
			return err
		}
	}
	return nil
}
func (a ContractMigrationAuthorization) UnpackInterfaces(u ct.AnyUnpacker) error {
	for _, g := range a.Grants {
		if err := g.UnpackInterfaces(u); err != nil {
			return err
		}
	}
	return nil
}
func (a StoreCodeAuthorization) MsgTypeURL() string   { return "/cosmwasm.wasm.v1.MsgStoreCode" }
func (a StoreCodeAuthorization) ValidateBasic() error { return ErrRetired }
func (a StoreCodeAuthorization) Accept(context.Context, sdk.Msg) (authz.AcceptResponse, error) {
	return authz.AcceptResponse{}, ErrRetired
}
func (a ContractExecutionAuthorization) MsgTypeURL() string {
	return "/cosmwasm.wasm.v1.MsgExecuteContract"
}
func (a ContractExecutionAuthorization) ValidateBasic() error { return ErrRetired }
func (a ContractExecutionAuthorization) Accept(context.Context, sdk.Msg) (authz.AcceptResponse, error) {
	return authz.AcceptResponse{}, ErrRetired
}
func (a ContractMigrationAuthorization) MsgTypeURL() string {
	return "/cosmwasm.wasm.v1.MsgMigrateContract"
}
func (a ContractMigrationAuthorization) ValidateBasic() error { return ErrRetired }
func (a ContractMigrationAuthorization) Accept(context.Context, sdk.Msg) (authz.AcceptResponse, error) {
	return authz.AcceptResponse{}, ErrRetired
}
func (p StoreCodeProposal) GetTitle() string                         { return p.Title }
func (p StoreCodeProposal) GetDescription() string                   { return p.Description }
func (p StoreCodeProposal) ProposalRoute() string                    { return "wasm" }
func (p StoreCodeProposal) ProposalType() string                     { return "StoreCode" }
func (p StoreCodeProposal) ValidateBasic() error                     { return ErrRetired }
func (p InstantiateContractProposal) GetTitle() string               { return p.Title }
func (p InstantiateContractProposal) GetDescription() string         { return p.Description }
func (p InstantiateContractProposal) ProposalRoute() string          { return "wasm" }
func (p InstantiateContractProposal) ProposalType() string           { return "InstantiateContract" }
func (p InstantiateContractProposal) ValidateBasic() error           { return ErrRetired }
func (p InstantiateContract2Proposal) GetTitle() string              { return p.Title }
func (p InstantiateContract2Proposal) GetDescription() string        { return p.Description }
func (p InstantiateContract2Proposal) ProposalRoute() string         { return "wasm" }
func (p InstantiateContract2Proposal) ProposalType() string          { return "InstantiateContract2" }
func (p InstantiateContract2Proposal) ValidateBasic() error          { return ErrRetired }
func (p MigrateContractProposal) GetTitle() string                   { return p.Title }
func (p MigrateContractProposal) GetDescription() string             { return p.Description }
func (p MigrateContractProposal) ProposalRoute() string              { return "wasm" }
func (p MigrateContractProposal) ProposalType() string               { return "MigrateContract" }
func (p MigrateContractProposal) ValidateBasic() error               { return ErrRetired }
func (p SudoContractProposal) GetTitle() string                      { return p.Title }
func (p SudoContractProposal) GetDescription() string                { return p.Description }
func (p SudoContractProposal) ProposalRoute() string                 { return "wasm" }
func (p SudoContractProposal) ProposalType() string                  { return "SudoContract" }
func (p SudoContractProposal) ValidateBasic() error                  { return ErrRetired }
func (p ExecuteContractProposal) GetTitle() string                   { return p.Title }
func (p ExecuteContractProposal) GetDescription() string             { return p.Description }
func (p ExecuteContractProposal) ProposalRoute() string              { return "wasm" }
func (p ExecuteContractProposal) ProposalType() string               { return "ExecuteContract" }
func (p ExecuteContractProposal) ValidateBasic() error               { return ErrRetired }
func (p UpdateAdminProposal) GetTitle() string                       { return p.Title }
func (p UpdateAdminProposal) GetDescription() string                 { return p.Description }
func (p UpdateAdminProposal) ProposalRoute() string                  { return "wasm" }
func (p UpdateAdminProposal) ProposalType() string                   { return "UpdateAdmin" }
func (p UpdateAdminProposal) ValidateBasic() error                   { return ErrRetired }
func (p ClearAdminProposal) GetTitle() string                        { return p.Title }
func (p ClearAdminProposal) GetDescription() string                  { return p.Description }
func (p ClearAdminProposal) ProposalRoute() string                   { return "wasm" }
func (p ClearAdminProposal) ProposalType() string                    { return "ClearAdmin" }
func (p ClearAdminProposal) ValidateBasic() error                    { return ErrRetired }
func (p PinCodesProposal) GetTitle() string                          { return p.Title }
func (p PinCodesProposal) GetDescription() string                    { return p.Description }
func (p PinCodesProposal) ProposalRoute() string                     { return "wasm" }
func (p PinCodesProposal) ProposalType() string                      { return "PinCodes" }
func (p PinCodesProposal) ValidateBasic() error                      { return ErrRetired }
func (p UnpinCodesProposal) GetTitle() string                        { return p.Title }
func (p UnpinCodesProposal) GetDescription() string                  { return p.Description }
func (p UnpinCodesProposal) ProposalRoute() string                   { return "wasm" }
func (p UnpinCodesProposal) ProposalType() string                    { return "UnpinCodes" }
func (p UnpinCodesProposal) ValidateBasic() error                    { return ErrRetired }
func (p UpdateInstantiateConfigProposal) GetTitle() string           { return p.Title }
func (p UpdateInstantiateConfigProposal) GetDescription() string     { return p.Description }
func (p UpdateInstantiateConfigProposal) ProposalRoute() string      { return "wasm" }
func (p UpdateInstantiateConfigProposal) ProposalType() string       { return "UpdateInstantiateConfig" }
func (p UpdateInstantiateConfigProposal) ValidateBasic() error       { return ErrRetired }
func (p StoreAndInstantiateContractProposal) GetTitle() string       { return p.Title }
func (p StoreAndInstantiateContractProposal) GetDescription() string { return p.Description }
func (p StoreAndInstantiateContractProposal) ProposalRoute() string  { return "wasm" }
func (p StoreAndInstantiateContractProposal) ProposalType() string {
	return "StoreAndInstantiateContract"
}
func (p StoreAndInstantiateContractProposal) ValidateBasic() error { return ErrRetired }
func (p *StoreCodeProposal) String() string                        { return proto.CompactTextString(p) }
func (p *InstantiateContractProposal) String() string              { return proto.CompactTextString(p) }
func (p *InstantiateContract2Proposal) String() string             { return proto.CompactTextString(p) }
func (p *MigrateContractProposal) String() string                  { return proto.CompactTextString(p) }
func (p *SudoContractProposal) String() string                     { return proto.CompactTextString(p) }
func (p *ExecuteContractProposal) String() string                  { return proto.CompactTextString(p) }
func (p *UpdateAdminProposal) String() string                      { return proto.CompactTextString(p) }
func (p *ClearAdminProposal) String() string                       { return proto.CompactTextString(p) }
func (p *PinCodesProposal) String() string                         { return proto.CompactTextString(p) }
func (p *UnpinCodesProposal) String() string                       { return proto.CompactTextString(p) }
func (p *UpdateInstantiateConfigProposal) String() string          { return proto.CompactTextString(p) }
func (p *StoreAndInstantiateContractProposal) String() string      { return proto.CompactTextString(p) }
func (p *AccessConfigUpdate) String() string                       { return proto.CompactTextString(p) }
func (p *Params) String() string                                   { return proto.CompactTextString(p) }
