package types

import (
	"github.com/cosmos/cosmos-sdk/codec"
	"github.com/cosmos/cosmos-sdk/codec/legacy"
	codectypes "github.com/cosmos/cosmos-sdk/codec/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/cosmos/cosmos-sdk/types/msgservice"
	txtypes "github.com/cosmos/cosmos-sdk/types/tx"
)

func RegisterLegacyAminoCodec(cdc *codec.LegacyAmino) {
	legacy.RegisterAminoMsg(cdc, &MsgRegisterKey{}, "pqcauth/MsgRegisterKey")
	legacy.RegisterAminoMsg(cdc, &MsgRotateKey{}, "pqcauth/MsgRotateKey")
	legacy.RegisterAminoMsg(cdc, &MsgRotateRecoveryKey{}, "pqcauth/MsgRotateRecoveryKey")
	legacy.RegisterAminoMsg(cdc, &MsgSetProtection{}, "pqcauth/MsgSetProtection")
	legacy.RegisterAminoMsg(cdc, &MsgRevokeKey{}, "pqcauth/MsgRevokeKey")
	legacy.RegisterAminoMsg(cdc, &MsgRecoverKey{}, "pqcauth/MsgRecoverKey")
	legacy.RegisterAminoMsg(cdc, &MsgUpdateParams{}, "pqcauth/MsgUpdateParams")
}

func RegisterInterfaces(registry codectypes.InterfaceRegistry) {
	registry.RegisterImplementations(
		(*sdk.Msg)(nil),
		&MsgRegisterKey{},
		&MsgRotateKey{},
		&MsgRotateRecoveryKey{},
		&MsgSetProtection{},
		&MsgRevokeKey{},
		&MsgRecoverKey{},
		&MsgUpdateParams{},
	)
	registry.RegisterImplementations(
		(*txtypes.TxExtensionOptionI)(nil),
		&ExtensionPQCAuth{},
	)
	msgservice.RegisterMsgServiceDesc(registry, &_Msg_serviceDesc)
}

var (
	amino     = codec.NewLegacyAmino()
	ModuleCdc = codec.NewAminoCodec(amino)
)

func init() {
	RegisterLegacyAminoCodec(amino)
	sdk.RegisterLegacyAminoCodec(amino)
}
