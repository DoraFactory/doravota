// Package types is a compile-only compatibility surface for Wasmd 0.70.x.
// Cosmos SDK v0.55 removed x/params, but Wasmd retains these declarations for
// its historical v2 -> v3 parameter migration. This package intentionally
// implements no store, keeper, governance, or runtime module.
package types

type ValueValidatorFn func(value interface{}) error

type ParamSetPair struct {
	Key         []byte
	Value       interface{}
	ValidatorFn ValueValidatorFn
}

func NewParamSetPair(key []byte, value interface{}, validator ValueValidatorFn) ParamSetPair {
	return ParamSetPair{Key: key, Value: value, ValidatorFn: validator}
}

type ParamSetPairs []ParamSetPair

type ParamSet interface {
	ParamSetPairs() ParamSetPairs
}

type KeyTable struct{}

func NewKeyTable(...ParamSetPair) KeyTable { return KeyTable{} }

func (KeyTable) RegisterParamSet(ParamSet) KeyTable { return KeyTable{} }
