package types

const (
	DefaultMaxExecMsgsPerTxForSponsor uint32 = 25
	MaxExecMsgsPerTxForSponsor        uint32 = 100

	DefaultMaxPolicyExecMsgBytes uint32 = 64 * 1024
	MaxPolicyExecMsgBytes        uint32 = 1024 * 1024

	DefaultMaxMethodNameBytes uint32 = 64
	MaxMethodNameBytes        uint32 = 256
)

// EffectiveMaxExecMsgs returns a consensus-safe execution-message limit even
// if malformed or legacy state bypassed Params validation.
func (p Params) EffectiveMaxExecMsgs() uint32 {
	return effectiveBoundedLimit(
		p.MaxExecMsgsPerTxForSponsor,
		DefaultMaxExecMsgsPerTxForSponsor,
		MaxExecMsgsPerTxForSponsor,
	)
}

// EffectiveMaxPolicyExecBytes returns a consensus-safe message-size limit.
func (p Params) EffectiveMaxPolicyExecBytes() uint32 {
	return effectiveBoundedLimit(
		p.MaxPolicyExecMsgBytes,
		DefaultMaxPolicyExecMsgBytes,
		MaxPolicyExecMsgBytes,
	)
}

// EffectiveMaxMethodBytes returns a consensus-safe method-name limit.
func (p Params) EffectiveMaxMethodBytes() uint32 {
	return effectiveBoundedLimit(
		p.MaxMethodNameBytes,
		DefaultMaxMethodNameBytes,
		MaxMethodNameBytes,
	)
}

func effectiveBoundedLimit(value, defaultValue, maximum uint32) uint32 {
	if value == 0 {
		return defaultValue
	}
	if value > maximum {
		return maximum
	}
	return value
}
