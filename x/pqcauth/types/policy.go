package types

// Effective returns a normalized copy of the policy at height without mutating
// consensus state. Pending fields activate at their exact H+1 height.
func (p AccountPolicy) Effective(height int64) AccountPolicy {
	if p.PendingEffectiveHeight == 0 || height < 0 || uint64(height) < p.PendingEffectiveHeight {
		return p
	}

	p.CurrentSigningKeyId = p.PendingSigningKeyId
	if p.PendingRecoveryKeyId != 0 {
		p.RecoveryKeyId = p.PendingRecoveryKeyId
	}
	p.SelfEnforced = p.PendingSelfEnforced
	p.PolicyVersion = p.PendingPolicyVersion
	p.PendingSigningKeyId = 0
	p.PendingEffectiveHeight = 0
	p.PendingSelfEnforced = false
	p.PendingPolicyVersion = 0
	p.PendingRecoveryKeyId = 0
	return p
}

func (p AccountPolicy) HasPendingChange(height int64) bool {
	return p.PendingEffectiveHeight != 0 && (height < 0 || uint64(height) < p.PendingEffectiveHeight)
}

func (k PQCKeyRecord) IsEffective(height int64) bool {
	if k.Status != KeyStatus_KEY_STATUS_LIVE || height < 0 || uint64(height) < k.EffectiveHeight {
		return false
	}
	return k.InactiveFromHeight == 0 || uint64(height) < k.InactiveFromHeight
}
