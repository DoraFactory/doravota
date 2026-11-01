package types

// CheckRegistrationAllowed applies the active classic-account registration
// gate. The captured fresh marker is retained for interface compatibility but
// cannot enable FRESH_ACCOUNTS_ONLY in phase one.
func CheckRegistrationAllowed(params Params, height int64, fresh bool) error {
	switch params.EffectiveRegistrationMode(height) {
	case RegistrationMode_REGISTRATION_MODE_OPEN:
		return nil
	case RegistrationMode_REGISTRATION_MODE_FRESH_ACCOUNTS_ONLY:
		// Defense in depth for malformed/imported experimental state. Do not
		// silently relax this to OPEN, even for a captured fresh candidate.
		return ErrRegistrationClosed.Wrap("FRESH_ACCOUNTS_ONLY is disabled in phase one")
	case RegistrationMode_REGISTRATION_MODE_CLOSED:
		return ErrRegistrationClosed
	default:
		return ErrRegistrationClosed.Wrap("invalid registration mode")
	}
}
