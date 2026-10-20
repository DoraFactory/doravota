package types

// CheckRegistrationAllowed applies the active classic-account registration
// gate. "Fresh" means the account was observed before SetPubKey with both a
// zero sequence and no public key stored on chain.
func CheckRegistrationAllowed(params Params, height int64, fresh bool) error {
	switch params.EffectiveRegistrationMode(height) {
	case RegistrationMode_REGISTRATION_MODE_OPEN:
		return nil
	case RegistrationMode_REGISTRATION_MODE_FRESH_ACCOUNTS_ONLY:
		if !fresh {
			return ErrFreshRegistrationOnly
		}
		return nil
	case RegistrationMode_REGISTRATION_MODE_CLOSED:
		return ErrRegistrationClosed
	default:
		return ErrRegistrationClosed.Wrap("invalid registration mode")
	}
}
