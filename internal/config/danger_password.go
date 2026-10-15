package config

import "fmt"

func validateDangerPasswordDependencies(password *Password, account *AccountClosure, application *ApplicationCloseReauth) error {
	if password == nil && (account != nil && account.Enabled || application != nil && application.Enabled) {
		return fmt.Errorf("%w: public closure proofs require the password runtime", ErrInvalidConfiguration)
	}
	// Closing the public entry must not stop durable replay/cleanup workers.
	return nil
}
