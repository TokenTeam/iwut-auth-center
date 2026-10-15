package domain

import "errors"

var (
	ErrIdentity    = errors.New("APPLICATION_USER_STORAGE_IDENTITY_REQUIRED")
	ErrInvalid     = errors.New("INVALID_APPLICATION_USER_STORAGE_REQUEST")
	ErrUnavailable = errors.New("APPLICATION_USER_STORAGE_UNAVAILABLE")
)
