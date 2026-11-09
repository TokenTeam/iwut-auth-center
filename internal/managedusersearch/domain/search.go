package domain

import (
	"errors"
	"strings"
	"time"
	"unicode/utf8"
)

var (
	ErrIdentity    = errors.New("INVALID_USER_IDENTITY")
	ErrForbidden   = errors.New("MANAGED_USER_SEARCH_FORBIDDEN")
	ErrInvalid     = errors.New("INVALID_MANAGED_USER_SEARCH_REQUEST")
	ErrLarge       = errors.New("MANAGED_USER_SEARCH_REQUEST_TOO_LARGE")
	ErrRate        = errors.New("MANAGED_USER_SEARCH_RATE_LIMITED")
	ErrUnavailable = errors.New("MANAGED_USER_SEARCH_UNAVAILABLE")
)

type Query struct{ Kind, Value string }
type Summary struct{ AuthID, AccountStatus, DeveloperStatus string }
type Result struct {
	Items []Summary
	AsOf  time.Time
}

func ValidID(value string) bool {
	return value != "" && len(value) <= 256 && utf8.ValidString(value) && strings.TrimSpace(value) == value
}
