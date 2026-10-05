package domain

import (
	"errors"
	"regexp"
	"time"
)

var (
	ErrInvalidRequest = errors.New("INVALID_SESSION_MANAGEMENT_REQUEST")
	ErrInvalidCursor  = errors.New("INVALID_SESSION_CURSOR")
	ErrCurrentSession = errors.New("CURRENT_SESSION_NOT_ALLOWED")
	ErrSessionInvalid = errors.New("SESSION_INVALID")
	ErrRateLimited    = errors.New("SESSION_MANAGEMENT_RATE_LIMITED")
	ErrUnavailable    = errors.New("SESSION_MANAGEMENT_UNAVAILABLE")
)
var idPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

func ValidID(id string) bool { return idPattern.MatchString(id) }
func ValidateList(pageSize int, cursor string) error {
	if pageSize < 1 || pageSize > 50 || cursor != "" && !ValidID(cursor) {
		return ErrInvalidRequest
	}
	return nil
}
func ValidateTargets(ids []string) error {
	if len(ids) < 1 || len(ids) > 50 {
		return ErrInvalidRequest
	}
	seen := make(map[string]bool, len(ids))
	for _, id := range ids {
		if !ValidID(id) || seen[id] {
			return ErrInvalidRequest
		}
		seen[id] = true
	}
	return nil
}

type Summary struct {
	SessionID, CredentialID, AuthenticationMethod     string
	AuthenticatedAt, CreatedAt, LastUsedAt, ExpiresAt time.Time
	IsCurrent                                         bool
}
type Page struct {
	CurrentSessionID string
	ObservedAt       time.Time
	Sessions         []Summary
	NextCursor       string
}
