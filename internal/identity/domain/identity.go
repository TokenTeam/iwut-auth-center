package domain

import (
	"errors"
	"slices"
	"sort"
	"strings"
	"time"
)

var (
	ErrInvalidRequest = errors.New("invalid identity issuance request")
	ErrForbidden      = errors.New("identity issuance forbidden")
	ErrSessionInvalid = errors.New("session invalid")
	ErrUnavailable    = errors.New("identity issuance unavailable")
)

const AuthAudience = "iwut-auth-center"
const AppAudience = "iwut-app-center"

func KnownAudience(a string) bool { return a == AuthAudience || a == AppAudience }

type Snapshot struct {
	AuthID             string
	Permissions        []string
	PermissionRevision int64
	DeveloperStatus    string
	SessionExpiresAt   time.Time
}
type Claims struct {
	AuthID, Audience, JTI string
	IssuedAt, ExpiresAt   int64
	Permissions           []string
	DeveloperStatus       string
}
type Issued struct {
	JWS       string
	ExpiresAt int64
}

func (s Snapshot) Valid() bool {
	if s.AuthID == "" || s.PermissionRevision < 1 || s.SessionExpiresAt.IsZero() {
		return false
	}
	seen := map[string]bool{}
	for _, p := range s.Permissions {
		if p == "" || strings.TrimSpace(p) != p || seen[p] {
			return false
		}
		seen[p] = true
	}
	switch s.DeveloperStatus {
	case "", "PENDING", "APPROVED", "REJECTED", "SUSPENDED":
	default:
		return false
	}
	return true
}
func Project(s Snapshot, audience, jti string, now time.Time, ttl time.Duration) (Claims, error) {
	if !KnownAudience(audience) {
		return Claims{}, ErrInvalidRequest
	}
	if !s.Valid() {
		return Claims{}, ErrUnavailable
	}
	iat := now.Unix()
	exp := min(iat+int64(ttl/time.Second), s.SessionExpiresAt.Unix())
	if exp <= iat {
		return Claims{}, ErrSessionInvalid
	}
	c := Claims{AuthID: s.AuthID, Audience: audience, JTI: jti, IssuedAt: iat, ExpiresAt: exp, Permissions: []string{}}
	allowed := []string{"auth.account.manage", "auth.developer.manage", "auth.platform-admin.manage", "auth.reviewer.manage"}
	if audience == AppAudience {
		allowed = []string{"app.profile.review", "app.version.review"}
		c.DeveloperStatus = s.DeveloperStatus
	}
	for _, p := range s.Permissions {
		if slices.Contains(allowed, p) {
			c.Permissions = append(c.Permissions, p)
		}
	}
	sort.Strings(c.Permissions)
	return c, nil
}
