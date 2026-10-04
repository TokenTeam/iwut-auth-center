// Package domain owns OAuth authorization state independently of its wire and
// persistence representations. All mutations share Auth's transaction fence.
package domain

import (
	"errors"
	"slices"
	"sort"
	"strings"
	"time"
)

var (
	ErrRequest      = errors.New("invalid_request")
	ErrScope        = errors.New("invalid_scope")
	ErrClient       = errors.New("invalid_client")
	ErrGrant        = errors.New("invalid_grant")
	ErrToken        = errors.New("invalid_token")
	ErrInsufficient = errors.New("insufficient_scope")
	ErrUnavailable  = errors.New("temporarily_unavailable")
	ErrLogin        = errors.New("login_required")
	ErrConsent      = errors.New("consent_required")
	ErrConflict     = errors.New("interaction_changed")
	ErrNotFound     = errors.New("not_found")
)

type Scope struct {
	Name, Label, Description, Kind, Audience string
	Enabled                                  bool
}
type Catalog struct {
	Revision    int64
	GeneratedAt time.Time
	Scopes      []Scope
}

func (c Catalog) Enabled(refresh bool) []string {
	var out []string
	for _, s := range c.Scopes {
		if s.Enabled && (s.Kind == "RESOURCE" && s.Audience != "" || s.Kind == "PROTOCOL" && (s.Name == "openid" || s.Name == "email" || s.Name == "offline_access" && refresh)) {
			out = append(out, s.Name)
		}
	}
	return Union(out)
}

// Channels are explicit security boundaries, never fallback priorities.
func ValidChannel(channel string) bool {
	return channel == "TEST" || channel == "STABLE" || channel == "GREY"
}

func ValidMembership(channel, testerID string) bool {
	return ValidChannel(channel) && (channel == "TEST" && testerID != "" || channel != "TEST" && testerID == "")
}

type Client struct {
	ID, ApplicationID, Type, Channel                             string
	RegistrationRevision, AuthorizationEpoch, CredentialRevision int64
}
type Runtime struct {
	Client                                               Client
	Major                                                int32
	AdminID, VersionID, ProfileID, DisplayName, TesterID string
	PublicationRevision                                  int64
	Redirects, Required, Optional                        []string
	ObservedAt, ValidUntil                               time.Time
}

func (r Runtime) Fresh(now time.Time) bool {
	return !r.ObservedAt.After(now) && r.ValidUntil.After(now) && r.ValidUntil.Sub(r.ObservedAt) > 0 && r.ValidUntil.Sub(r.ObservedAt) <= 5*time.Second
}
func (r Runtime) SameTuple(o Runtime) bool {
	return r.Client == o.Client && r.Major == o.Major && r.AdminID == o.AdminID && r.VersionID == o.VersionID && r.ProfileID == o.ProfileID && r.PublicationRevision == o.PublicationRevision && r.TesterID == o.TesterID
}

type RedirectEntry struct {
	Channel, VersionID  string
	Major               int32
	PublicationRevision int64
}
type RedirectSnapshot struct {
	ApplicationID          string
	Entries                []RedirectEntry
	URIs                   []string
	ObservedAt, ValidUntil time.Time
}
type Session struct {
	ID, AuthID                 string
	AuthenticatedAt, ExpiresAt time.Time
}
type User struct {
	AuthID, Email, DeveloperHandle   string
	EmailVerified, DeveloperApproved bool
}
type AuthorizationRequest struct {
	ClientID, RedirectURI, State, Nonce, Challenge, ChallengeMethod, Channel, Prompt string
	Major                                                                            int32
	Scopes                                                                           []string
	MaxAge                                                                           *int64
}
type Interaction struct {
	ID, CSRFHash, Status, AuthID, SessionID, InitialSessionID string
	Request                                                   AuthorizationRequest
	Runtime                                                   Runtime
	GrantRevision                                             int64
	AuthenticatedAt, ExpiresAt                                time.Time
}
type Grant struct {
	ID, AuthID, ApplicationID, Channel, Status, DisplayName string
	Scopes                                                  []string
	Revision, RevocationEpoch                               int64
	CreatedAt, UpdatedAt                                    time.Time
}
type Code struct {
	Digest, AuthID, ClientID, GrantID, RedirectURI, Nonce, Challenge, FamilyID string
	Scopes                                                                     []string
	Runtime                                                                    Runtime
	GrantRevision, GrantEpoch                                                  int64
	AuthenticatedAt, ExpiresAt                                                 time.Time
	Consumed                                                                   bool
}
type Family struct {
	ID, AuthID, ClientID, ApplicationID, GrantID, Channel, TesterID string
	Major                                                           int32
	GrantEpoch, ClientEpoch                                         int64
	ScopeCeiling                                                    []string
	CreatedAt, IdleExpiresAt, AbsoluteExpiresAt                     time.Time
	LastRefreshedAt                                                 *time.Time
	Revoked                                                         bool
}
type Access struct {
	ID, AuthID, GrantID                    string
	GrantRevision, GrantEpoch, ClientEpoch int64
	Runtime                                Runtime
	IssuedAt                               time.Time
	Digest, FamilyID                       string
	Scopes, Audiences                      []string
	ExpiresAt                              time.Time
	Revoked                                bool
}
type Refresh struct {
	Digest, FamilyID string
	Consumed         bool
}
type Sector struct{ ID, ApplicationID, Hostname string }
type Subject struct{ ID, AuthID, SectorID string }
type Audit struct {
	ID, AuthID, GrantID, ClientID, Action string
	Scopes                                []string
	Revision, Epoch                       int64
	At                                    time.Time
}
type AuthorizationView struct {
	InteractionID, CSRF, DisplayName, DeveloperHandle, Channel string
	Requested, Required, PreviouslyGranted                     []string
	Definitions                                                []Scope
	Redirect                                                   string
	LoginRequired                                              bool
}
type TokenResponse struct {
	AccessToken, RefreshToken, IDToken string
	ExpiresIn                          int64
	Scopes                             []string
}
type UserInfo struct {
	Subject, Email string
	EmailVerified  bool
}
type ClientProof struct {
	ClientID, Secret string
	Basic            bool
}
type Route struct {
	ID, Audience, Protocol, Method, Path string
	Scopes, Channels                     []string
}
type DelegationRequest struct{ RouteID, PolicyDigest, Protocol, Method, TargetPath string }
type Delegation struct {
	Token     string
	ExpiresAt time.Time
}

func ValidScopes(xs []string) bool {
	if len(xs) > 32 {
		return false
	}
	seen := map[string]bool{}
	for _, s := range xs {
		if len(s) == 0 || len(s) > 128 || seen[s] {
			return false
		}
		seen[s] = true
		for _, c := range s {
			if c < 0x21 || c > 0x7e || c == '"' || c == '\\' {
				return false
			}
		}
	}
	return true
}
func Contains(xs []string, s string) bool { return slices.Contains(xs, s) }
func Subset(a, b []string) bool {
	for _, s := range a {
		if !Contains(b, s) {
			return false
		}
	}
	return true
}
func Union(sets ...[]string) []string {
	m := map[string]bool{}
	for _, ss := range sets {
		for _, s := range ss {
			m[s] = true
		}
	}
	out := make([]string, 0, len(m))
	for s := range m {
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}
func Intersect(first []string, rest ...[]string) []string {
	out := []string{}
	for _, s := range first {
		ok := true
		for _, set := range rest {
			ok = ok && Contains(set, s)
		}
		if ok {
			out = append(out, s)
		}
	}
	return Union(out)
}
func Difference(a, b []string) []string {
	out := []string{}
	for _, s := range a {
		if !Contains(b, s) {
			out = append(out, s)
		}
	}
	return Union(out)
}
func ParseScopes(s string) ([]string, error) {
	xs := strings.Split(s, " ")
	if !ValidScopes(xs) {
		return nil, ErrScope
	}
	return Union(xs), nil
}

// Registration describes Auth-owned static OIDC metadata. Origins are search
// hints only: CORS always re-resolves the current App runtime before allowing it.
type Registration struct {
	ClientID, ApplicationID, SectorID, SectorURI, Type string
	Major                                              int32
	Origins                                            []string
}
