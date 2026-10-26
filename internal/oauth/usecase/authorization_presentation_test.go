package usecase

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"testing"
	"time"

	d "iwut-auth-center/internal/oauth/domain"
	"iwut-auth-center/internal/oauth/port"
)

type consentState struct {
	interaction d.Interaction
	grant       d.Grant
	codes       []d.Code
	audits      []d.Audit
}
type consentStore struct {
	port.Tx
	state     consentState
	catalog   d.Catalog
	runtime   d.Runtime
	now       time.Time
	failAudit bool
}

func (s *consentStore) Transaction(_ context.Context, fn func(port.Tx) error) error {
	previous := s.state
	if err := fn(s); err != nil {
		s.state = previous
		return err
	}
	return nil
}
func (*consentStore) ApplicationOpen(string) (bool, error)        { return true, nil }
func (s *consentStore) Interaction(string) (d.Interaction, error) { return s.state.interaction, nil }
func (s *consentStore) SaveInteraction(i d.Interaction) error     { s.state.interaction = i; return nil }
func (s *consentStore) Session(string, time.Time) (d.Session, error) {
	return d.Session{ID: "session", AuthID: "user", AccountRevision: 1, AuthenticatedAt: s.now.Add(-time.Hour)}, nil
}
func (*consentStore) User(string) (d.User, error) {
	return d.User{AccountRevision: 1, AuthID: "user", DeveloperApproved: true, DeveloperHandle: "developer"}, nil
}
func (s *consentStore) Catalog() (d.Catalog, error) { return s.catalog, nil }
func (s *consentStore) FindGrant(string, string, string) (d.Grant, error) {
	if s.state.grant.ID == "" {
		return d.Grant{}, d.ErrNotFound
	}
	return s.state.grant, nil
}
func (s *consentStore) SaveGrant(g d.Grant) error { s.state.grant = g; return nil }
func (s *consentStore) SaveCode(c d.Code) error   { s.state.codes = append(s.state.codes, c); return nil }
func (s *consentStore) Audit(a d.Audit) error {
	if s.failAudit {
		return d.ErrUnavailable
	}
	s.state.audits = append(s.state.audits, a)
	return nil
}

type consentApp struct {
	port.App
	store *consentStore
}

func (a consentApp) Authorize(context.Context, d.Runtime, string) (d.Runtime, error) {
	return a.store.runtime, nil
}

type consentCrypto struct {
	port.Crypto
	sequence int
}

func (c *consentCrypto) Random() (string, error) {
	c.sequence++
	sum := sha256.Sum256([]byte(fmt.Sprint(c.sequence)))
	return base64.RawURLEncoding.EncodeToString(sum[:]), nil
}
func (c *consentCrypto) ID() string { value, _ := c.Random(); return value }
func (*consentCrypto) Digest(purpose, value string) string {
	sum := sha256.Sum256([]byte(purpose + ":" + value))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func newConsentService(t *testing.T) (*Service, *consentStore, d.AuthorizationView) {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Millisecond)
	crypto := &consentCrypto{}
	runtime := d.Runtime{Client: d.Client{ID: "client", ApplicationID: "app", Channel: "STABLE", RegistrationRevision: 1, AuthorizationEpoch: 1}, Major: 1, AdminID: "owner", VersionID: "version", ProfileID: "profile", DisplayName: "Application", PublicationRevision: 1, Required: []string{"openid"}, Optional: []string{"email", "data.read"}, ObservedAt: now, ValidUntil: now.Add(5 * time.Second)}
	store := &consentStore{now: now, runtime: runtime, catalog: d.Catalog{Revision: 1, GeneratedAt: now, Scopes: []d.Scope{
		{Name: "openid", Label: "Login", Description: "Identify account", Kind: "PROTOCOL", Enabled: true},
		{Name: "email", Label: "Email", Description: "Read login email", Kind: "PROTOCOL", Enabled: true},
		{Name: "data.read", Label: "Data", Description: "Read resource", Kind: "RESOURCE", Audience: "resource", Enabled: true},
	}}}
	store.state.interaction = d.Interaction{ID: "interaction", CSRFHash: crypto.Digest("csrf", "csrf"), Status: "PENDING", Runtime: runtime, Request: d.AuthorizationRequest{ClientID: "client", Channel: "STABLE", Major: 1, Scopes: []string{"openid", "email"}, Prompt: "consent", RedirectURI: "https://client.example/callback", State: "state"}, ExpiresAt: now.Add(time.Minute)}
	service, err := New(store, consentApp{store: store}, crypto, Config{Issuer: "https://auth.example", SectorSuffix: "sectors.example"})
	if err != nil {
		t.Fatal(err)
	}
	service.now = func() time.Time { return now }
	view, err := service.View(t.Context(), "interaction", "csrf", "session")
	if err != nil {
		t.Fatal(err)
	}
	return service, store, view
}

func TestConsentPresentationChangesAreRequestLocal(t *testing.T) {
	for _, test := range []struct {
		name   string
		index  int
		reject bool
	}{
		{"requested text", 1, true}, {"unrelated text", 2, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			service, store, view := newConsentService(t)
			store.catalog.Scopes[test.index].Description += " corrected"
			store.catalog.Revision++
			_, err := service.Confirm(t.Context(), view.InteractionID, view.CSRF, view.PresentationID, "session", []string{"openid", "email"}, true)
			if test.reject {
				if !errors.Is(err, d.ErrConflict) || len(store.state.codes) != 0 || store.state.grant.ID != "" {
					t.Fatalf("stale view committed: %v", err)
				}
			} else if err != nil {
				t.Fatal(err)
			}
		})
	}
}
func TestConsentPresentationRequiresCurrentTabEvidence(t *testing.T) {
	for _, mode := range []string{"missing", "old tab", "legacy"} {
		t.Run(mode, func(t *testing.T) {
			service, store, view := newConsentService(t)
			presentation := view.PresentationID
			switch mode {
			case "missing":
				presentation = ""
			case "old tab":
				other, err := service.View(t.Context(), view.InteractionID, view.CSRF, "session")
				if err != nil || other.PresentationID == presentation {
					t.Fatal("view did not rotate evidence", err)
				}
			case "legacy":
				store.state.interaction.Presentation = nil
			}
			if _, err := service.Confirm(t.Context(), view.InteractionID, view.CSRF, presentation, "session", []string{"openid", "email"}, true); !errors.Is(err, d.ErrConflict) {
				t.Fatal("missing/current-tab evidence accepted", err)
			}
			if len(store.state.codes) != 0 || store.state.grant.ID != "" {
				t.Fatal("invalid confirmation wrote grant/code")
			}
		})
	}
}

func TestConsentPresentationScopeDisableIsInteractionChanged(t *testing.T) {
	service, store, view := newConsentService(t)
	store.catalog.Scopes[1].Enabled = false
	if _, err := service.Confirm(t.Context(), view.InteractionID, view.CSRF, view.PresentationID, "session", []string{"openid", "email"}, true); !errors.Is(err, d.ErrConflict) {
		t.Fatal("changed scope bypassed stale-view protection", err)
	}
	if len(store.state.codes) != 0 || store.state.grant.ID != "" || store.state.interaction.Status != "PENDING" {
		t.Fatal("scope disable committed an authorization decision")
	}
}

func TestConsentPresentationAuditAndRollback(t *testing.T) {
	service, store, view := newConsentService(t)
	store.failAudit = true
	if _, err := service.Confirm(t.Context(), view.InteractionID, view.CSRF, view.PresentationID, "session", []string{"openid", "email"}, true); !errors.Is(err, d.ErrUnavailable) {
		t.Fatal(err)
	}
	if store.state.interaction.Status != "PENDING" || store.state.grant.ID != "" || len(store.state.codes) != 0 {
		t.Fatal("audit failure did not roll back")
	}
	store.failAudit = false
	if _, err := service.Confirm(t.Context(), view.InteractionID, view.CSRF, view.PresentationID, "session", []string{"openid", "email"}, true); err != nil {
		t.Fatal(err)
	}
	audit := store.state.audits[0]
	if audit.ConsentSource != "EXPLICIT" || audit.Presentation == nil || audit.Presentation.ID != view.PresentationID || !audit.Presentation.Valid([]string{"openid", "email"}) || len(audit.Presentation.Definitions) != 2 {
		t.Fatalf("missing explicit display evidence: %+v", audit)
	}
	// The existing same-scope grant is reused without manufacturing evidence
	// that a newer definition was displayed to the user.
	store.state.interaction.Status = "PENDING"
	store.state.interaction.Request.Prompt = "none"
	store.catalog.Scopes[1].Description = "Corrected email wording"
	if result, err := service.View(t.Context(), view.InteractionID, view.CSRF, "session"); err != nil || result.Redirect == "" {
		t.Fatal("silent prior grant reuse failed", err)
	}
	audit = store.state.audits[1]
	if audit.ConsentSource != "PRIOR_GRANT_REUSE" || audit.ReusedGrantRevision != 1 || audit.Presentation != nil {
		t.Fatalf("silent reuse fabricated display: %+v", audit)
	}
}
