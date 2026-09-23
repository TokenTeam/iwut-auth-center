package usecase

import (
	"context"
	"errors"
	"iwut-auth-center/internal/identity/domain"
	"testing"
	"time"
)

type repositoryFunc func(context.Context, []byte, func(domain.Snapshot, time.Time) error) error

func (f repositoryFunc) WithSession(c context.Context, d []byte, p func(domain.Snapshot, time.Time) error) error {
	return f(c, d, p)
}

type signerFunc func(context.Context, domain.Claims) (string, error)

func (f signerFunc) Sign(c context.Context, v domain.Claims) (string, error) { return f(c, v) }
func TestIssueRechecksRetriesAndNeverReleasesUnconfirmedCandidate(t *testing.T) {
	protocol := testTokens{}
	token := "valid"
	now := time.Now().Truncate(time.Second)
	snapshot := domain.Snapshot{AuthID: "user", PermissionRevision: 1, Permissions: []string{"app.version.review", "auth.reviewer.manage"}, DeveloperStatus: "APPROVED", SessionExpiresAt: now.Add(45 * time.Second)}
	var claims []domain.Claims
	signer := signerFunc(func(_ context.Context, c domain.Claims) (string, error) {
		claims = append(claims, c)
		return "header.payload.signature", nil
	})
	for _, failure := range []error{nil, domain.ErrUnavailable, context.DeadlineExceeded} {
		calls := 0
		repo := repositoryFunc(func(_ context.Context, _ []byte, p func(domain.Snapshot, time.Time) error) error {
			calls++
			if err := p(snapshot, now); err != nil {
				return err
			}
			snapshot.Permissions = []string{}
			if err := p(snapshot, now.Add(time.Second)); err != nil {
				return err
			}
			return failure
		})
		service, _ := New(repo, signer, protocol, 60*time.Second)
		service.now = func() time.Time { return now }
		result, err := service.Issue(t.Context(), token, domain.AppAudience, []string{domain.AppAudience})
		if failure != nil {
			if !errors.Is(err, failure) || result.JWS != "" {
				t.Fatalf("candidate escaped %v %v", result, err)
			}
		} else {
			if err != nil || result.ExpiresAt != snapshot.SessionExpiresAt.Unix() {
				t.Fatalf("result %v %v", result, err)
			}
		}
		if calls != 1 {
			t.Fatal(calls)
		}
	}
	if c := claims[len(claims)-1]; c.Permissions == nil || len(c.Permissions) != 0 || c.DeveloperStatus != "APPROVED" || c.IssuedAt != now.Add(time.Second).Unix() {
		t.Fatal(c)
	}
	if claims[0].JTI != claims[1].JTI || claims[0].JTI != "ca944095-1a71-4213-8782-c37af418584c" {
		t.Fatal("jti must be UUID v4 per RPC")
	}
}
func TestIssueBoundariesAndFailure(t *testing.T) {
	protocol := testTokens{}
	token := "valid"
	now := time.Now().Truncate(time.Second)
	snapshot := domain.Snapshot{AuthID: "user", PermissionRevision: 1, SessionExpiresAt: now.Add(time.Minute)}
	called := false
	repo := repositoryFunc(func(_ context.Context, _ []byte, p func(domain.Snapshot, time.Time) error) error {
		called = true
		return p(snapshot, now)
	})
	signer := signerFunc(func(context.Context, domain.Claims) (string, error) { return "jws", nil })
	service, _ := New(repo, signer, protocol, time.Minute)
	service.now = func() time.Time { return now }
	for _, tc := range []struct {
		token, aud string
		allowed    []string
		want       error
	}{{token, "unknown", nil, domain.ErrInvalidRequest}, {token, domain.AuthAudience, nil, domain.ErrForbidden}, {"bad", domain.AuthAudience, []string{domain.AuthAudience}, domain.ErrSessionInvalid}} {
		called = false
		r, e := service.Issue(t.Context(), tc.token, tc.aud, tc.allowed)
		if !errors.Is(e, tc.want) || called || r.JWS != "" {
			t.Fatalf("%v %v", r, e)
		}
	}
	for _, ttl := range []time.Duration{0, 500 * time.Millisecond, 301 * time.Second, 1500 * time.Millisecond} {
		if _, err := New(repo, signer, protocol, ttl); err == nil {
			t.Fatal(ttl)
		}
	}
	for _, at := range []time.Time{now, now.Add(time.Second - time.Nanosecond)} {
		snapshot.SessionExpiresAt = at
		if r, e := service.Issue(t.Context(), token, domain.AuthAudience, []string{domain.AuthAudience}); !errors.Is(e, domain.ErrSessionInvalid) || r.JWS != "" {
			t.Fatal(r, e)
		}
	}
	snapshot.SessionExpiresAt = now.Add(time.Minute)
	service.now = func() time.Time { return now.Add(time.Minute) }
	if r, e := service.Issue(t.Context(), token, domain.AuthAudience, []string{domain.AuthAudience}); !errors.Is(e, domain.ErrSessionInvalid) || r.JWS != "" {
		t.Fatal(r, e)
	}
	service.now = func() time.Time { return now }
	service.signer = signerFunc(func(context.Context, domain.Claims) (string, error) { return "", errors.New("secret crypto failure") })
	if r, e := service.Issue(t.Context(), token, domain.AuthAudience, []string{domain.AuthAudience}); !errors.Is(e, domain.ErrUnavailable) || r.JWS != "" {
		t.Fatal(r, e)
	}
}

type testTokens struct{}

func (testTokens) TokenDigest(token string) ([]byte, error) {
	if token != "valid" {
		return nil, errors.New("invalid")
	}
	return make([]byte, 32), nil
}
func (testTokens) NewID() (string, error) { return "ca944095-1a71-4213-8782-c37af418584c", nil }
