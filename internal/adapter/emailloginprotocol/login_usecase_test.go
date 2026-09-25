package emailloginprotocol

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"testing"
	"time"

	"iwut-auth-center/internal/adapter/deviceprotocol"
	auth "iwut-auth-center/internal/authentication/domain"
	"iwut-auth-center/internal/emaillogin/domain"
	"iwut-auth-center/internal/emaillogin/port"
	"iwut-auth-center/internal/emaillogin/usecase"
)

type repositoryStub struct {
	op                    domain.Operation
	created               bool
	beginErr, completeErr error
	failures, commits     int
	candidate             port.Commit
}

func (r *repositoryStub) Begin(_ context.Context, op domain.Operation, _ string, _ time.Time) (domain.Operation, bool, error) {
	if r.beginErr != nil {
		return domain.Operation{}, false, r.beginErr
	}
	if r.op.OperationID == "" {
		r.op = op
		r.op.Eligible = true
		r.op.CredentialAcceptable = true
		r.op.AuthID = "existing-user"
		r.op.EmailBindingRevision = 3
		r.created = true
		return r.op, true, nil
	}
	return r.op, false, nil
}
func (r *repositoryStub) Get(context.Context, string) (domain.Operation, error) { return r.op, nil }
func (r *repositoryStub) Fail(context.Context, string, time.Time) error {
	r.failures++
	r.op.FailedAttempts++
	return nil
}
func (r *repositoryStub) Complete(_ context.Context, c port.Commit, _ time.Time) (string, error) {
	r.commits++
	r.candidate = c
	if r.completeErr != nil {
		return "", r.completeErr
	}
	r.op.Status = auth.Completed
	return c.Credential.CredentialID, nil
}

type senderStub struct {
	calls int
	code  string
	err   error
}

func (s *senderStub) Send(_ context.Context, _, purpose, code string, _ time.Time) error {
	s.calls++
	s.code = code
	if purpose != domain.Purpose {
		panic("wrong purpose")
	}
	return s.err
}
func loginFixture(t *testing.T) (*usecase.Login, *repositoryStub, *senderStub, *ecdsa.PrivateKey, domain.Begin) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	normalize := func(s string) (string, error) {
		if s != "student@example.test" {
			return "", domain.ErrInvalid
		}
		return s, nil
	}
	protocol, _ := New("test", make([]byte, 32), normalize)
	device, _ := deviceprotocol.New("test")
	limiter, _ := deviceprotocol.NewLimiter(deviceprotocol.DefaultRateLimits())
	repo := &repositoryStub{}
	sender := &senderStub{}
	login, err := usecase.New(repo, protocol, device, sender, limiter, "test", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	return login, repo, sender, key, domain.Begin{RequestID: "77777777-7777-4777-8777-000000000001", Email: "student@example.test", ProtocolVersion: auth.ProtocolVersion, PublicKey: elliptic.Marshal(elliptic.P256(), key.X, key.Y), Source: "test"}
}
func signed(t *testing.T, key *ecdsa.PrivateKey, payload []byte) []byte {
	t.Helper()
	digest := sha256.Sum256(payload)
	sig, err := ecdsa.SignASN1(rand.Reader, key, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	return sig
}
func TestLoginRequiresBothProofsAndReleasesOnlyConfirmedResult(t *testing.T) {
	u, r, s, key, b := loginFixture(t)
	ctx := t.Context()
	challenge, err := u.Begin(ctx, b)
	if err != nil {
		t.Fatal(err)
	}
	if challenge.ProtocolVersion != domain.ProtocolVersion || s.calls != 1 || r.op.AuthID != "existing-user" {
		t.Fatal("bad begin")
	}
	retry, err := u.Begin(ctx, b)
	if err != nil || retry.OperationID != challenge.OperationID || s.calls != 1 {
		t.Fatal("idempotent retry sent again", err)
	}
	sig := signed(t, key, challenge.SigningPayload)
	wrong := "00000000"
	if s.code == wrong {
		wrong = "00000001"
	}
	if _, err := u.Complete(ctx, challenge.OperationID, wrong, sig, "test"); !errors.Is(err, domain.ErrFailed) {
		t.Fatal(err)
	}
	if _, err := u.Complete(ctx, challenge.OperationID, s.code, signed(t, key, []byte("wrong context")), "test"); !errors.Is(err, domain.ErrFailed) {
		t.Fatal(err)
	}
	if r.failures != 2 || r.commits != 0 {
		t.Fatal("proof failures escaped counting")
	}
	r.completeErr = domain.ErrUnavailable
	result, err := u.Complete(ctx, challenge.OperationID, s.code, sig, "test")
	if !errors.Is(err, domain.ErrUnavailable) || result.SessionToken != "" {
		t.Fatal("uncertain commit leaked token")
	}
	r.completeErr = nil
	result, err = u.Complete(ctx, challenge.OperationID, s.code, sig, "test")
	if err != nil || result.AuthID != "existing-user" || result.SessionToken == "" {
		t.Fatal("complete", err)
	}
	if r.candidate.Credential.ProtocolVersion != auth.ProtocolVersion || r.candidate.Session.AuthenticationMethod != domain.AuthenticationMethod || r.candidate.Session.EmailBindingRevision != 3 {
		t.Fatal("provenance mismatch")
	}
	if _, err := u.Complete(ctx, challenge.OperationID, s.code, sig, "test"); !errors.Is(err, domain.ErrCompleted) {
		t.Fatal("replay", err)
	}
}
func TestFrozenEligibilityCredentialAndExpiry(t *testing.T) {
	for _, test := range []struct {
		name   string
		modify func(*repositoryStub, *usecase.Login)
		want   error
	}{
		{"placeholder", func(r *repositoryStub, _ *usecase.Login) { r.op.Eligible = false }, domain.ErrFailed},
		{"bad-credential", func(r *repositoryStub, _ *usecase.Login) { r.op.CredentialAcceptable = false }, domain.ErrCredential},
		{"missing-revision", func(r *repositoryStub, _ *usecase.Login) { r.op.EmailBindingRevision = 0 }, domain.ErrFailed},
		{"at-expiry", func(r *repositoryStub, u *usecase.Login) {
			r.op.ExpiresAt = time.Now().UTC().Truncate(time.Millisecond)
		}, domain.ErrFailed},
		{"rotation", func(r *repositoryStub, _ *usecase.Login) { r.op.KeyID = "old-key" }, domain.ErrFailed},
		{"five-errors", func(r *repositoryStub, _ *usecase.Login) { r.op.FailedAttempts = 5 }, domain.ErrFailed},
	} {
		t.Run(test.name, func(t *testing.T) {
			u, r, s, key, b := loginFixture(t)
			challenge, err := u.Begin(t.Context(), b)
			if err != nil {
				t.Fatal(err)
			}
			test.modify(r, u)
			result, err := u.Complete(t.Context(), challenge.OperationID, s.code, signed(t, key, challenge.SigningPayload), "test")
			if !errors.Is(err, test.want) || result.SessionToken != "" || r.commits != 0 {
				t.Fatal("invalid operation completed", err)
			}
		})
	}
}
func TestDeliveryFailureRetryDoesNotSendAgain(t *testing.T) {
	u, _, s, _, b := loginFixture(t)
	s.err = errors.New("private SMTP detail")
	if _, err := u.Begin(t.Context(), b); !errors.Is(err, domain.ErrDelivery) {
		t.Fatal(err)
	}
	if _, err := u.Begin(t.Context(), b); err != nil || s.calls != 1 {
		t.Fatal("delivery retry sent twice", err)
	}
}
