package usecase

import (
	"context"
	"encoding/asn1"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/google/uuid"
	d "iwut-auth-center/internal/applicationclosereauth/domain"
	pd "iwut-auth-center/internal/password/domain"
	pp "iwut-auth-center/internal/password/port"
)

type reauthRepositoryStub struct {
	op        d.Operation
	failErr   error
	fails     int
	completes int
}

func (r *reauthRepositoryStub) Begin(_ context.Context, _ []byte, app, id string, challenge []byte, now, expires time.Time) (d.Operation, error) {
	r.op = d.Operation{OperationID: id, AuthID: "auth-1", SessionID: uuid.NewString(), CredentialID: uuid.NewString(), ApplicationID: app, Challenge: challenge, PublicKey: make([]byte, 65), AccountRevision: 1, PasswordRevision: 1, State: d.Pending, CreatedAt: now, ExpiresAt: expires}
	return r.op, nil
}
func (r *reauthRepositoryStub) ReadForComplete(context.Context, []byte, string, string, time.Time) (d.Operation, error) {
	return r.op, nil
}
func (r *reauthRepositoryStub) Complete(_ context.Context, _ []byte, _, _ string, digest []byte, _ int64, claims d.Claims, _ time.Time) (d.Operation, error) {
	r.completes++
	if r.op.State == d.Completed {
		return r.op, nil
	}
	r.op.State, r.op.SignatureDigest, r.op.JTI = d.Completed, append([]byte(nil), digest...), claims.JTI
	r.op.AuthTime, r.op.IssuedAt, r.op.NotBefore, r.op.ProofExpiresAt = claims.AuthTime, claims.IssuedAt, claims.NotBefore, claims.ExpiresAt
	return r.op, nil
}
func (r *reauthRepositoryStub) Fail(context.Context, string, time.Time) error {
	r.fails++
	return r.failErr
}

type reauthProtocolStub struct {
	id        string
	challenge []byte
	valid     bool
}

func (p reauthProtocolStub) RandomBytes(int) ([]byte, error) {
	return append([]byte(nil), p.challenge...), nil
}
func (p reauthProtocolStub) NewID() (string, error) { return p.id, nil }
func (p reauthProtocolStub) Verify([]byte, []byte, []byte) bool {
	return p.valid
}

type reauthSignerStub struct{ calls int }

func (s *reauthSignerStub) Sign(_ context.Context, claims d.Claims) (string, error) {
	s.calls++
	return claims.JTI + ":" + claims.ExpiresAt.Format(time.RFC3339), nil
}

func validTestSignature(t *testing.T) []byte {
	t.Helper()
	raw, err := asn1.Marshal(struct{ R, S *big.Int }{big.NewInt(1), big.NewInt(1)})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestCompleteFixesFiveMinuteProofAndRetriesSameClaims(t *testing.T) {
	operationID := uuid.NewString()
	applicationID := uuid.NewString()
	now := time.Date(2026, 10, 6, 1, 2, 3, 456000000, time.UTC)
	repository := &reauthRepositoryStub{op: d.Operation{OperationID: operationID, AuthID: "auth-1", SessionID: uuid.NewString(), CredentialID: uuid.NewString(), ApplicationID: applicationID, Challenge: make([]byte, 32), PublicKey: make([]byte, 65), AccountRevision: 1, PasswordRevision: 1, State: d.Pending, CreatedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Minute)}}
	signer := &reauthSignerStub{}
	service, err := New(repository, reauthProtocolStub{valid: true}, signer, "https://auth.example.test", passwordVerifierStub{})
	if err != nil {
		t.Fatal(err)
	}
	service.clock = func() time.Time { return now }
	wantJTI := uuid.MustParse("0199b891-e780-7000-8000-000000000001")
	service.newJTI = func() (uuid.UUID, error) { return wantJTI, nil }
	signature := validTestSignature(t)
	first, err := service.Complete(t.Context(), make([]byte, 32), operationID, applicationID, signature, "test password", "source")
	if err != nil {
		t.Fatal(err)
	}
	service.clock = func() time.Time { return now.Add(30 * time.Second) }
	second, err := service.Complete(t.Context(), make([]byte, 32), operationID, applicationID, signature, "test password", "source")
	if err != nil || second != first {
		t.Fatalf("retry = %#v, %v; first = %#v", second, err, first)
	}
	if repository.op.JTI != wantJTI.String() || !repository.op.AuthTime.Equal(time.Unix(now.Unix(), 0).UTC()) || !repository.op.ProofExpiresAt.Equal(repository.op.AuthTime.Add(5*time.Minute)) || !repository.op.NotBefore.Equal(repository.op.AuthTime.Add(-30*time.Second)) {
		t.Fatalf("fixed claims = %#v", repository.op)
	}
	if signer.calls != 2 {
		t.Fatalf("sign calls = %d", signer.calls)
	}
	if repository.completes != 2 {
		t.Fatal("completed replay skipped the final transaction")
	}
	service.password = passwordVerifierStub{err: pd.ErrAuthentication}
	if _, err = service.Complete(t.Context(), make([]byte, 32), operationID, applicationID, signature, "wrong current password", "source"); !errors.Is(err, d.ErrFailed) || signer.calls != 2 || repository.completes != 2 {
		t.Fatal("replay without password authority", err)
	}
}

func TestCompleteFailsClosedWhenFailureCounterCannotPersist(t *testing.T) {
	id, app := uuid.NewString(), uuid.NewString()
	repository := &reauthRepositoryStub{op: d.Operation{OperationID: id, AuthID: "auth-1", ApplicationID: app, Challenge: make([]byte, 32), PublicKey: make([]byte, 65), State: d.Pending}, failErr: d.ErrUnavailable}
	service, err := New(repository, reauthProtocolStub{valid: false}, &reauthSignerStub{}, "issuer", passwordVerifierStub{})
	if err != nil {
		t.Fatal(err)
	}
	_, err = service.Complete(t.Context(), make([]byte, 32), id, app, validTestSignature(t), "test password", "source")
	if !errors.Is(err, d.ErrUnavailable) || repository.fails != 1 {
		t.Fatalf("Complete() = %v, failures = %d", err, repository.fails)
	}
}

func TestSigningPayloadBindsDomainOperationApplicationAndChallenge(t *testing.T) {
	id, app := uuid.NewString(), uuid.NewString()
	challenge := make([]byte, 32)
	challenge[31] = 1
	payload, err := SigningPayload(id, app, challenge)
	if err != nil {
		t.Fatal(err)
	}
	changed := append([]byte(nil), challenge...)
	changed[31] = 2
	other, err := SigningPayload(id, app, changed)
	if err != nil {
		t.Fatal(err)
	}
	if string(payload) == string(other) || len(payload) != 149 {
		t.Fatalf("payload binding/length invalid: %d", len(payload))
	}
}

type passwordVerifierStub struct {
	err      error
	revision int64
}

func (p passwordVerifierStub) VerifyPassword(context.Context, pp.ReauthRequest) (int64, error) {
	if p.err != nil {
		return 0, p.err
	}
	if p.revision > 0 {
		return p.revision, nil
	}
	return 1, nil
}
