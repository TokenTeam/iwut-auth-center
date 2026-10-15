package usecase

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"github.com/google/uuid"
	auth "iwut-auth-center/internal/authentication/domain"
	ap "iwut-auth-center/internal/authentication/port"
	d "iwut-auth-center/internal/campuscertification/domain"
	"iwut-auth-center/internal/campuscertification/port"
	"testing"
	"time"
)

type fakeCampusRepo struct {
	session                   auth.Session
	op                        port.Operation
	beginCount, completeCount int
	checkErr                  error
	missing                   bool
}

func (r *fakeCampusRepo) CheckSession(context.Context, []byte, time.Time) (auth.Session, error) {
	return r.session, r.checkErr
}
func (r *fakeCampusRepo) Begin(_ context.Context, op port.Operation, _ []byte, _ string, _ time.Time) (port.Operation, bool, error) {
	r.beginCount++
	if r.op.Proof.OperationID != "" {
		return r.op, false, nil
	}
	r.op = op
	return op, true, nil
}
func (r *fakeCampusRepo) Get(context.Context, string) (port.Operation, error) { return r.op, nil }
func (r *fakeCampusRepo) Complete(_ context.Context, op port.Operation, _ []byte, now time.Time) (d.Certification, error) {
	r.completeCount++
	return d.Certification{Institution: d.Institution, CertifiedAt: now}, nil
}
func (r *fakeCampusRepo) Own(context.Context, []byte, time.Time) (d.Certification, error) {
	if r.missing {
		return d.Certification{}, d.ErrNotFound
	}
	return d.Certification{}, d.ErrUnavailable
}

type fakeCampusSender struct {
	count int
	fail  bool
}

type fakeCampusDevice struct{ ap.DeviceProtocol }

func (fakeCampusDevice) NewID() (string, error) { return uuid.NewString(), nil }

type fakeCampusProtocol struct{}

func (fakeCampusProtocol) KeyID() string { return "campus-key" }
func (fakeCampusProtocol) ValidID(id string) bool {
	parsed, err := uuid.Parse(id)
	return err == nil && parsed.Version() == 4 && parsed.String() == id
}
func (fakeCampusProtocol) RequestMAC(b d.Begin, authID string, revision int64) []byte {
	sum := sha256.Sum256([]byte(fmt.Sprintf("%s|%s|%s|%d", b.RequestID, b.Email, authID, revision)))
	return sum[:]
}
func (fakeCampusProtocol) CodeMAC(op port.Operation, code string) []byte {
	sum := sha256.Sum256([]byte(op.Proof.OperationID + "|" + code))
	return sum[:]
}
func (fakeCampusProtocol) NewCode() (string, error) { return "00005678", nil }

type fakeCampusLimiter struct{}

func (fakeCampusLimiter) AllowBegin(string, time.Time) bool    { return true }
func (fakeCampusLimiter) AllowComplete(string, time.Time) bool { return true }
func (fakeCampusLimiter) AllowLocator(string, time.Time) bool  { return true }

type deniedCampusReadLimiter struct{ fakeCampusLimiter }

func (deniedCampusReadLimiter) AllowComplete(string, time.Time) bool { return false }

func (s *fakeCampusSender) Send(context.Context, string, string, string, time.Time) error {
	s.count++
	if s.fail {
		return errors.New("SMTP failure")
	}
	return nil
}
func campusTestService(t *testing.T) (*Service, *fakeCampusRepo, *fakeCampusSender, []byte) {
	t.Helper()
	device := fakeCampusDevice{}
	p := fakeCampusProtocol{}
	repo := &fakeCampusRepo{session: auth.Session{AuthID: "auth-one", AccountRevision: 1}}
	sender := &fakeCampusSender{}
	limiter := fakeCampusLimiter{}
	service, err := New(repo, p, device, sender, limiter, "test-auth")
	if err != nil {
		t.Fatal(err)
	}
	service.now = func() time.Time { return time.UnixMilli(1791799200000) }
	return service, repo, sender, bytes.Repeat([]byte{1}, 32)
}
func TestCampusBeginNormalizationAndIndependentPurpose(t *testing.T) {
	u, r, s, digest := campusTestService(t)
	b := d.Begin{RequestID: uuid.NewString(), Email: " User+Tag@WHUT.EDU.CN ", Source: "socket-peer"}
	op, err := u.Begin(t.Context(), b, digest)
	if err != nil || op.Email != "user+tag@whut.edu.cn" || op.Proof.Purpose != d.Purpose || op.Proof.AccountRevision != 1 || op.Proof.AuthID != "auth-one" || op.Proof.ExpiresAt.Sub(op.Proof.CreatedAt) != 10*time.Minute {
		t.Fatal(op, err)
	}
	if _, err = u.Begin(t.Context(), b, digest); err != nil || s.count != 1 || r.beginCount != 2 {
		t.Fatal("idempotent delivery", err)
	}
	for _, bad := range []string{"name@sub.whut.edu.cn", "name@whut.edu.cn.evil.test", "name@example.test", "name@whut.edu.cn\n"} {
		if _, err = u.Begin(t.Context(), d.Begin{RequestID: uuid.NewString(), Email: bad}, digest); !errors.Is(err, d.ErrInvalid) {
			t.Fatal("bad campus accepted", bad, err)
		}
	}
	if _, err = u.Begin(t.Context(), b, nil); !errors.Is(err, d.ErrSession) {
		t.Fatal("missing Session", err)
	}
}
func TestCampusCompleteRejectsTamperedSnapshotsAndOtherAccount(t *testing.T) {
	u, r, _, digest := campusTestService(t)
	op, err := u.Begin(t.Context(), d.Begin{RequestID: uuid.NewString(), Email: "name@whut.edu.cn"}, digest)
	if err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*port.Operation){func(op *port.Operation) { op.Email = "other@whut.edu.cn" }, func(op *port.Operation) { op.Proof.Purpose = "BIND_EMAIL" }, func(op *port.Operation) { op.Proof.ServiceID = "other-auth" }, func(op *port.Operation) { op.Proof.ApplicationID = "other-app" }, func(op *port.Operation) { op.Proof.AccountRevision = 2 }, func(op *port.Operation) { op.KeyID = "old-key" }} {
		r.op = op
		mutate(&r.op)
		if _, err = u.Complete(t.Context(), op.Proof.OperationID, "00005678", digest); !errors.Is(err, d.ErrVerification) {
			t.Fatal("tampered operation accepted", err)
		}
	}
	r.op = op
	r.session.AuthID = "other-account"
	if _, err = u.Complete(t.Context(), op.Proof.OperationID, "00005678", digest); !errors.Is(err, d.ErrVerification) {
		t.Fatal("another account completed", err)
	}
	if r.completeCount != 0 {
		t.Fatal("rejected proof reached commit")
	}
	r.session.AuthID = "auth-one"
	if _, err = u.Complete(t.Context(), op.Proof.OperationID, "00005678", digest); err != nil || r.completeCount != 1 {
		t.Fatal("valid completion rejected", err)
	}
}
func TestCampusOwnDistinguishesAbsenceFromFailure(t *testing.T) {
	u, r, _, digest := campusTestService(t)
	if _, err := u.Own(t.Context(), digest); !errors.Is(err, d.ErrUnavailable) {
		t.Fatal("dependency failure treated absent", err)
	}
	r.missing = true
	if fact, err := u.Own(t.Context(), digest); err != nil || fact.Valid() {
		t.Fatal("absent fact query", fact, err)
	}
}

func TestCampusOwnReadAdmissionIsBounded(t *testing.T) {
	u, _, _, digest := campusTestService(t)
	u.limiter = deniedCampusReadLimiter{}
	if _, err := u.Own(t.Context(), digest); !errors.Is(err, d.ErrRate) {
		t.Fatalf("unbounded own read: %v", err)
	}
}
