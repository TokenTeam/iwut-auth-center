package mongo

import (
	"context"
	"errors"
	"github.com/google/uuid"
	"go.mongodb.org/mongo-driver/v2/bson"
	m "go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
	"iwut-auth-center/internal/adapter/credentialprotocol"
	"iwut-auth-center/internal/adapter/sessionmanagementrate"
	ad "iwut-auth-center/internal/authentication/domain"
	ap "iwut-auth-center/internal/authentication/port"
	d "iwut-auth-center/internal/credentialmanagement/domain"
	uc "iwut-auth-center/internal/credentialmanagement/usecase"
	pp "iwut-auth-center/internal/password/port"
	pu "iwut-auth-center/internal/password/usecase"
	"math"
	"sync"
	"testing"
	"time"
)

type credentialFixture struct {
	passwordFixture
	repo     *CredentialManagementRepository
	service  *uc.Service
	protocol *credentialprotocol.Protocol
	digest   []byte
	session  ad.Established
	clock    time.Time
	verifier *pu.ReauthService
}

func newCredentialFixture(t *testing.T) *credentialFixture {
	t.Helper()
	f := attachPassword(t, newAuthenticationFixture(t, EnsurePasswordSchema, EnsurePasswordQuotaSchema, EnsureEmailAccountSchema, EnsureCredentialManagementSchema))
	if err := EnsureCredentialManagementSchema(t.Context(), f.r.database); err != nil {
		t.Fatal(err)
	}
	protocol, _ := credentialprotocol.New("iwut-auth-center:test")
	repo, _ := NewCredentialManagementRepository(f.r, "iwut-auth-center:test")
	gate, _ := sessionmanagementrate.New(100000, 100000, 100000, 100000)
	verifier, _ := pu.NewReauth(f.repository, f.engine, f.quota)
	service, _ := uc.New(repo, protocol, verifier, gate, "iwut-auth-center:test")
	session := f.login(t)
	digest, _ := f.p.TokenDigest(session.SessionToken)
	out := &credentialFixture{f, repo, service, protocol, digest, session, time.Now().UTC().Truncate(time.Millisecond), verifier}
	f.r.clock = func() time.Time { return out.clock }
	service.SetClock(func() time.Time { return out.clock })
	verifier.SetClock(func() time.Time { return out.clock })
	return out
}
func (f *credentialFixture) target(t *testing.T) authenticationFixture {
	return secondaryCredential(t, f.authenticationFixture, f.c.AuthID)
}
func (f *credentialFixture) begin(t *testing.T, id string) d.Started {
	t.Helper()
	out, err := f.service.Begin(t.Context(), f.digest, uuid.NewString(), id)
	if err != nil {
		t.Fatal(err)
	}
	return out
}
func TestCredentialManagementListLabelCASAndNoTouch(t *testing.T) {
	f := newCredentialFixture(t)
	other := f.target(t)
	ctx := t.Context()
	var before SessionDocument
	if err := f.r.database.Collection(SessionCollection).FindOne(ctx, bson.M{"sessionId": f.session.SessionID}).Decode(&before); err != nil {
		t.Fatal(err)
	}
	page, err := f.service.List(ctx, f.digest, 50, "")
	if err != nil || len(page.Credentials) != 2 {
		t.Fatal(page, err)
	}
	current := 0
	for _, c := range page.Credentials {
		if c.IsCurrent {
			current++
		}
		if c.Label != "" || c.LabelRevision != 0 {
			t.Fatal(c)
		}
	}
	if current != 1 {
		t.Fatal("current marker")
	}
	label, err := f.service.SetLabel(ctx, f.digest, other.c.CredentialID, "  Laptop  ", 0)
	if err != nil || label.Label != "Laptop" || label.Revision != 1 {
		t.Fatal(label, err)
	}
	if _, err = f.service.SetLabel(ctx, f.digest, other.c.CredentialID, "Laptop", 0); !errors.Is(err, d.ErrLabelConflict) {
		t.Fatal("stale no-op", err)
	}
	if _, err = f.service.SetLabel(ctx, f.digest, other.c.CredentialID, "Laptop", 1); err != nil {
		t.Fatal(err)
	}
	count, err := f.r.database.Collection(CredentialManagementAuditCollection).CountDocuments(ctx, bson.M{})
	if err != nil || count != 1 {
		t.Fatal("no-op audited", count, err)
	}
	var after SessionDocument
	if err = f.r.database.Collection(SessionCollection).FindOne(ctx, bson.M{"sessionId": f.session.SessionID}).Decode(&after); err != nil || !after.LastUsedAt.Equal(before.LastUsedAt) || !after.ExpiresAt.Equal(before.ExpiresAt) {
		t.Fatal("LRU touched", err)
	}
	_, err = f.r.database.Collection(CredentialCollection).UpdateOne(ctx, bson.M{"credentialId": other.c.CredentialID}, bson.M{"$set": bson.M{"labelRevision": int64(math.MaxInt64)}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.service.SetLabel(ctx, f.digest, other.c.CredentialID, "new", math.MaxInt64); !errors.Is(err, d.ErrUnavailable) {
		t.Fatal("overflow", err)
	}
}
func TestCredentialManagementRevocationReplayAndOwnerIsolation(t *testing.T) {
	f := newCredentialFixture(t)
	target := f.target(t)
	targetSession := target.login(t)
	request := uuid.NewString()
	start, err := f.service.Begin(t.Context(), f.digest, request, target.c.CredentialID)
	if err != nil {
		t.Fatal(err)
	}
	again, err := f.service.Begin(t.Context(), f.digest, request, target.c.CredentialID)
	if err != nil || again.Operation.OperationID != start.Operation.OperationID {
		t.Fatal("Begin not idempotent", err)
	}
	if _, err = f.service.Begin(t.Context(), f.digest, request, f.c.CredentialID); !errors.Is(err, d.ErrCurrent) {
		t.Fatal(err)
	}
	third := f.target(t)
	if _, err = f.service.Begin(t.Context(), f.digest, request, third.c.CredentialID); !errors.Is(err, d.ErrConflict) {
		t.Fatal("same key different target", err)
	}
	alternate := f.login(t)
	alternateDigest, _ := f.p.TokenDigest(alternate.SessionToken)
	sig := signAuthentication(t, f.key, start.SigningPayload)
	if err = f.service.Complete(t.Context(), alternateDigest, start.Operation.OperationID, sig, initialPassword, "127.0.0.1"); !errors.Is(err, d.ErrProof) {
		t.Fatal("other Session authorized", err)
	}
	if err = f.service.Complete(t.Context(), f.digest, start.Operation.OperationID, sig, "wrong password", "127.0.0.1"); !errors.Is(err, d.ErrProof) {
		t.Fatal("wrong password", err)
	}
	if err = f.service.Complete(t.Context(), f.digest, start.Operation.OperationID, sig, initialPassword, "127.0.0.1"); err != nil {
		t.Fatal(err)
	}
	var first CredentialDocument
	if err = f.r.database.Collection(CredentialCollection).FindOne(t.Context(), bson.M{"credentialId": target.c.CredentialID}).Decode(&first); err != nil || first.RevokedAt == nil {
		t.Fatal(first, err)
	}
	if _, err = target.u.Check(t.Context(), targetSession.SessionToken); !errors.Is(err, ap.ErrSessionInvalid) {
		t.Fatal("target session survived", err)
	}
	f.clock = f.clock.Add(6 * time.Minute)
	differentDER := signAuthentication(t, f.key, start.SigningPayload)
	if err = f.service.Complete(t.Context(), f.digest, start.Operation.OperationID, differentDER, initialPassword, "127.0.0.1"); err != nil {
		t.Fatal("post-expiry completed replay failed", err)
	}
	count, _ := f.r.database.Collection(CredentialManagementAuditCollection).CountDocuments(t.Context(), bson.M{"action": "REVOKE_OTHER"})
	if count != 1 {
		t.Fatal("duplicate revoke audit", count)
	}
	var repeated CredentialDocument
	_ = f.r.database.Collection(CredentialCollection).FindOne(t.Context(), bson.M{"credentialId": target.c.CredentialID}).Decode(&repeated)
	if !repeated.RevokedAt.Equal(*first.RevokedAt) {
		t.Fatal("first time changed")
	}
	if _, err = f.service.Begin(t.Context(), f.digest, request, target.c.CredentialID); !errors.Is(err, d.ErrCompleted) {
		t.Fatal("completed Begin", err)
	}
}
func TestCredentialManagementSharedFiveFailureBudgetAndNoAuthorityConsumption(t *testing.T) {
	f := newCredentialFixture(t)
	target := f.target(t)
	op := f.begin(t, target.c.CredentialID)
	for i := 0; i < 5; i++ {
		key := f.key
		password := "wrong current password"
		if i%2 == 1 {
			key = target.key
			password = initialPassword
		}
		err := f.service.Complete(t.Context(), f.digest, op.Operation.OperationID, signAuthentication(t, key, op.SigningPayload), password, "127.0.0.1")
		if !errors.Is(err, d.ErrProof) {
			t.Fatal(i, err)
		}
	}
	if err := f.service.Complete(t.Context(), f.digest, op.Operation.OperationID, signAuthentication(t, f.key, op.SigningPayload), initialPassword, "127.0.0.1"); !errors.Is(err, d.ErrProof) {
		t.Fatal("exhausted accepted", err)
	}
	stored, err := f.repo.read(t.Context(), bson.M{"operationId": op.Operation.OperationID})
	if err != nil || stored.FailedAttempts != 5 || stored.Status != d.Failed {
		t.Fatal(stored, err)
	}
}
func TestCredentialManagementBoundedScanAndMetadataCorruption(t *testing.T) {
	f := newCredentialFixture(t)
	for i := 0; i < 201; i++ {
		other := secondaryCredential(t, f.authenticationFixture, f.c.AuthID)
		c := credentialDocument(other.c)
		c.RevokedAt = &f.clock
		c.CreatedAt = f.clock.Add(time.Duration(i+1) * time.Second)
		_, err := f.r.database.Collection(CredentialCollection).UpdateOne(t.Context(), bson.M{"credentialId": c.CredentialID}, bson.M{"$set": bson.M{"revokedAt": f.clock, "createdAt": c.CreatedAt}})
		if err != nil {
			t.Fatal(err)
		}
	}
	page, err := f.service.List(t.Context(), f.digest, 10, "")
	if err != nil || len(page.Credentials) != 0 || page.NextCursor == "" {
		t.Fatal("scan unbounded", page, err)
	}
	next, err := f.service.List(t.Context(), f.digest, 10, page.NextCursor)
	if err != nil || len(next.Credentials) != 1 || next.NextCursor != "" {
		t.Fatal(next, err)
	}
	target := f.target(t)
	_, err = f.r.database.Collection(CredentialCollection).UpdateOne(t.Context(), bson.M{"credentialId": target.c.CredentialID}, bson.M{"$unset": bson.M{"label": ""}, "$set": bson.M{"createdAt": f.clock.Add(1000 * time.Second)}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.service.List(t.Context(), f.digest, 50, ""); !errors.Is(err, d.ErrUnavailable) {
		t.Fatal("partial metadata accepted", err)
	}
}

type credentialPasswordVerifier func(context.Context, pp.ReauthRequest) (int64, error)

func (v credentialPasswordVerifier) VerifyPassword(ctx context.Context, in pp.ReauthRequest) (int64, error) {
	return v(ctx, in)
}
func TestCredentialManagementFinalPasswordFenceAndAuditRollback(t *testing.T) {
	for _, mode := range []string{"password-race", "audit-failure"} {
		t.Run(mode, func(t *testing.T) {
			f := newCredentialFixture(t)
			target := f.target(t)
			op := f.begin(t, target.c.CredentialID)
			sig := signAuthentication(t, f.key, op.SigningPayload)
			if mode == "password-race" {
				gate, _ := sessionmanagementrate.New(100000, 100000, 100000, 10000)
				f.service, _ = uc.New(f.repo, f.protocol, credentialPasswordVerifier(func(ctx context.Context, in pp.ReauthRequest) (int64, error) {
					revision, err := f.verifier.VerifyPassword(ctx, in)
					if err != nil {
						return revision, err
					}
					_, err = f.r.database.Collection(PasswordCollection).UpdateOne(ctx, bson.M{"authId": f.c.AuthID}, bson.M{"$inc": bson.M{"passwordRevision": int64(1)}})
					return revision, err
				}), gate, "iwut-auth-center:test")
				if err := f.service.Complete(t.Context(), f.digest, op.Operation.OperationID, sig, initialPassword, "127.0.0.1"); !errors.Is(err, d.ErrProof) {
					t.Fatal("stale password committed", err)
				}
			} else {
				if _, err := f.r.database.Collection(CredentialManagementAuditCollection).Indexes().CreateOne(t.Context(), auditRejectingIndex()); err != nil {
					t.Fatal(err)
				}
				if _, err := f.r.database.Collection(CredentialManagementAuditCollection).InsertOne(t.Context(), bson.M{"action": "REVOKE_OTHER"}); err != nil {
					t.Fatal(err)
				}
				if err := f.service.Complete(t.Context(), f.digest, op.Operation.OperationID, sig, initialPassword, "127.0.0.1"); !errors.Is(err, d.ErrUnavailable) {
					t.Fatal("audit failure committed", err)
				}
			}
			var targetDoc CredentialDocument
			_ = f.r.database.Collection(CredentialCollection).FindOne(t.Context(), bson.M{"credentialId": target.c.CredentialID}).Decode(&targetDoc)
			if targetDoc.RevokedAt != nil {
				t.Fatal("partial revocation")
			}
			stored, _ := f.repo.read(t.Context(), bson.M{"operationId": op.Operation.OperationID})
			if stored.Status != d.Pending {
				t.Fatal("partial operation")
			}
		})
	}
}
func TestCredentialManagementConcurrentComplete(t *testing.T) {
	f := newCredentialFixture(t)
	target := f.target(t)
	op := f.begin(t, target.c.CredentialID)
	sig := signAuthentication(t, f.key, op.SigningPayload)
	var wg sync.WaitGroup
	failures := make(chan error, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			failures <- f.service.Complete(t.Context(), f.digest, op.Operation.OperationID, sig, initialPassword, "127.0.0.1")
		}()
	}
	wg.Wait()
	close(failures)
	for err := range failures {
		if err != nil {
			t.Fatal(err)
		}
	}
	count, _ := f.r.database.Collection(CredentialManagementAuditCollection).CountDocuments(t.Context(), bson.M{"action": "REVOKE_OTHER"})
	if count != 1 {
		t.Fatal("double mutation", count)
	}
}
func TestCredentialManagementCapacityAndExpiredMaintenance(t *testing.T) {
	f := newCredentialFixture(t)
	target := f.target(t)
	for i := 0; i < 5; i++ {
		f.begin(t, target.c.CredentialID)
	}
	if _, err := f.service.Begin(t.Context(), f.digest, uuid.NewString(), target.c.CredentialID); !errors.Is(err, d.ErrRate) {
		t.Fatal("owner cap", err)
	}
	f.clock = f.clock.Add(24 * time.Hour)
	if err := f.repo.Tick(t.Context()); err != nil {
		t.Fatal(err)
	}
	count, _ := f.r.database.Collection(CredentialManagementOperationCollection).CountDocuments(t.Context(), bson.M{})
	if count != 0 {
		t.Fatal("expired operations retained", count)
	}
}

func auditRejectingIndex() m.IndexModel {
	return m.IndexModel{Keys: bson.D{{Key: "action", Value: 1}}, Options: options.Index().SetUnique(true).SetName("fixture_action_unique")}
}

func TestCredentialManagementGlobalPendingCapIncludesItsCollection(t *testing.T) {
	f := newCredentialFixture(t)
	target := f.target(t)
	// Admission-only fixture records, never passed to a proof command.
	rows := make([]any, 10000)
	for i := range rows {
		rows[i] = bson.M{"operationId": uuid.NewString(), "requestId": uuid.NewString(), "authId": "other", "status": d.Pending, "expiresAt": f.clock.Add(time.Minute), "retainUntil": f.clock.Add(time.Hour)}
	}
	if _, err := f.r.database.Collection(CredentialManagementOperationCollection).InsertMany(t.Context(), rows); err != nil {
		t.Fatal(err)
	}
	if _, err := f.service.Begin(t.Context(), f.digest, uuid.NewString(), target.c.CredentialID); !errors.Is(err, d.ErrRate) {
		t.Fatal("global pending cap bypassed", err)
	}
	count, err := f.r.database.Collection(CredentialManagementOperationCollection).CountDocuments(t.Context(), bson.M{})
	if err != nil || count != 10000 {
		t.Fatal("admission evicted live records", count, err)
	}
}

func TestCredentialManagementConcurrentLabelCASHasOneAudit(t *testing.T) {
	f := newCredentialFixture(t)
	target := f.target(t)
	results := make(chan error, 2)
	var wg sync.WaitGroup
	for _, label := range []string{"Laptop", "Phone"} {
		wg.Add(1)
		go func(label string) {
			defer wg.Done()
			_, err := f.service.SetLabel(t.Context(), f.digest, target.c.CredentialID, label, 0)
			results <- err
		}(label)
	}
	wg.Wait()
	close(results)
	successes, conflicts := 0, 0
	for err := range results {
		if err == nil {
			successes++
		} else if errors.Is(err, d.ErrLabelConflict) {
			conflicts++
		} else {
			t.Fatal(err)
		}
	}
	count, err := f.r.database.Collection(CredentialManagementAuditCollection).CountDocuments(t.Context(), bson.M{"action": "SET_LABEL"})
	if err != nil || successes != 1 || conflicts != 1 || count != 1 {
		t.Fatal(successes, conflicts, count, err)
	}
}
