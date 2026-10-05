package mongo

import (
	"context"
	"errors"
	"github.com/google/uuid"
	"go.mongodb.org/mongo-driver/v2/bson"
	m "go.mongodb.org/mongo-driver/v2/mongo"
	d "iwut-auth-center/internal/developerwithdrawal/domain"
	o "iwut-auth-center/internal/ownerexit/domain"
	"sync"
	"testing"
	"time"
)

func withdrawalFixture(t *testing.T) (*DeveloperWithdrawalRepository, *m.Database, SessionDocument) {
	t.Helper()
	app, db, session := developerFixture(t)
	if _, e := app.Evaluate(t.Context(), session.TokenDigest, developerApply); e != nil {
		t.Fatal(e)
	}
	if _, e := db.Collection(PrincipalCollection).UpdateOne(t.Context(), bson.M{"authId": session.AuthID}, bson.M{"$set": bson.M{"developerRevision": int64(1)}}); e != nil {
		t.Fatal(e)
	}
	if e := EnsureDeveloperWithdrawalSchema(t.Context(), db); e != nil {
		t.Fatal(e)
	}
	return NewDeveloperWithdrawalRepository(app.authentication), db, session
}
func prepareWithdrawal(t *testing.T, r *DeveloperWithdrawalRepository, s SessionDocument) (o.Operation, time.Time) {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Millisecond)
	op, e := r.Prepare(t.Context(), s.TokenDigest, uuid.NewString(), uuid.NewString(), 1, now)
	if e != nil {
		t.Fatal(e)
	}
	return op, now
}
func bindWithdrawal(t *testing.T, r *DeveloperWithdrawalRepository, op o.Operation, now time.Time) o.Operation {
	t.Helper()
	receipt, _ := uuid.NewV7()
	e := r.auth.WithAuthTransaction(t.Context(), func(tx context.Context) error {
		var e error
		op, e = r.auth.BindOwnerExitPreparationTx(tx, op.AuthID, op.OperationID, receipt.String(), "", now)
		return e
	})
	if e != nil {
		t.Fatal(e)
	}
	return op
}
func TestDeveloperWithdrawalMongoCommitReplayAndPreservation(t *testing.T) {
	r, db, s := withdrawalFixture(t)
	op, now := prepareWithdrawal(t, r, s)
	if _, e := r.Confirm(t.Context(), s.TokenDigest, op.OperationID, now); !errors.Is(e, d.ErrConflict) {
		t.Fatal(e)
	}
	op = bindWithdrawal(t, r, op, now)
	result, e := r.Read(t.Context(), s.TokenDigest, op.OperationID, now.Add(time.Second))
	if e != nil || result.State != "READY" {
		t.Fatal(result, e)
	}
	var before SessionDocument
	if e = db.Collection(SessionCollection).FindOne(t.Context(), bson.M{"sessionId": s.SessionID}).Decode(&before); e != nil {
		t.Fatal(e)
	}
	if _, e = r.Read(t.Context(), s.TokenDigest, op.OperationID, now.Add(2*time.Second)); e != nil {
		t.Fatal(e)
	}
	var after SessionDocument
	_ = db.Collection(SessionCollection).FindOne(t.Context(), bson.M{"sessionId": s.SessionID}).Decode(&after)
	if !before.LastUsedAt.Equal(after.LastUsedAt) {
		t.Fatal("read touched session")
	}
	var wg sync.WaitGroup
	for range 5 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			out, e := r.Confirm(t.Context(), s.TokenDigest, op.OperationID, now.Add(3*time.Second))
			if e != nil || out.State != "COMPLETED" || out.DeveloperStatus != "WITHDRAWN" || out.DeveloperRevision != 2 {
				t.Error(out, e)
			}
		}()
	}
	wg.Wait()
	if n, e := db.Collection("auth_developer_lifecycle_audit_events").CountDocuments(t.Context(), bson.M{}); e != nil || n != 1 {
		t.Fatal(n, e)
	}
	var principal bson.M
	_ = db.Collection(PrincipalCollection).FindOne(t.Context(), bson.M{"authId": s.AuthID}).Decode(&principal)
	if principal["accountRevision"] != int64(1) || principal["permissionRevision"] != int64(5) || principal["associationGroupId"] != "kept" {
		t.Fatal(principal)
	}
	if n, _ := db.Collection(DeveloperHandleCollection).CountDocuments(t.Context(), bson.M{"authId": s.AuthID}); n != 1 {
		t.Fatal("handle released")
	}
	if _, e := r.Authenticate(t.Context(), s.TokenDigest, now.Add(time.Second)); e != nil {
		t.Fatal("ordinary session revoked", e)
	}
	if _, e := r.Cancel(t.Context(), s.TokenDigest, op.OperationID, now); !errors.Is(e, d.ErrConflict) {
		t.Fatal(e)
	}
	replay, e := r.Prepare(t.Context(), s.TokenDigest, op.RequestID, uuid.NewString(), 1, now)
	if e != nil || replay.Decision != o.Committed || replay.OperationID != op.OperationID {
		t.Fatal(replay, e)
	}
	decision, e := NewOwnerExitRepository(r.auth).Get(t.Context(), s.AuthID, op.OperationID)
	if e != nil || decision.Decision != o.Committed || !decision.NotificationPending {
		t.Fatal(decision, e)
	}
}
func TestDeveloperWithdrawalMongoCancellationAndInvalidation(t *testing.T) {
	for _, reason := range []string{"expiry", "revoked session", "developer revision", "permission revision"} {
		t.Run(reason, func(t *testing.T) {
			r, db, s := withdrawalFixture(t)
			op, now := prepareWithdrawal(t, r, s)
			op = bindWithdrawal(t, r, op, now)
			switch reason {
			case "expiry":
				now = now.Add(11 * time.Minute)
			case "revoked session":
				_, _ = db.Collection(SessionCollection).UpdateOne(t.Context(), bson.M{"sessionId": s.SessionID}, bson.M{"$set": bson.M{"revokedAt": now}})
			case "developer revision":
				_, _ = db.Collection(PrincipalCollection).UpdateOne(t.Context(), bson.M{"authId": s.AuthID}, bson.M{"$inc": bson.M{"developerRevision": int64(1)}})
			case "permission revision":
				_, _ = db.Collection(PrincipalCollection).UpdateOne(t.Context(), bson.M{"authId": s.AuthID}, bson.M{"$inc": bson.M{"permissionRevision": int64(1)}})
			}
			if _, e := NewOwnerExitRepository(r.auth).Due(t.Context(), now.Add(time.Second), 100); e != nil {
				t.Fatal(e)
			}
			op, e := NewOwnerExitRepository(r.auth).Get(t.Context(), s.AuthID, op.OperationID)
			if e != nil || op.Decision != o.Cancelled || !op.NotificationPending {
				t.Fatal(op, e)
			}
		})
	}
}
func TestOwnerExitMongoSharedPendingAndBlockedRelease(t *testing.T) {
	r, _, s := withdrawalFixture(t)
	op, now := prepareWithdrawal(t, r, s)
	other := op
	other.OperationID = uuid.NewString()
	other.RequestID = ""
	other.Purpose = o.Closure
	e := r.auth.WithAuthTransaction(t.Context(), func(tx context.Context) error {
		_, e := r.auth.CreateOwnerExitTx(tx, other)
		if !errors.Is(e, o.ErrConflict) {
			t.Fatal(e)
		}
		return nil
	})
	if e != nil {
		t.Fatal(e)
	}
	bound, e := NewOwnerExitRepository(r.auth).BindPreparation(t.Context(), s.AuthID, op.OperationID, o.Preparation{Blocker: "OWNED_APPLICATIONS"}, now)
	if e != nil || bound.Decision != o.Cancelled || bound.ReceiptID != "" {
		t.Fatal(bound, e)
	}
	if _, e := r.Prepare(t.Context(), s.TokenDigest, uuid.NewString(), uuid.NewString(), 1, now); e != nil {
		t.Fatal("blocked pending not released", e)
	}
	if _, e := r.Prepare(t.Context(), s.TokenDigest, op.RequestID, uuid.NewString(), 2, now); !errors.Is(e, d.ErrConflict) {
		t.Fatal(e)
	}
}
