package mongo

import (
	"errors"
	"go.mongodb.org/mongo-driver/v2/bson"
	dd "iwut-auth-center/internal/developer/domain"
	dp "iwut-auth-center/internal/developer/port"
	id "iwut-auth-center/internal/identity/domain"
	od "iwut-auth-center/internal/oauth/domain"
	op "iwut-auth-center/internal/oauth/port"
	"testing"
	"time"
)

func TestDeveloperLifecycleMongoReadersRejectInconsistentRevisions(t *testing.T) {
	repo, db, session, _, _, _ := identityFixture(t)
	directory, _ := NewPrincipalRepository(db)
	oauth := NewOAuthRepository(repo.authentication, db)
	for _, tc := range []struct {
		name     string
		status   any
		revision any
		missing  bool
	}{
		{"missing", "APPROVED", nil, true},
		{"int32", "APPROVED", int32(1), false},
		{"zero activated", "APPROVED", int64(0), false},
		{"negative", "SUSPENDED", int64(-1), false},
		{"positive ordinary", nil, int64(1), false},
		{"unknown", "UNKNOWN", int64(1), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			update := bson.M{"$set": bson.M{"developerStatus": tc.status, "developerRevision": tc.revision}}
			if tc.missing {
				update = bson.M{"$set": bson.M{"developerStatus": tc.status}, "$unset": bson.M{"developerRevision": ""}}
			}
			if _, err := db.Collection(PrincipalCollection).UpdateOne(t.Context(), bson.M{"authId": session.AuthID}, update); err != nil {
				t.Fatal(err)
			}
			if _, err := directory.BatchGet(t.Context(), []dd.AuthID{dd.AuthID(session.AuthID)}); !errors.Is(err, dp.ErrDeveloperStatusUnavailable) {
				t.Fatalf("directory: %v", err)
			}
			signed := false
			if err := repo.WithSession(t.Context(), session.TokenDigest, func(id.Snapshot, time.Time) error { signed = true; return nil }); !errors.Is(err, id.ErrUnavailable) || signed {
				t.Fatalf("identity signed=%v: %v", signed, err)
			}
			if err := oauth.Transaction(t.Context(), func(tx op.Tx) error { _, err := tx.User(session.AuthID); return err }); !errors.Is(err, od.ErrUnavailable) {
				t.Fatalf("oauth: %v", err)
			}
		})
	}
	// An ordinary account is still a valid OAuth subject and directory record.
	if _, err := db.Collection(PrincipalCollection).UpdateOne(t.Context(), bson.M{"authId": session.AuthID}, bson.M{"$set": bson.M{"developerStatus": nil, "developerRevision": int64(0)}}); err != nil {
		t.Fatal(err)
	}
	if _, err := directory.BatchGet(t.Context(), []dd.AuthID{dd.AuthID(session.AuthID)}); err != nil {
		t.Fatal(err)
	}
	if err := repo.WithSession(t.Context(), session.TokenDigest, func(id.Snapshot, time.Time) error { return nil }); err != nil {
		t.Fatal(err)
	}
	if err := oauth.Transaction(t.Context(), func(tx op.Tx) error { _, err := tx.User(session.AuthID); return err }); err != nil {
		t.Fatal(err)
	}
}
