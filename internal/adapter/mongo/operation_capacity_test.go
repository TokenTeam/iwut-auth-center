package mongo

import (
	"context"
	"errors"
	"go.mongodb.org/mongo-driver/v2/bson"
	auth "iwut-auth-center/internal/authentication/domain"
	port "iwut-auth-center/internal/authentication/port"
	"testing"
	"time"
)

func TestOperationCapacityIsSharedAcrossPurposeCollections(t *testing.T) {
	f := newAuthenticationFixture(t)
	now := time.Now().UTC().Truncate(time.Millisecond)
	// Isolated admission fixtures intentionally exercise only fields counted by
	// the fence; no synthetic operation is sent to a production command.
	for _, name := range []string{AuthenticationOperationCollection, EmailAccountOperationCollection} {
		if _, err := f.r.database.Collection(name).InsertOne(t.Context(), bson.M{"operationId": name, "status": auth.Pending, "expiresAt": now.Add(time.Minute), "retainUntil": now.Add(time.Hour), "purgeAfter": now.Add(time.Hour)}); err != nil {
			t.Fatal(err)
		}
	}
	err := f.r.WithAuthTransaction(t.Context(), func(tx context.Context) error { return sharedOperationCapacityTx(tx, f.r.database, now, 2, true) })
	if !errors.Is(err, port.ErrLimitExceeded) {
		t.Fatalf("separate collection bypassed global pending cap: %v", err)
	}
}

func TestOperationCapacityCleanupIsBoundedAndNeverEvictsLive(t *testing.T) {
	f := newAuthenticationFixture(t)
	now := time.Now().UTC().Truncate(time.Millisecond)
	rows := make([]any, 130)
	for i := range rows {
		rows[i] = bson.M{"retainUntil": now.Add(-time.Minute)}
	}
	if _, err := f.r.database.Collection(EmailAccountMutationCollection).InsertMany(t.Context(), rows); err != nil {
		t.Fatal(err)
	}
	if _, err := f.r.database.Collection(EmailAccountMutationCollection).InsertOne(t.Context(), bson.M{"retainUntil": now.Add(time.Hour), "live": true}); err != nil {
		t.Fatal(err)
	}
	if err := f.r.WithAuthTransaction(t.Context(), func(tx context.Context) error { return sharedOperationCapacityTx(tx, f.r.database, now, 10000, false) }); err != nil {
		t.Fatal(err)
	}
	count, err := f.r.database.Collection(EmailAccountMutationCollection).CountDocuments(t.Context(), bson.M{})
	if err != nil || count != 67 {
		t.Fatalf("cleanup must drain at most 64: %d %v", count, err)
	}
	if count, err = f.r.database.Collection(EmailAccountMutationCollection).CountDocuments(t.Context(), bson.M{"live": true}); err != nil || count != 1 {
		t.Fatal("live row evicted", count, err)
	}
}
