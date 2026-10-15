package mongo

import (
	"context"
	"errors"
	"fmt"
	"go.mongodb.org/mongo-driver/v2/bson"
	dm "go.mongodb.org/mongo-driver/v2/mongo"
	account "iwut-auth-center/internal/account/domain"
	"iwut-auth-center/internal/profile/domain"
	"os"
	"sync"
	"testing"
	"time"
)

func profileDB(t *testing.T) *dm.Database {
	t.Helper()
	uri := os.Getenv("MONGODB_INTEGRATION_URI")
	if uri == "" {
		t.Skip("MONGODB_INTEGRATION_URI is not set")
	}
	client, e := NewClient(uri)
	if e != nil {
		t.Fatal(e)
	}
	db := client.Database(fmt.Sprintf("profile_%d", time.Now().UnixNano()))
	t.Cleanup(func() { _ = db.Drop(context.Background()); _ = client.Disconnect(context.Background()) })
	if e = EnsurePrincipalSchema(context.Background(), db); e != nil {
		t.Fatal(e)
	}
	return db
}
func insertProfile(t *testing.T, db *dm.Database) {
	t.Helper()
	_, e := db.Collection(PrincipalCollection).InsertOne(context.Background(), bson.M{"authId": "user1", "principalType": "USER", "accountStatus": "ACTIVE", "accountRevision": int64(1), "minimumCredentialRevision": int64(1), "permissions": bson.A{"existing"}, "updatedAt": time.Unix(50, 0), "profile": bson.M{"entries": bson.A{}, "revision": int64(1), "updatedAt": time.Unix(100, 0)}})
	if e != nil {
		t.Fatal(e)
	}
}
func TestMongoProfileAtomicRevisionAndOtherFields(t *testing.T) {
	db := profileDB(t)
	insertProfile(t, db)
	r, _ := NewProfileRepository(db)
	ctx := account.WithIdentity(context.Background(), "user1", 1)
	s := domain.Snapshot{Entries: []domain.Entry{{Key: "education.flag", Value: domain.Value{Type: domain.Boolean}}, {Key: "education.year", Value: domain.Value{Type: domain.Integer, Integer: 2026}}}, Revision: 2, UpdatedAt: time.Unix(200, 0)}
	errs := make(chan error, 2)
	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); errs <- r.Commit(ctx, "user1", 1, s) }()
	}
	wg.Wait()
	close(errs)
	success, conflict := 0, 0
	for e := range errs {
		if e == nil {
			success++
		} else if errors.Is(e, domain.ErrConflict) {
			conflict++
		} else {
			t.Fatal(e)
		}
	}
	if success != 1 || conflict != 1 {
		t.Fatalf("atomicity successes=%d conflicts=%d", success, conflict)
	}
	var raw bson.Raw
	if e := db.Collection(PrincipalCollection).FindOne(ctx, bson.M{"authId": "user1"}).Decode(&raw); e != nil {
		t.Fatal(e)
	}
	if raw.Lookup("updatedAt").DateTime() != 50000 || raw.Lookup("permissions").Type != bson.TypeArray {
		t.Fatal("unrelated principal fields overwritten")
	}
	profile := raw.Lookup("profile").Document()
	if profile.Lookup("revision").Type != bson.TypeInt64 {
		t.Fatal("revision not BSON int64")
	}
	entries, _ := profile.Lookup("entries").Array().Values()
	if entries[1].Document().Lookup("value").Type != bson.TypeInt32 {
		t.Fatal("integer not BSON int32")
	}
	if _, e := r.Confirm(ctx, "user1", 1); e != domain.ErrConflict {
		t.Fatal("stale no-op succeeded")
	}
	_, _ = db.Collection(PrincipalCollection).UpdateOne(ctx, bson.M{"authId": "user1"}, bson.M{"$set": bson.M{"accountStatus": "DISABLED"}})
	if _, e := r.Confirm(ctx, "user1", 2); e != domain.ErrDisabled {
		t.Fatal("disabled no-op succeeded")
	}
}
func TestMongoProfileRejectsCorruptStorage(t *testing.T) {
	db := profileDB(t)
	insertProfile(t, db)
	r, _ := NewProfileRepository(db)
	ctx := account.WithIdentity(context.Background(), "user1", 1)
	for _, patch := range []bson.M{
		{"profile.revision": int32(1)},
		{"profile.entries": bson.A{bson.M{"key": "year", "valueType": "INTEGER", "value": int64(1)}}},
		{"profile.entries": bson.A{bson.M{"key": "x", "valueType": "BOOLEAN", "value": false}, bson.M{"key": "x", "valueType": "BOOLEAN", "value": true}}},
		{"profile.entries": bson.A{bson.M{"key": "education.campus_areas", "valueType": "STRING_SET", "value": bson.A{"NANHU", "JIANHU"}}}},
		{"profile.entries": bson.A{bson.M{"key": "education.current_grade", "valueType": "ACADEMIC_GRADE", "value": bson.M{"stage": "UNDERGRADUATE", "year": int32(1), "finalYear": int32(4), "academicYear": int32(2026)}}}},
		{"profile.entries": bson.A{bson.M{"key": "education.current_grade", "valueType": "ACADEMIC_GRADE", "value": bson.M{"stage": "UNDERGRADUATE", "year": int32(1), "finalYear": int32(4), "academicYear": int32(2026), "confirmedAt": time.Now(), "extra": true}}}},
	} {
		_, _ = db.Collection(PrincipalCollection).UpdateOne(ctx, bson.M{"authId": "user1"}, bson.M{"$set": bson.M{"profile": bson.M{"revision": int64(1), "updatedAt": time.Now(), "entries": bson.A{}}}})
		_, _ = db.Collection(PrincipalCollection).UpdateOne(ctx, bson.M{"authId": "user1"}, bson.M{"$set": patch})
		if _, e := r.Read(ctx, "user1"); e != domain.ErrUnavailable {
			t.Fatalf("corruption accepted %+v: %v", patch, e)
		}
	}
}

func TestMongoProfileRoundTripsExtendedValues(t *testing.T) {
	db := profileDB(t)
	insertProfile(t, db)
	r, _ := NewProfileRepository(db)
	ctx := account.WithIdentity(context.Background(), "user1", 1)
	confirmed := time.Now().UTC().Truncate(time.Millisecond)
	snapshot := domain.Snapshot{Revision: 2, UpdatedAt: confirmed, Entries: []domain.Entry{
		{Key: "education.campus_areas", Value: domain.Value{Type: domain.StringSet, Strings: []string{"JIANHU", "NANHU"}}},
		{Key: "education.current_grade", Value: domain.Value{Type: domain.AcademicGrade, Academic: &domain.Grade{Stage: "UNDERGRADUATE", Year: 3, FinalYear: 4, AcademicYear: 2025, ConfirmedAt: &confirmed}}},
	}}
	if err := r.Commit(ctx, "user1", 1, snapshot); err != nil {
		t.Fatal(err)
	}
	principal, err := r.Read(ctx, "user1")
	if err != nil || len(principal.Profile.Entries) != 2 {
		t.Fatalf("read = %#v, %v", principal, err)
	}
	if got := principal.Profile.Entries[0].Value.Strings; len(got) != 2 || got[0] != "JIANHU" || got[1] != "NANHU" {
		t.Fatal("string set changed", got)
	}
	grade := principal.Profile.Entries[1].Value.Academic
	if grade == nil || grade.Stage != "UNDERGRADUATE" || grade.Year != 3 || grade.ConfirmedAt == nil || !grade.ConfirmedAt.Equal(confirmed) {
		t.Fatal("grade changed", grade)
	}
}
