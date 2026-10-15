package mongo

import (
	"errors"
	"testing"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	d "iwut-auth-center/internal/academicyear/domain"
	account "iwut-auth-center/internal/account/domain"
)

func TestAcademicYearPolicyMongoProjectionUpdateNoopAndPrecision(t *testing.T) {
	administrator, database, actor := administratorFixture(t)
	authentication := administrator.authentication
	if err := EnsureAcademicYearSchema(t.Context(), database); err != nil {
		t.Fatal(err)
	}
	repository, err := NewAcademicYearRepository(authentication)
	if err != nil || repository.Initialize(t.Context()) != nil {
		t.Fatal("initialize", err)
	}
	location, _ := time.LoadLocation("Asia/Shanghai")
	now := time.Date(2026, time.October, 10, 8, 9, 10, 321000000, location)
	authentication.clock = func() time.Time { return now }
	ctx := account.WithIdentity(t.Context(), actor, 1)
	initial, err := repository.Get(ctx, actor)
	if err != nil || initial.CurrentAcademicYear != 2026 || !initial.NextRolloverAt.Equal(time.Date(2027, time.September, 1, 0, 0, 0, 0, location)) || initial.Revision != 1 {
		t.Fatalf("initial = %#v, %v", initial, err)
	}
	next := time.Date(2027, time.February, 20, 1, 2, 3, 456789123, location)
	updated, err := repository.Update(ctx, d.Command{ActorAuthID: actor, NextRolloverAt: next, ExpectedRevision: 1, Reason: "test precise future instant"})
	if err != nil || updated.Revision != 2 || updated.CurrentAcademicYear != 2026 || !updated.NextRolloverAt.Equal(next) {
		t.Fatalf("updated = %#v, %v", updated, err)
	}
	read, err := repository.Get(ctx, actor)
	if err != nil || !read.NextRolloverAt.Equal(next) {
		t.Fatalf("precision lost: %#v, %v", read, err)
	}
	noop, err := repository.Update(ctx, d.Command{ActorAuthID: actor, NextRolloverAt: next, ExpectedRevision: 2, Reason: "same"})
	if err != nil || noop.Revision != 2 {
		t.Fatalf("no-op = %#v, %v", noop, err)
	}
	count, err := database.Collection(AcademicYearAuditCollection).CountDocuments(t.Context(), bson.M{})
	if err != nil || count != 1 {
		t.Fatalf("audit count = %d, %v", count, err)
	}
}

func TestAcademicYearPolicyMongoDoesNotReprovisionAfterDeletion(t *testing.T) {
	fixture := newAuthenticationFixture(t)
	database := fixture.r.database
	if err := EnsureAcademicYearSchema(t.Context(), database); err != nil {
		t.Fatal(err)
	}
	repository, _ := NewAcademicYearRepository(fixture.r)
	if err := repository.Initialize(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Collection(AuthenticationRuntimeCollection).DeleteMany(t.Context(), bson.M{"_id": bson.M{"$in": bson.A{academicYearScheduleID, academicYearProvisionID}}}); err != nil {
		t.Fatal(err)
	}
	if err := repository.Initialize(t.Context()); !errors.Is(err, d.ErrUnavailable) {
		t.Fatalf("deleted policy was silently re-provisioned: %v", err)
	}
	if _, err := repository.CurrentAcademicYear(t.Context(), time.Now()); !errors.Is(err, d.ErrUnavailable) {
		t.Fatalf("deleted policy was read: %v", err)
	}
}
