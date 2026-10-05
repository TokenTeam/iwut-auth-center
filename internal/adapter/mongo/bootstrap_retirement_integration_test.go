package mongo

import (
	"errors"
	"github.com/google/uuid"
	"go.mongodb.org/mongo-driver/v2/bson"
	account "iwut-auth-center/internal/account/domain"
	d "iwut-auth-center/internal/administrator/domain"
	"testing"
	"time"
)

func TestBootstrapAuditControlledRetirementKeepsGovernanceAvailable(t *testing.T) {
	r, db, original := administratorFixture(t)
	ctx := account.WithIdentity(t.Context(), original, 1)
	adminCandidate(t, db, "successor")
	if _, e := r.Manage(ctx, d.Command{ActorAuthID: original, SubjectAuthID: "successor", Action: "GRANT", Reason: "handover", ExpectedRevision: 1}); e != nil {
		t.Fatal(e)
	}
	var marker bson.Raw
	if e := db.Collection(AuthenticationRuntimeCollection).FindOne(ctx, bson.M{"_id": bootstrapMarker}).Decode(&marker); e != nil {
		t.Fatal(e)
	}
	eventID := marker.Lookup("eventId").StringValue()
	now := time.Now().UTC().Truncate(time.Millisecond)
	occurred := now.Add(-181 * 24 * time.Hour)
	for _, c := range []string{AuthenticationRuntimeCollection, PlatformAdminAuditCollection} {
		filter := bson.M{"eventId": eventID}
		if _, e := db.Collection(c).UpdateOne(ctx, filter, bson.M{"$set": bson.M{"occurredAt": occurred}}); e != nil {
			t.Fatal(e)
		}
	}
	if _, e := db.Collection(PrincipalCollection).ReplaceOne(ctx, bson.M{"authId": original}, bson.M{"authId": original, "principalType": "USER", "accountStatus": "CLOSED", "accountRevision": int64(2), "terminatedAt": now.Add(-time.Hour), "closureOperationId": uuid.NewString()}); e != nil {
		t.Fatal(e)
	}
	if _, e := db.Collection(PlatformAdminAuditCollection).DeleteOne(ctx, bson.M{"eventId": eventID}); e != nil {
		t.Fatal(e)
	}
	successor := account.WithIdentity(t.Context(), "successor", 1)
	if _, e := r.Get(successor, "successor", "successor"); !errors.Is(e, d.ErrUnavailable) {
		t.Fatal("missing audit accepted", e)
	}
	for _, retirement := range []time.Time{now.Add(-2 * 24 * time.Hour), now.Add(time.Hour), now} {
		if _, e := db.Collection(AuthenticationRuntimeCollection).UpdateOne(ctx, bson.M{"_id": bootstrapMarker}, bson.M{"$set": bson.M{"auditRetiredAt": retirement}}); e != nil {
			t.Fatal(e)
		}
		state, e := r.Get(successor, "successor", "successor")
		if retirement.Equal(now) {
			if e != nil || !state.Effective() {
				t.Fatal(state, e)
			}
		} else if !errors.Is(e, d.ErrUnavailable) {
			t.Fatal(retirement, e)
		}
	}
	var tomb bson.Raw
	if e := db.Collection(PrincipalCollection).FindOne(ctx, bson.M{"authId": original}).Decode(&tomb); e != nil || tomb.Lookup("authenticationFence").Type != 0 {
		t.Fatal("tombstone mutated", e)
	}
	if _, e := db.Collection(PrincipalCollection).UpdateOne(ctx, bson.M{"authId": original}, bson.M{"$set": bson.M{"permissions": bson.A{}}}); e != nil {
		t.Fatal(e)
	}
	if _, e := r.Get(successor, "successor", "successor"); !errors.Is(e, d.ErrUnavailable) {
		t.Fatal("invalid tombstone", e)
	}
}
