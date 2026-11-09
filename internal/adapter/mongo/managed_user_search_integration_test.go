package mongo

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"go.mongodb.org/mongo-driver/v2/bson"
	account "iwut-auth-center/internal/account/domain"
	admin "iwut-auth-center/internal/administrator/domain"
	ops "iwut-auth-center/internal/applicationoperations/domain"
	d "iwut-auth-center/internal/managedusersearch/domain"
)

func TestManagedUserSearchMongoCurrentBindingsAndPrivacy(t *testing.T) {
	fixture, db, subject := reviewerFixture(t)
	adminVerifiedEmail(t, db, subject)
	ctx := account.WithIdentity(t.Context(), "admin", 1)
	repo := NewManagedUserSearchRepository(fixture.authentication)
	secondary := subject + "+tag@example.test"
	bindingID := uuid.NewString()
	if _, err := db.Collection(EmailBindingCollection).InsertOne(t.Context(), emailBindingDocument{BindingID: bindingID, AuthID: subject, Email: secondary, VerifiedAt: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Collection(EmailDirectoryCollection).UpdateOne(t.Context(), bson.M{"authId": subject}, bson.M{"$set": bson.M{"verifiedCount": int64(2), "revision": int64(2)}}); err != nil {
		t.Fatal(err)
	}
	for _, query := range []d.Query{{Kind: "authId", Value: subject}, {Kind: "email", Value: " " + strings.ToUpper(secondary) + " "}, {Kind: "email", Value: subject + "@example.test"}} {
		result, err := repo.Search(ctx, "admin", query)
		if err != nil || len(result.Items) != 1 || result.Items[0] != (d.Summary{AuthID: subject, AccountStatus: "ACTIVE"}) || result.AsOf.IsZero() {
			t.Fatal(result, err)
		}
	}
	for _, state := range []string{"PENDING", "APPROVED", "REJECTED", "SUSPENDED", "WITHDRAWN"} {
		if _, err := db.Collection(PrincipalCollection).UpdateOne(t.Context(), bson.M{"authId": subject}, bson.M{"$set": bson.M{"developerStatus": state, "developerRevision": int64(1), "accountStatus": "DISABLED"}}); err != nil {
			t.Fatal(err)
		}
		result, err := repo.Search(ctx, "admin", d.Query{Kind: "authId", Value: subject})
		if err != nil || len(result.Items) != 1 || result.Items[0].DeveloperStatus != state || result.Items[0].AccountStatus != "DISABLED" {
			t.Fatal(result, err)
		}
	}
	// Detach only the tested secondary binding using the fixture's exact directory.
	if _, err := db.Collection(EmailBindingCollection).DeleteOne(t.Context(), bson.M{"bindingId": bindingID}); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Collection(EmailDirectoryCollection).UpdateOne(t.Context(), bson.M{"authId": subject}, bson.M{"$set": bson.M{"verifiedCount": int64(1), "revision": int64(3)}}); err != nil {
		t.Fatal(err)
	}
	result, err := repo.Search(ctx, "admin", d.Query{Kind: "email", Value: secondary})
	if err != nil || len(result.Items) != 0 {
		t.Fatal("historical binding remained visible", result, err)
	}
	// ID lookup must survive a broken email directory; email lookup must fail closed.
	if _, err := db.Collection(EmailDirectoryCollection).UpdateOne(t.Context(), bson.M{"authId": subject}, bson.M{"$set": bson.M{"revision": "bad"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.Search(ctx, "admin", d.Query{Kind: "authId", Value: subject}); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.Search(ctx, "admin", d.Query{Kind: "email", Value: subject + "@example.test"}); !errors.Is(err, d.ErrUnavailable) {
		t.Fatal(err)
	}
}

func TestManagedUserSearchMongoClosedCorruptionAndOnlineAdministrator(t *testing.T) {
	fixture, db, subject := reviewerFixture(t)
	adminVerifiedEmail(t, db, subject)
	ctx := account.WithIdentity(t.Context(), "admin", 1)
	repo := NewManagedUserSearchRepository(fixture.authentication)
	for _, query := range []d.Query{{Kind: "authId", Value: "missing"}, {Kind: "email", Value: "unknown@example.test"}} {
		out, err := repo.Search(ctx, "admin", query)
		if err != nil || len(out.Items) != 0 || out.Items == nil {
			t.Fatal(out, err)
		}
	}
	if err := BootstrapSystemPrincipals(t.Context(), db); err != nil {
		t.Fatal(err)
	}
	var system bson.M
	if err := db.Collection(PrincipalCollection).FindOne(t.Context(), bson.M{"principalType": "SYSTEM"}).Decode(&system); err != nil {
		t.Fatal(err)
	}
	if out, err := repo.Search(ctx, "admin", d.Query{Kind: "authId", Value: system["authId"].(string)}); err != nil || len(out.Items) != 0 {
		t.Fatal(out, err)
	}
	if _, err := db.Collection(PrincipalCollection).UpdateOne(t.Context(), bson.M{"authId": subject}, bson.M{"$set": bson.M{"developerStatus": "INVALID"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.Search(ctx, "admin", d.Query{Kind: "authId", Value: subject}); !errors.Is(err, d.ErrUnavailable) {
		t.Fatal(err)
	}
	tombstone := bson.M{"authId": subject, "principalType": "USER", "accountStatus": "CLOSED", "accountRevision": int64(2), "closureOperationId": uuid.NewString(), "terminatedAt": time.Now().UTC()}
	if _, err := db.Collection(PrincipalCollection).ReplaceOne(t.Context(), bson.M{"authId": subject}, tombstone); err != nil {
		t.Fatal(err)
	}
	for _, query := range []d.Query{{Kind: "authId", Value: subject}, {Kind: "email", Value: subject + "@example.test"}} {
		if out, err := repo.Search(ctx, "admin", query); err != nil || len(out.Items) != 0 {
			t.Fatal(out, err)
		}
	}
	adminCandidate(t, db, "backup")
	management, _ := NewPlatformAdministratorRepository(fixture.authentication, true)
	if _, err := management.Manage(ctx, admin.Command{ActorAuthID: "admin", SubjectAuthID: "backup", Action: "GRANT", ExpectedRevision: 1, Reason: "search authority lifecycle"}); err != nil {
		t.Fatal(err)
	}
	state, err := management.Get(ctx, "admin", "admin")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := management.Manage(account.WithIdentity(t.Context(), "backup", 1), admin.Command{ActorAuthID: "backup", SubjectAuthID: "admin", Action: "REVOKE", ExpectedRevision: state.Revision, Reason: "end search authority"}); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.Search(ctx, "admin", d.Query{}); !errors.Is(err, d.ErrForbidden) {
		t.Fatal("input validation preceded current authority", err)
	}
}

func TestApplicationSearchMongoFormalGrantAndAuditRollback(t *testing.T) {
	repo, subject := applicationOperationsFixture(t)
	ctx := account.WithIdentity(t.Context(), "admin", 1)
	self := account.WithIdentity(t.Context(), subject, 1)
	command := ops.Command{ActorAuthID: "admin", SubjectAuthID: subject, Permission: ops.Search, Action: "GRANT", ExpectedRevision: 1, Reason: "directory access"}
	state, err := repo.Manage(ctx, command)
	if err != nil || !state.Has(ops.Search) || state.Has(ops.Suspend) || state.Has(ops.Restore) {
		t.Fatal(state, err)
	}
	own, err := repo.GetOwn(self, subject)
	if err != nil || len(own.EffectivePermissions) != 1 || own.EffectivePermissions[0] != ops.Search {
		t.Fatal(own, err)
	}
	command.Action, command.ExpectedRevision = "REVOKE", 2
	if _, err := repo.Manage(ctx, command); err != nil {
		t.Fatal(err)
	}
	own, err = repo.GetOwn(self, subject)
	if err != nil || len(own.EffectivePermissions) != 0 || own.Revision != 3 {
		t.Fatal(own, err)
	}
	db := repo.authentication.database
	if err := db.RunCommand(t.Context(), bson.D{{Key: "collMod", Value: PermissionAuditCollection}, {Key: "validator", Value: bson.M{"permission": bson.M{"$ne": ops.Search}}}}).Err(); err != nil {
		t.Fatal(err)
	}
	command.Action, command.ExpectedRevision = "GRANT", 3
	if _, err := repo.Manage(ctx, command); !errors.Is(err, ops.ErrUnavailable) {
		t.Fatal(err)
	}
	own, err = repo.GetOwn(self, subject)
	if err != nil || own.Revision != 3 || len(own.EffectivePermissions) != 0 {
		t.Fatal("audit failure changed permission", own, err)
	}
}
