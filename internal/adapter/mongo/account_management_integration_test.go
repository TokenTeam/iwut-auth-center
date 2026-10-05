package mongo

import (
	"errors"
	"go.mongodb.org/mongo-driver/v2/bson"
	account "iwut-auth-center/internal/account/domain"
	admin "iwut-auth-center/internal/administrator/domain"
	"math"
	"sync"
	"testing"
)

func TestAccountManagementMongoCASAuditAndRestore(t *testing.T) {
	admins, db, actor := administratorFixture(t)
	repo, err := NewAccountManagementRepository(admins.authentication)
	if err != nil {
		t.Fatal(err)
	}
	if err = EnsureAccountManagementSchema(t.Context(), db); err != nil {
		t.Fatal(err)
	}
	adminCandidate(t, db, "ordinary")
	ctx := account.WithIdentity(t.Context(), actor, 1)
	command := account.Command{ActorAuthID: actor, SubjectAuthID: "ordinary", Action: "DISABLE", ExpectedRevision: 1, Reason: "investigation"}
	disabled, err := repo.Manage(ctx, command)
	if err != nil || disabled.Revision != 2 || disabled.Status != "DISABLED" {
		t.Fatal(disabled, err)
	}
	if _, err = repo.Manage(ctx, command); !errors.Is(err, account.ErrConflict) {
		t.Fatal(err)
	}
	command.Action = "RESTORE"
	command.ExpectedRevision = 2
	restored, err := repo.Manage(ctx, command)
	if err != nil || restored.Revision != 3 || restored.Status != "ACTIVE" {
		t.Fatal(restored, err)
	}
	var raw bson.Raw
	if err = db.Collection(PrincipalCollection).FindOne(ctx, bson.M{"authId": "ordinary"}).Decode(&raw); err != nil || raw.Lookup("permissionRevision").Int64() != 1 {
		t.Fatal(err)
	}
	count, err := db.Collection(AccountStatusAuditCollection).CountDocuments(ctx, bson.M{})
	if err != nil || count != 2 {
		t.Fatal(count, err)
	}
	if err = db.RunCommand(ctx, bson.D{{Key: "collMod", Value: AccountStatusAuditCollection}, {Key: "validator", Value: bson.M{"reason": bson.M{"$ne": "rollback"}}}, {Key: "validationLevel", Value: "strict"}}).Err(); err != nil {
		t.Fatal(err)
	}
	command.Action = "DISABLE"
	command.ExpectedRevision = 3
	command.Reason = "rollback"
	if result, err := repo.Manage(ctx, command); !errors.Is(err, account.ErrUnavailable) || result.AuthID != "" {
		t.Fatal(result, err)
	}
	state, err := repo.Get(ctx, actor, "ordinary")
	if err != nil || state.Revision != 3 || state.Status != "ACTIVE" {
		t.Fatal(state, err)
	}
	_, err = db.Collection(PrincipalCollection).UpdateOne(ctx, bson.M{"authId": "ordinary"}, bson.M{"$set": bson.M{"accountRevision": int64(math.MaxInt64)}})
	if err != nil {
		t.Fatal(err)
	}
	command.ExpectedRevision = math.MaxInt64
	if _, err = repo.Manage(ctx, command); !errors.Is(err, account.ErrExhausted) {
		t.Fatal(err)
	}
}
func TestAccountManagementMongoDisableAndAdminRevokeSerialize(t *testing.T) {
	admins, db, actor := administratorFixture(t)
	repo, err := NewAccountManagementRepository(admins.authentication)
	if err != nil {
		t.Fatal(err)
	}
	if err = EnsureAccountManagementSchema(t.Context(), db); err != nil {
		t.Fatal(err)
	}
	ctx := account.WithIdentity(t.Context(), actor, 1)
	if _, err = repo.Manage(ctx, account.Command{ActorAuthID: actor, SubjectAuthID: actor, Action: "DISABLE", ExpectedRevision: 1, Reason: "self"}); !errors.Is(err, account.ErrLastAdmin) {
		t.Fatal(err)
	}
	adminCandidate(t, db, "second")
	if _, err = admins.Manage(ctx, admin.Command{ActorAuthID: actor, SubjectAuthID: "second", Action: "GRANT", ExpectedRevision: 1, Reason: "second"}); err != nil {
		t.Fatal(err)
	}
	results := make(chan error, 2)
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, err := repo.Manage(ctx, account.Command{ActorAuthID: actor, SubjectAuthID: "second", Action: "DISABLE", ExpectedRevision: 1, Reason: "pause"})
		results <- err
	}()
	go func() {
		defer wg.Done()
		_, err := admins.Manage(ctx, admin.Command{ActorAuthID: actor, SubjectAuthID: actor, Action: "REVOKE", ExpectedRevision: 2, Reason: "handover"})
		results <- err
	}()
	wg.Wait()
	close(results)
	success := 0
	for err := range results {
		if err == nil {
			success++
		} else if !errors.Is(err, account.ErrLastAdmin) && !errors.Is(err, account.ErrForbidden) && !errors.Is(err, admin.ErrLast) {
			t.Fatal(err)
		}
	}
	if success != 1 {
		t.Fatal(success)
	}
	count, err := db.Collection(PrincipalCollection).CountDocuments(ctx, bson.M{"accountStatus": "ACTIVE", "permissions": bson.M{"$all": admin.Permissions()}})
	if err != nil || count != 1 {
		t.Fatal(count, err)
	}
}
