package mongo

import (
	"errors"
	"sync"
	"testing"

	"go.mongodb.org/mongo-driver/v2/bson"

	account "iwut-auth-center/internal/account/domain"
	domain "iwut-auth-center/internal/applicationoperations/domain"
)

func applicationOperationsFixture(t *testing.T) (*ApplicationOperationsPermissionRepository, string) {
	t.Helper()
	reviewer, database, subject := reviewerFixture(t)
	adminVerifiedEmail(t, database, subject)
	repository, err := NewApplicationOperationsPermissionRepository(reviewer.authentication, true)
	if err != nil {
		t.Fatal(err)
	}
	return repository, subject
}

func TestApplicationOperationsMongoIndependentCASAndDisabledRevoke(t *testing.T) {
	repository, subject := applicationOperationsFixture(t)
	ctx := account.WithIdentity(t.Context(), "admin", 1)
	start := make(chan struct{})
	results := make(chan error, 2)
	var wait sync.WaitGroup
	for _, permission := range domain.Permissions() {
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			_, err := repository.Manage(ctx, domain.Command{ActorAuthID: "admin", SubjectAuthID: subject, Permission: permission, Action: "GRANT", ExpectedRevision: 1, Reason: "application operations onboarding"})
			results <- err
		}()
	}
	close(start)
	wait.Wait()
	close(results)
	successes := 0
	for err := range results {
		if err == nil {
			successes++
		} else if !errors.Is(err, domain.ErrConflict) {
			t.Fatal(err)
		}
	}
	if successes != 1 {
		t.Fatal(successes)
	}
	state, err := repository.Get(ctx, "admin", subject)
	if err != nil || state.Revision != 2 || state.Has(domain.Restore) == state.Has(domain.Suspend) {
		t.Fatal(state, err)
	}
	granted := domain.Restore
	ungranted := domain.Suspend
	if state.Has(domain.Suspend) {
		granted = domain.Suspend
		ungranted = domain.Restore
	}
	if _, err = repository.authentication.database.Collection(PrincipalCollection).UpdateOne(t.Context(), bson.M{"authId": subject}, bson.M{"$set": bson.M{"accountStatus": "DISABLED"}}); err != nil {
		t.Fatal(err)
	}
	state, err = repository.Get(ctx, "admin", subject)
	if err != nil || state.AccountStatus != "DISABLED" || state.Permissions[0].Effective || state.Permissions[1].Effective {
		t.Fatal(state, err)
	}
	if _, err = repository.Manage(ctx, domain.Command{ActorAuthID: "admin", SubjectAuthID: subject, Permission: ungranted, Action: "GRANT", ExpectedRevision: 2, Reason: "must remain blocked"}); !errors.Is(err, domain.ErrGrantBlocked) {
		t.Fatal(err)
	}
	state, err = repository.Manage(ctx, domain.Command{ActorAuthID: "admin", SubjectAuthID: subject, Permission: granted, Action: "REVOKE", ExpectedRevision: 2, Reason: "offboarding while disabled"})
	if err != nil || state.Revision != 3 || state.Has(granted) {
		t.Fatal(state, err)
	}
}

func TestApplicationOperationsMongoEmailAndSharedAudit(t *testing.T) {
	reviewer, database, subject := reviewerFixture(t)
	repository, _ := NewApplicationOperationsPermissionRepository(reviewer.authentication, true)
	ctx := account.WithIdentity(t.Context(), "admin", 1)
	command := domain.Command{ActorAuthID: "admin", SubjectAuthID: subject, Permission: domain.Suspend, Action: "GRANT", ExpectedRevision: 1, Reason: "operations duty"}
	if _, err := repository.Manage(ctx, command); !errors.Is(err, domain.ErrUnavailable) {
		t.Fatal(err)
	}
	adminVerifiedEmail(t, database, subject)
	state, err := repository.Manage(ctx, command)
	if err != nil || state.Revision != 2 || !state.Has(domain.Suspend) {
		t.Fatal(state, err)
	}
	var event bson.M
	if err = database.Collection(PermissionAuditCollection).FindOne(t.Context(), bson.M{"subjectAuthId": subject, "permission": domain.Suspend}).Decode(&event); err != nil {
		t.Fatal(err)
	}
	if event["reason"] != command.Reason || event["action"] != "GRANT" || event["actorAuthId"] != "admin" {
		t.Fatal(event)
	}
	var principal bson.Raw
	if err = database.Collection(PrincipalCollection).FindOne(t.Context(), bson.M{"authId": subject}).Decode(&principal); err != nil {
		t.Fatal(err)
	}
	permissions, _ := adminPermissions(principal.Lookup("permissions"))
	for _, forbidden := range []string{"auth.platform-admin.manage", "app.profile.review", "app.version.review"} {
		for _, permission := range permissions {
			if permission == forbidden {
				t.Fatal("unexpected implicit permission", permissions)
			}
		}
	}
}
