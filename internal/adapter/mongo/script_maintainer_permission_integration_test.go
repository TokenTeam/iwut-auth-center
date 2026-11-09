package mongo

import (
	"context"
	"errors"
	"slices"
	"sync"
	"testing"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"

	account "iwut-auth-center/internal/account/domain"
	appops "iwut-auth-center/internal/applicationoperations/domain"
	identity "iwut-auth-center/internal/identity/domain"
	"iwut-auth-center/internal/scriptmaintainer/domain"
)

func TestScriptMaintainerMongoSharedCASAndRevokeWithoutEmail(t *testing.T) {
	reviewer, db, subject := reviewerFixture(t)
	adminVerifiedEmail(t, db, subject)
	ctx := account.WithIdentity(t.Context(), "admin", 1)
	repo := NewScriptMaintainerPermissionRepository(reviewer.authentication, true)
	recoveryOff := NewScriptMaintainerPermissionRepository(reviewer.authentication, false)
	grant := domain.Command{ActorAuthID: "admin", SubjectAuthID: subject, Permission: domain.MaintainPermission, Action: "GRANT", ExpectedRevision: 1, Reason: "script maintenance duty"}
	if _, err := recoveryOff.Manage(ctx, grant); !errors.Is(err, domain.ErrGrantBlocked) {
		t.Fatal("grant without recovery", err)
	}
	if _, err := repo.Get(account.WithIdentity(t.Context(), subject, 1), subject, "nonexistent"); !errors.Is(err, domain.ErrForbidden) {
		t.Fatal("target lookup preceded current administrator check", err)
	}

	start := make(chan struct{})
	type result struct {
		permission string
		err        error
	}
	results := make(chan result, 2)
	var wait sync.WaitGroup
	for _, permission := range []string{domain.MaintainPermission, domain.ReviewPermission} {
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			cmd := grant
			cmd.Permission = permission
			_, err := repo.Manage(ctx, cmd)
			results <- result{permission, err}
		}()
	}
	close(start)
	wait.Wait()
	close(results)
	successes, conflicts := 0, 0
	for result := range results {
		err := result.err
		switch {
		case err == nil:
			successes++
			grant.Permission = result.permission
		case errors.Is(err, domain.ErrConflict):
			conflicts++
		default:
			t.Fatal(err)
		}
	}
	if successes != 1 || conflicts != 1 {
		t.Fatal(successes, conflicts)
	}
	repeated := grant
	repeated.ExpectedRevision = 2
	if _, err := repo.Manage(ctx, repeated); !errors.Is(err, domain.ErrConflict) {
		t.Fatal("repeated grant with current revision", err)
	}
	operations, _ := NewApplicationOperationsPermissionRepository(reviewer.authentication, true)
	op := appops.Command{ActorAuthID: "admin", SubjectAuthID: subject, Permission: appops.Suspend, Action: "GRANT", ExpectedRevision: 1, Reason: "operations duty"}
	if _, err := operations.Manage(ctx, op); !errors.Is(err, appops.ErrConflict) {
		t.Fatal("UC027 did not share revision", err)
	}
	op.ExpectedRevision = 2
	if _, err := operations.Manage(ctx, op); err != nil {
		t.Fatal(err)
	}

	// Deliberately damage only the target fixture's email data. The formal
	// query and revoke must not depend on recovery or even read that directory.
	if _, err := db.Collection(EmailDirectoryCollection).UpdateOne(t.Context(), bson.M{"authId": subject}, bson.M{"$set": bson.M{"revision": "invalid"}}); err != nil {
		t.Fatal(err)
	}
	accountTransition(t, reviewer.authentication, subject, "DISABLED")
	state, err := recoveryOff.Get(ctx, "admin", subject)
	if err != nil || !state.For(grant.Permission).Granted || state.For(grant.Permission).Effective || state.Revision != 3 {
		t.Fatal(state, err)
	}
	grant.Action, grant.ExpectedRevision = "REVOKE", 3
	state, err = recoveryOff.Manage(ctx, grant)
	if err != nil || state.For(grant.Permission).Granted || state.For(grant.Permission).Effective || state.Revision != 4 {
		t.Fatal(state, err)
	}
	var raw bson.Raw
	if err := db.Collection(PrincipalCollection).FindOne(t.Context(), bson.M{"authId": subject}).Decode(&raw); err != nil {
		t.Fatal(err)
	}
	permissions, err := adminPermissions(raw.Lookup("permissions"))
	if err != nil || len(permissions) != 1 || permissions[0] != appops.Suspend {
		t.Fatal(permissions, err)
	}
	if count, err := db.Collection(PermissionAuditCollection).CountDocuments(t.Context(), bson.M{"subjectAuthId": subject, "permission": grant.Permission}); err != nil || count != 2 {
		t.Fatal("audit did not match actual script changes", count, err)
	}
}

func TestScriptMaintainerMongoAuditFailureRollsBack(t *testing.T) {
	reviewer, db, subject := reviewerFixture(t)
	adminVerifiedEmail(t, db, subject)
	ctx := account.WithIdentity(t.Context(), "admin", 1)
	repo := NewScriptMaintainerPermissionRepository(reviewer.authentication, true)
	if err := db.RunCommand(t.Context(), bson.D{{Key: "collMod", Value: PermissionAuditCollection}, {Key: "validator", Value: bson.M{"permission": bson.M{"$ne": domain.PublishPermission}}}}).Err(); err != nil {
		t.Fatal(err)
	}
	command := domain.Command{ActorAuthID: "admin", SubjectAuthID: subject, Permission: domain.PublishPermission, Action: "GRANT", ExpectedRevision: 1, Reason: "audit rollback"}
	if _, err := repo.Manage(ctx, command); !errors.Is(err, domain.ErrUnavailable) {
		t.Fatal(err)
	}
	state, err := repo.Get(ctx, "admin", subject)
	if err != nil || state.For(domain.PublishPermission).Granted || state.Revision != 1 {
		t.Fatal("permission changed despite audit failure", state, err)
	}
}

func TestScriptMaintainerMongoIssuanceAndRevokeCommitOrder(t *testing.T) {
	issuer, db, session, _, _, _ := identityFixture(t)
	if err := EnsureReviewerSchema(t.Context(), db); err != nil {
		t.Fatal(err)
	}
	adminCandidate(t, db, "admin")
	seedAdministrator(t, issuer.authentication, "admin")
	adminVerifiedEmail(t, db, session.AuthID)
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	actor := account.WithIdentity(ctx, "admin", 1)
	repo := NewScriptMaintainerPermissionRepository(issuer.authentication, true)
	command := domain.Command{ActorAuthID: "admin", SubjectAuthID: session.AuthID, Permission: domain.MaintainPermission, Action: "GRANT", ExpectedRevision: 1, Reason: "issuance ordering"}
	if _, err := repo.Manage(actor, command); err != nil {
		t.Fatal(err)
	}
	started, release := make(chan struct{}), make(chan struct{})
	issueResult, revokeResult := make(chan error, 1), make(chan error, 1)
	var once sync.Once
	go func() {
		issueResult <- issuer.WithSession(ctx, session.TokenDigest, func(snapshot identity.Snapshot, now time.Time) error {
			claims, err := identity.Project(snapshot, identity.AppAudience, "first", now, time.Minute)
			if err != nil || !slices.Equal(claims.Permissions, []string{domain.MaintainPermission, "app.version.review"}) {
				return errors.New("in-flight issue did not see the committed grant")
			}
			once.Do(func() { close(started) })
			select {
			case <-release:
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
		})
	}()
	select {
	case <-started:
	case err := <-issueResult:
		t.Fatal(err)
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	command.Action, command.ExpectedRevision = "REVOKE", 2
	attempted := make(chan struct{})
	go func() {
		close(attempted)
		_, err := repo.Manage(actor, command)
		revokeResult <- err
	}()
	<-attempted
	close(release)
	if err := <-issueResult; err != nil {
		t.Fatal(err)
	}
	if err := <-revokeResult; err != nil {
		t.Fatal(err)
	}
	if err := issuer.WithSession(ctx, session.TokenDigest, func(snapshot identity.Snapshot, now time.Time) error {
		claims, err := identity.Project(snapshot, identity.AppAudience, "second", now, time.Minute)
		if err != nil || snapshot.PermissionRevision != 3 || !slices.Equal(claims.Permissions, []string{"app.version.review"}) {
			return errors.New("new issue read a revoked grant or lost an unrelated permission")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
