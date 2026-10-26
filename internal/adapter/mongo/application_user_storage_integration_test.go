package mongo

import (
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"go.mongodb.org/mongo-driver/v2/bson"
	d "iwut-auth-center/internal/oauth/domain"
)

func TestApplicationUserStorageMongoCASAndUserClear(t *testing.T) {
	fixture := newOAuthFixture(t)
	ctx := t.Context()
	if err := EnsureApplicationUserStorageSchema(ctx, fixture.repo.db); err != nil {
		t.Fatal(err)
	}
	applicationID := uuid.NewString()
	fixture.app.mu.Lock()
	fixture.app.runtime.Client.ApplicationID = applicationID
	fixture.app.runtime.Optional = append(fixture.app.runtime.Optional, "storage.read", "storage.write")
	fixture.app.mu.Unlock()
	fixture.seed = append(fixture.seed,
		d.Scope{Name: "storage.read", Label: "Read app data", Description: "Read application-specific user data", Kind: "RESOURCE", Audience: "iwut-auth-center", Enabled: true},
		d.Scope{Name: "storage.write", Label: "Write app data", Description: "Write application-specific user data", Kind: "RESOURCE", Audience: "iwut-auth-center", Enabled: true},
	)
	if err := updateOAuthFixtureCatalog(t, fixture.repo, fixture.seed); err != nil {
		t.Fatal(err)
	}
	tokens := fixture.tokens(t, "openid", "storage.read", "storage.write")

	empty, err := fixture.service.BatchGetApplicationUserStorage(ctx, tokens.AccessToken, []string{"theme"})
	if err != nil || empty.Revision != 0 || len(empty.Entries) != 0 || len(empty.MissingKeys) != 1 {
		t.Fatalf("empty snapshot = %#v, %v", empty, err)
	}
	created, err := fixture.service.MutateApplicationUserStorage(ctx, tokens.AccessToken, 0, []d.StorageMutation{{Key: "theme", Action: "PUT", Value: "dark"}})
	if err != nil || !created.Changed || created.Revision != 1 {
		t.Fatalf("create = %#v, %v", created, err)
	}

	results := make(chan error, 2)
	var group sync.WaitGroup
	for _, key := range []string{"locale", "layout"} {
		key := key
		group.Add(1)
		go func() {
			defer group.Done()
			_, mutateErr := fixture.service.MutateApplicationUserStorage(ctx, tokens.AccessToken, 1, []d.StorageMutation{{Key: key, Action: "PUT", Value: "value"}})
			results <- mutateErr
		}()
	}
	group.Wait()
	close(results)
	succeeded, conflicted := 0, 0
	for result := range results {
		switch {
		case result == nil:
			succeeded++
		case errors.Is(result, d.ErrStorageConflict):
			conflicted++
		default:
			t.Fatalf("concurrent mutation = %v", result)
		}
	}
	if succeeded != 1 || conflicted != 1 {
		t.Fatalf("concurrent results: succeeded=%d conflicted=%d", succeeded, conflicted)
	}

	repository, err := NewApplicationUserStorageRepository(fixture.auth.r)
	if err != nil {
		t.Fatal(err)
	}
	changed, err := repository.Clear(ctx, fixture.auth.c.AuthID, applicationID, time.Now().UTC())
	if err != nil || !changed {
		t.Fatalf("clear = %t, %v", changed, err)
	}
	after, err := fixture.service.BatchGetApplicationUserStorage(ctx, tokens.AccessToken, []string{"theme"})
	if err != nil || after.Revision != 0 || len(after.Entries) != 0 || len(after.MissingKeys) != 1 {
		t.Fatalf("after clear = %#v, %v", after, err)
	}
	count, err := fixture.repo.db.Collection(ApplicationUserStorageAuditCollection).CountDocuments(ctx, bson.M{"authId": fixture.auth.c.AuthID, "applicationId": applicationID, "action": "USER_CLEARED"})
	if err != nil || count != 1 {
		t.Fatalf("clear audit count = %d, %v", count, err)
	}
}
