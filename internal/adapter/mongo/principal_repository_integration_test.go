package mongo

import (
	"context"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	drivermongo "go.mongodb.org/mongo-driver/v2/mongo"

	"iwut-auth-center/internal/developer/domain"
	"iwut-auth-center/internal/developer/port"
)

const mongoIntegrationURIEnvironment = "MONGODB_INTEGRATION_URI"

func TestPrincipalRepository_BatchGetAndUniqueAuthID(t *testing.T) {
	database := integrationDatabase(t)
	if err := EnsurePrincipalSchema(t.Context(), database); err != nil {
		t.Fatalf("EnsurePrincipalSchema() error = %v", err)
	}
	collection := database.Collection(PrincipalCollection)
	_, err := collection.InsertMany(t.Context(), []any{
		bson.M{"authId": "user-a", "principalType": "USER", "developerStatus": "APPROVED"},
		bson.M{"authId": "user-b", "principalType": "USER", "developerStatus": "SUSPENDED"},
		bson.M{"authId": "ordinary-user", "principalType": "USER", "developerStatus": nil},
	})
	if err != nil {
		t.Fatalf("insert fixtures: %v", err)
	}
	_, err = collection.InsertOne(t.Context(), bson.M{"authId": "user-a", "principalType": "USER", "developerStatus": "PENDING"})
	if !drivermongo.IsDuplicateKeyError(err) {
		t.Fatalf("duplicate insert error = %v, want duplicate key", err)
	}

	repository, err := NewPrincipalRepository(database)
	if err != nil {
		t.Fatalf("NewPrincipalRepository() error = %v", err)
	}
	authIDA, _ := domain.NewAuthID("user-a")
	authIDB, _ := domain.NewAuthID("user-b")
	ordinaryAuthID, _ := domain.NewAuthID("ordinary-user")
	principals, err := repository.BatchGet(t.Context(), []domain.AuthID{authIDB, ordinaryAuthID, authIDA})
	if err != nil {
		t.Fatalf("BatchGet() error = %v", err)
	}
	got := make(map[domain.AuthID]domain.DeveloperStatus, len(principals))
	for _, principal := range principals {
		got[principal.AuthID()] = principal.DeveloperStatus()
	}
	if got[authIDA] != domain.DeveloperStatusApproved || got[authIDB] != domain.DeveloperStatusSuspended || got[ordinaryAuthID] != "" {
		t.Fatalf("statuses = %v", got)
	}
}

func TestPrincipalRepository_CorruptRecordFailsClosed(t *testing.T) {
	database := integrationDatabase(t)
	if err := EnsurePrincipalSchema(t.Context(), database); err != nil {
		t.Fatalf("EnsurePrincipalSchema() error = %v", err)
	}
	_, err := database.Collection(PrincipalCollection).InsertOne(t.Context(), bson.M{
		"authId": "corrupt-user", "principalType": "USER", "developerStatus": "UNKNOWN",
	})
	if err != nil {
		t.Fatalf("insert corrupt fixture: %v", err)
	}
	repository, err := NewPrincipalRepository(database)
	if err != nil {
		t.Fatalf("NewPrincipalRepository() error = %v", err)
	}
	authID, _ := domain.NewAuthID("corrupt-user")
	_, err = repository.BatchGet(t.Context(), []domain.AuthID{authID})
	if !errors.Is(err, port.ErrDeveloperStatusUnavailable) {
		t.Fatalf("BatchGet() error = %v, want ErrDeveloperStatusUnavailable", err)
	}
}

func integrationDatabase(t *testing.T) *drivermongo.Database {
	t.Helper()
	uri := os.Getenv(mongoIntegrationURIEnvironment)
	if uri == "" {
		t.Skipf("set %s or run scripts/test-mongo-integration.sh", mongoIntegrationURIEnvironment)
	}
	client, err := NewClient(uri)
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}
	database, err := NewDatabase(client, fmt.Sprintf("iwut_auth_center_repository_%d", time.Now().UnixNano()))
	if err != nil {
		t.Fatalf("NewDatabase() error = %v", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = database.Drop(ctx)
		_ = client.Disconnect(ctx)
	})
	return database
}
