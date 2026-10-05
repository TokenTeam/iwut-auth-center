package mongo

import (
	"errors"
	"go.mongodb.org/mongo-driver/v2/bson"
	d "iwut-auth-center/internal/developer/domain"
	p "iwut-auth-center/internal/developer/port"
	u "iwut-auth-center/internal/developer/usecase"
	"testing"
)

func TestBR_DEV_003_LifecycleMongoProjection(t *testing.T) {
	db := integrationDatabase(t)
	_, err := db.Collection(PrincipalCollection).InsertMany(t.Context(), []any{
		bson.M{"authId": "withdrawn", "principalType": "USER", "accountStatus": "ACTIVE", "developerStatus": "WITHDRAWN"},
		bson.M{"authId": "disabled", "principalType": "USER", "accountStatus": "DISABLED", "developerStatus": "SUSPENDED"},
		bson.M{"authId": "closed", "principalType": "USER", "accountStatus": "CLOSED"},
		bson.M{"authId": "broken", "principalType": "USER", "developerStatus": "APPROVED"},
	})
	if err != nil {
		t.Fatal(err)
	}
	repo, _ := NewPrincipalRepository(db)
	h := u.NewBatchGetDeveloperStatusesHandler(repo)
	out, err := h.Handle(t.Context(), []string{"closed", "withdrawn", "disabled"})
	if err != nil || len(out) != 3 {
		t.Fatalf("%v %v", out, err)
	}
	if out[0].AccountStatus != d.AccountClosed || out[0].DeveloperStatus != "" || out[1].DeveloperStatus != d.DeveloperStatusWithdrawn || out[2].AccountStatus != d.AccountDisabled {
		t.Fatalf("%v", out)
	}
	if out, err := h.Handle(t.Context(), []string{"closed", "broken"}); !errors.Is(err, p.ErrDeveloperStatusUnavailable) || out != nil {
		t.Fatalf("%v %v", out, err)
	}
}
