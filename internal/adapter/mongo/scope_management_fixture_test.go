package mongo

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"go.mongodb.org/mongo-driver/v2/bson"
	account "iwut-auth-center/internal/account/domain"
	od "iwut-auth-center/internal/oauth/domain"
	d "iwut-auth-center/internal/scopemanagement/domain"
)

// updateOAuthFixtureCatalog uses the real administrator management transaction
// rather than preserving a startup-only update bypass for historical fixtures.
func updateOAuthFixtureCatalog(t *testing.T, repo *OAuthRepository, scopes []od.Scope) error {
	t.Helper()
	var principal struct {
		AuthID string `bson:"authId"`
	}
	if err := repo.db.Collection(PrincipalCollection).FindOne(t.Context(), bson.M{"principalType": "USER", "accountStatus": "ACTIVE"}).Decode(&principal); err != nil {
		return err
	}
	ctx := account.WithIdentity(t.Context(), principal.AuthID, 1)
	if repo.auth.WithAuthTransaction(ctx, func(tx context.Context) error { return repo.auth.RequireAdministratorTx(tx, principal.AuthID) }) != nil {
		var principalRaw bson.Raw
		if err := repo.db.Collection(PrincipalCollection).FindOne(t.Context(), bson.M{"authId": principal.AuthID}).Decode(&principalRaw); err != nil {
			return err
		}
		if principalRaw.Lookup("permissionRevision").Type == 0 {
			if _, err := repo.db.Collection(PrincipalCollection).UpdateOne(t.Context(), bson.M{"authId": principal.AuthID}, bson.M{"$set": bson.M{"permissions": bson.A{}, "permissionRevision": int64(1)}}); err != nil {
				return err
			}
		}
		seedAdministrator(t, repo.auth, principal.AuthID)
	}
	r, err := NewScopeManagementRepository(repo.auth, scopes, func([]od.Scope) error { return nil })
	if err != nil {
		return err
	}
	for _, v := range scopeDefinitions(scopes) {
		snapshot, err := r.Get(ctx, principal.AuthID)
		if err != nil {
			return err
		}
		var old *d.Definition
		for _, current := range snapshot.Scopes {
			if current.Name == v.Name {
				copy := current
				old = &copy
				break
			}
		}
		changes := []d.Change{}
		if old == nil {
			registration := v
			registration.ProfileValueType = ""
			changes = append(changes, d.Change{Kind: "REGISTER", Definition: registration, Contract: v.Description, ProviderEvidence: "real OAuth test provider"})
		} else {
			if !old.StableEqual(v) {
				return od.ErrScope
			}
			if old.Label != v.Label || old.Description != v.Description {
				changes = append(changes, d.Change{Kind: "CORRECT_TEXT", Name: v.Name, Label: v.Label, Description: v.Description})
			}
			if old.Enabled != v.Enabled {
				changes = append(changes, d.Change{Kind: "SET_ENABLED", Name: v.Name, Enabled: v.Enabled})
			}
		}
		for _, change := range changes {
			snapshot, err = r.Get(ctx, principal.AuthID)
			if err != nil {
				return err
			}
			_, err = r.Change(ctx, d.Command{ActorAuthID: principal.AuthID, OperationID: uuid.NewString(), ExpectedRevision: snapshot.Revision, ExpectedDigest: snapshot.Digest, Reason: "explicit test catalog change", Changes: []d.Change{change}})
			if err != nil {
				return err
			}
		}
	}
	return nil
}
