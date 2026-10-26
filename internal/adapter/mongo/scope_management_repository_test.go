package mongo

import (
	"errors"
	"strings"
	"testing"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	od "iwut-auth-center/internal/oauth/domain"
	d "iwut-auth-center/internal/scopemanagement/domain"
)

func TestScopeManagementStrictCatalogAndOperationBSON(t *testing.T) {
	catalog := od.Catalog{Revision: 1, GeneratedAt: time.Now().UTC().Truncate(time.Millisecond), Scopes: []od.Scope{{Name: "email", Label: "Email", Description: "Read verified email", Kind: "PROTOCOL", Enabled: true}}}
	encode := func(v any) bson.Raw {
		t.Helper()
		raw, err := bson.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	if _, err := decodeManagedCatalog(encode(oauthDocument[od.Catalog]{ID: "current", Data: catalog})); err != nil {
		t.Fatal(err)
	}
	for name, edit := range map[string]func(bson.M){
		"missing enabled": func(v bson.M) { delete(v["data"].(bson.M)["scopes"].(bson.A)[0].(bson.M), "enabled") },
		"int32 revision":  func(v bson.M) { v["data"].(bson.M)["revision"] = int32(1) },
		"wrong bool":      func(v bson.M) { v["data"].(bson.M)["scopes"].(bson.A)[0].(bson.M)["enabled"] = "true" },
		"unknown field":   func(v bson.M) { v["data"].(bson.M)["unexpected"] = true },
		"missing type":    func(v bson.M) { delete(v["data"].(bson.M)["scopes"].(bson.A)[0].(bson.M), "profilevaluetype") },
	} {
		t.Run(name, func(t *testing.T) {
			doc := bson.M{"_id": "current", "data": bson.M{"revision": int64(1), "generatedat": catalog.GeneratedAt, "scopes": bson.A{bson.M{"name": "email", "label": "Email", "description": "Read verified email", "kind": "PROTOCOL", "audience": "", "profilefield": "", "profilevaluetype": "", "enabled": true}}}}
			edit(doc)
			if _, err := decodeManagedCatalog(encode(doc)); !errors.Is(err, d.ErrUnavailable) {
				t.Fatal("malformed accepted", err)
			}
		})
	}
	op := d.Operation{OperationID: "90c77db1-e62b-458c-a53b-98bc0bc44424", RequestDigest: strings.Repeat("a", 64), ActorAuthID: "admin", Reason: "reason", Outcome: "APPLIED", BaseRevision: 1, ResultRevision: 2, ResultGeneratedAt: catalog.GeneratedAt, ResultDigest: strings.Repeat("b", 64), OccurredAt: catalog.GeneratedAt}
	if _, err := decodeScopeOperation(encode(operationDocumentScope(op)), op.OperationID); err != nil {
		t.Fatal(err)
	}
	bad := operationDocumentScope(op)
	bad["outcome"] = "UNKNOWN"
	if _, err := decodeScopeOperation(encode(bad), op.OperationID); err == nil {
		t.Fatal("nonterminal receipt accepted")
	}
	bad = operationDocumentScope(op)
	bad["resultRevision"] = int32(2)
	if _, err := decodeScopeOperation(encode(bad), op.OperationID); err == nil {
		t.Fatal("malformed receipt accepted")
	}
}

func TestScopeManagementApplyRestrictsDeliveredProviderAndStableMapping(t *testing.T) {
	base := d.Definition{Name: "openid", Label: "Login", Description: "Identify user", Kind: "PROTOCOL", Enabled: true}
	provider := d.Definition{Name: "profile.basic.name", Label: "Name", Description: "Read name", Kind: "USERINFO_PROFILE", ProfileField: "basic.name", ProfileValueType: "STRING", Enabled: true}
	r := &ScopeManagementRepository{providers: map[string]d.Definition{provider.Name: provider}}
	reg := provider
	reg.ProfileValueType = ""
	after, contracts, err := r.apply([]d.Definition{base}, []d.Change{{Kind: "REGISTER", Definition: reg, Contract: "Read name", ProviderEvidence: "UC028"}})
	if err != nil || len(after) != 2 || len(contracts) != 1 || after[1].ProfileValueType != "STRING" {
		t.Fatal(after, contracts, err)
	}
	if _, _, err := r.apply(after, []d.Change{{Kind: "REGISTER", Definition: reg}}); !errors.Is(err, d.ErrBlocked) {
		t.Fatal("same name registered", err)
	}
	reg.Name = "profile.basic.name.v2"
	if _, _, err := r.apply([]d.Definition{base}, []d.Change{{Kind: "REGISTER", Definition: reg}}); !errors.Is(err, d.ErrBlocked) {
		t.Fatal("alias registered", err)
	}
	if _, _, err := r.apply([]d.Definition{base}, []d.Change{{Kind: "REGISTER", Definition: d.Definition{Name: "arbitrary", Label: "Arbitrary", Description: "Arbitrary", Kind: "RESOURCE", Audience: "fake-service"}}}); !errors.Is(err, d.ErrBlocked) {
		t.Fatal("fake provider", err)
	}
	if _, _, err := r.apply([]d.Definition{base}, []d.Change{{Kind: "SET_ENABLED", Name: "missing"}}); !errors.Is(err, d.ErrBlocked) {
		t.Fatal("unknown enabled", err)
	}
}
