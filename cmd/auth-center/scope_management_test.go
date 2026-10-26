package main

import (
	"testing"

	d "iwut-auth-center/internal/oauth/domain"
)

func TestScopeCatalogDeploymentGates(t *testing.T) {
	scopes := []d.Scope{
		{Name: "openid", Kind: "PROTOCOL", Enabled: true},
		{Name: "email", Kind: "PROTOCOL", Enabled: false},
		{Name: "storage.read", Kind: "RESOURCE", Audience: "iwut-auth-center", Enabled: true},
		{Name: "storage.write", Kind: "RESOURCE", Audience: "iwut-auth-center", Enabled: true},
		{Name: "items.read", Kind: "RESOURCE", Audience: "items", Enabled: true},
	}
	routes := map[string]d.Route{"items": {Audience: "items", Scopes: []string{"items.read"}}}
	if err := validateOAuthCatalogDeployment(scopes, true, true, true, routes); err != nil {
		t.Fatalf("unrelated disabled email must remain restartable: %v", err)
	}
	for _, name := range []string{"storage.read", "storage.write", "items.read"} {
		t.Run(name, func(t *testing.T) {
			changed := append([]d.Scope(nil), scopes...)
			for i := range changed {
				if changed[i].Name == name {
					changed[i].Enabled = false
				}
			}
			if validateOAuthCatalogDeployment(changed, true, true, true, routes) == nil {
				t.Fatal("accepted disabling a required deployment scope")
			}
		})
	}
	if validateOAuthCatalogDeployment(scopes, false, true, true, routes) == nil || validateOAuthCatalogDeployment(scopes, true, false, true, routes) == nil {
		t.Fatal("accepted a resource deployment without readiness")
	}
	wrongAudience := append([]d.Scope(nil), scopes...)
	wrongAudience[len(wrongAudience)-1].Audience = "other"
	if validateOAuthCatalogDeployment(wrongAudience, true, true, true, routes) == nil {
		t.Fatal("accepted an audience mismatch")
	}
}
