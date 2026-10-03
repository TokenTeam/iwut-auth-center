package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestOAuthRouteDigestAndAmbiguity(t *testing.T) {
	p := filepath.Join(t.TempDir(), "policy.json")
	policy := routePolicy{Version: 1, Routes: []oauthRouteJSON{{ID: "read", Audience: "data", Protocol: "HTTP", Method: "GET", Path: "/data/{id}", Scopes: []string{"z.read", "a.read"}, Channels: []string{"TEST"}}}}
	write := func() {
		b, _ := json.MarshalIndent(policy, "", "  ")
		if e := os.WriteFile(p, b, 0600); e != nil {
			t.Fatal(e)
		}
	}
	write()
	a, e := loadOAuthRoutes(p, nil)
	if e != nil {
		t.Fatal(e)
	}
	policy.Routes[0].Scopes = []string{"a.read", "z.read"}
	write()
	b, e := loadOAuthRoutes(p, nil)
	if e != nil || a.Digest != b.Digest {
		t.Fatal("unstable policy digest", e)
	}
	policy.Routes = append(policy.Routes, oauthRouteJSON{ID: "ambiguous", Audience: "another", Protocol: "HTTP", Method: "GET", Path: "/data/fixed", Scopes: []string{"a.read"}, Channels: []string{"TEST"}})
	write()
	if _, e := loadOAuthRoutes(p, nil); e == nil {
		t.Fatal("ambiguous route accepted")
	}
}
