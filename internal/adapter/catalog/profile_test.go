package catalog

import (
	"context"
	"iwut-auth-center/internal/config"
	"testing"
)

func TestProfileCatalogExplicitEmptyAndInvalid(t *testing.T) {
	for _, raw := range []string{"", `{}`, `{"definitions":null}`, `{"definitions":[],"surprise":1}`, `{"definitions":[{"key":"x","label":"X","description":"X","valueType":"BOOLEAN"}]}`, `{"definitions":[{"key":"x","label":"X","description":"X","valueType":"BOOLEAN","constraints":{"minimum":0}}]}`} {
		if _, e := NewProfileCatalog(config.ProfileConfig{JSON: []byte(raw)}); e == nil {
			t.Fatalf("invalid catalog accepted %s", raw)
		}
	}
	p, e := NewProfileCatalog(config.ProfileConfig{JSON: []byte(`{"definitions":[]}`)})
	if e != nil {
		t.Fatal(e)
	}
	defs, e := p.Snapshot(context.Background())
	if e != nil || len(defs) != 0 {
		t.Fatal("explicit empty rejected")
	}
}
