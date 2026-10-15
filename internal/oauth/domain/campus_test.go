package domain

import (
	"slices"
	"testing"
)

func TestCampusScopeHasOneReservedMeaning(t *testing.T) {
	valid := Scope{Name: "campus.whut", Kind: "USERINFO_CAMPUS", Enabled: true}
	if !valid.ValidMetadata() || !slices.Equal((Catalog{Scopes: []Scope{valid}}).Enabled(false), []string{"campus.whut"}) {
		t.Fatal("campus disclosure scope was not enabled")
	}
	for name, invalid := range map[string]Scope{
		"other campus": {Name: "campus.other", Kind: "USERINFO_CAMPUS", Enabled: true},
		"resource":     {Name: "campus.whut", Kind: "RESOURCE", Audience: "auth", Enabled: true},
		"protocol":     {Name: "campus.whut", Kind: "PROTOCOL", Enabled: true},
		"audience":     {Name: "campus.whut", Kind: "USERINFO_CAMPUS", Audience: "auth", Enabled: true},
		"profile":      {Name: "campus.whut", Kind: "USERINFO_CAMPUS", ProfileField: "education.campus_areas", Enabled: true},
		"value type":   {Name: "campus.whut", Kind: "USERINFO_CAMPUS", ProfileValueType: "BOOLEAN", Enabled: true},
	} {
		t.Run(name, func(t *testing.T) {
			if invalid.ValidMetadata() || len((Catalog{Scopes: []Scope{invalid}}).Enabled(true)) != 0 {
				t.Fatal("invalid campus meaning was enabled", invalid)
			}
		})
	}
	valid.Enabled = false
	if len((Catalog{Scopes: []Scope{valid}}).Enabled(true)) != 0 {
		t.Fatal("disabled campus scope was enabled")
	}
}
