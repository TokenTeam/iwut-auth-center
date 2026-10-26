package domain

import (
	"testing"
	"time"
)

func TestRequestedDefinitionsDigestIncludesNonJSONMetadata(t *testing.T) {
	definitions := []Scope{
		{Name: "profile.test", Kind: "USERINFO_PROFILE", ProfileField: "test", ProfileValueType: "STRING", Label: "Test", Description: "Test description", Enabled: true},
		{Name: "openid", Kind: "PROTOCOL", Label: "Login", Description: "Identify", Enabled: true},
	}
	digest := RequestedDefinitionsDigest(definitions)
	if digest != RequestedDefinitionsDigest([]Scope{definitions[1], definitions[0]}) {
		t.Fatal("digest depends on catalog order")
	}
	definitions[0].ProfileValueType = "INTEGER"
	if digest == RequestedDefinitionsDigest(definitions) {
		t.Fatal("json-excluded profile type not included in display digest")
	}
	definitions[0].ProfileValueType = "STRING"
	p := ConsentPresentation{ID: "presentation", Digest: digest, Definitions: definitions, PreparedAt: time.Now()}
	if !p.Valid([]string{"openid", "profile.test"}) || p.Valid([]string{"openid"}) {
		t.Fatal("presentation does not bind exact requested definitions")
	}
	definitions[0].Enabled = false
	if p.Valid([]string{"openid", "profile.test"}) {
		t.Fatal("mutated presentation accepted")
	}
}
