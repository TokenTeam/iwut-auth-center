package mongo

import (
	"testing"
	"time"

	d "iwut-auth-center/internal/oauth/domain"
)

func TestOAuthCatalogCampusValidation(t *testing.T) {
	valid := d.Scope{Name: "campus.whut", Label: "Campus member", Description: "Read permanent campus membership", Kind: "USERINFO_CAMPUS", Enabled: true}
	doc := oauthDocument[d.Catalog]{ID: "current", Data: d.Catalog{Revision: 1, GeneratedAt: time.Now(), Scopes: []d.Scope{valid}}}
	if !validOAuthDocument(doc) {
		t.Fatal("valid campus catalog rejected")
	}
	for _, invalid := range []d.Scope{
		{Name: "campus.other", Label: valid.Label, Description: valid.Description, Kind: "USERINFO_CAMPUS"},
		{Name: "campus.whut", Label: valid.Label, Description: valid.Description, Kind: "RESOURCE", Audience: "resource"},
		{Name: "campus.whut", Label: valid.Label, Description: valid.Description, Kind: "USERINFO_CAMPUS", Audience: "resource"},
		{Name: "campus.whut", Label: valid.Label, Description: valid.Description, Kind: "USERINFO_CAMPUS", ProfileField: "basic.name"},
		{Name: "campus.whut", Label: valid.Label, Description: valid.Description, Kind: "USERINFO_CAMPUS", ProfileValueType: "BOOLEAN"},
	} {
		doc.Data.Scopes = []d.Scope{invalid}
		if validOAuthDocument(doc) {
			t.Fatal("bad campus catalog accepted", invalid)
		}
	}
}
