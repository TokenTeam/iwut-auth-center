package main

import (
	"errors"
	"testing"

	d "iwut-auth-center/internal/oauth/domain"
	pd "iwut-auth-center/internal/profile/domain"
)

func TestBindUserInfoProfileScopes(t *testing.T) {
	definitions := []pd.Definition{{Key: "basic.name", ValueType: pd.String}}
	valid := []d.Scope{{Name: "openid", Kind: "PROTOCOL"}, {Name: "profile.basic.name", Kind: "USERINFO_PROFILE", ProfileField: "basic.name"}}
	if err := bindUserInfoProfileScopes(valid, definitions); err != nil || valid[1].ProfileValueType != "STRING" {
		t.Fatalf("valid mapping = %#v, %v", valid, err)
	}
	for name, scopes := range map[string][]d.Scope{
		"unknown field":   {{Name: "profile.missing", Kind: "USERINFO_PROFILE", ProfileField: "missing"}},
		"wrong name":      {{Name: "profile.other", Kind: "USERINFO_PROFILE", ProfileField: "basic.name"}},
		"audience":        {{Name: "profile.basic.name", Kind: "USERINFO_PROFILE", ProfileField: "basic.name", Audience: "resource"}},
		"supplied type":   {{Name: "profile.basic.name", Kind: "USERINFO_PROFILE", ProfileField: "basic.name", ProfileValueType: "STRING"}},
		"duplicate field": {{Name: "profile.basic.name", Kind: "USERINFO_PROFILE", ProfileField: "basic.name"}, {Name: "profile.basic.name", Kind: "USERINFO_PROFILE", ProfileField: "basic.name"}},
		"metadata leak":   {{Name: "items.read", Kind: "RESOURCE", ProfileField: "basic.name"}},
	} {
		t.Run(name, func(t *testing.T) {
			if err := bindUserInfoProfileScopes(scopes, definitions); !errors.Is(err, d.ErrScope) {
				t.Fatalf("error = %v", err)
			}
		})
	}
}
