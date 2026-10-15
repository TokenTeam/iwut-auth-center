package main

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"iwut-auth-center/internal/adapter/catalog"
	"iwut-auth-center/internal/config"
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

func TestValidateApplicationUserStorageScopes(t *testing.T) {
	valid := []d.Scope{
		{Name: "storage.read", Kind: "RESOURCE", Audience: "iwut-auth-center", Enabled: true},
		{Name: "storage.write", Kind: "RESOURCE", Audience: "iwut-auth-center", Enabled: true},
	}
	if err := validateApplicationUserStorageScopes(valid); err != nil {
		t.Fatal(err)
	}
	for name, scopes := range map[string][]d.Scope{
		"missing":        valid[:1],
		"disabled":       {{Name: "storage.read", Kind: "RESOURCE", Audience: "iwut-auth-center"}, valid[1]},
		"wrong audience": {{Name: "storage.read", Kind: "RESOURCE", Audience: "other", Enabled: true}, valid[1]},
		"wrong kind":     {{Name: "storage.read", Kind: "PROTOCOL", Enabled: true}, valid[1]},
		"duplicate":      {valid[0], valid[0], valid[1]},
	} {
		t.Run(name, func(t *testing.T) {
			if err := validateApplicationUserStorageScopes(scopes); err == nil {
				t.Fatal("invalid storage scopes accepted")
			}
		})
	}
}

func TestProductionProfileAndScopeManifestsClose(t *testing.T) {
	root := filepath.Join("..", "..", "configs")
	profileJSON, err := os.ReadFile(filepath.Join(root, "profile-fields.production.json"))
	if err != nil {
		t.Fatal(err)
	}
	profileCatalog, err := catalog.NewProfileCatalog(config.ProfileConfig{JSON: profileJSON})
	if err != nil {
		t.Fatal(err)
	}
	definitions, err := profileCatalog.Snapshot(t.Context())
	if err != nil || len(definitions) != 9 {
		t.Fatalf("production definitions = %d, %v", len(definitions), err)
	}
	byKey := map[string]pd.Definition{}
	for _, definition := range definitions {
		byKey[definition.Key] = definition
	}
	for key, valueType := range map[string]pd.ValueType{
		"basic.name": pd.String, "basic.gender": pd.String,
		"education.campus_areas": pd.StringSet, "education.major": pd.String,
		"personal.birthday": pd.Date, "education.campus_card_number": pd.String,
		"contact.phone": pd.String, "contact.qq": pd.String,
		"education.current_grade": pd.AcademicGrade,
	} {
		if definition, ok := byKey[key]; !ok || definition.ValueType != valueType {
			t.Fatalf("production definition %s = %#v", key, definition)
		}
	}
	optionValues := func(key string) []string {
		values := make([]string, 0, len(byKey[key].Constraints.Options))
		for _, option := range byKey[key].Constraints.Options {
			values = append(values, option.Value)
		}
		return values
	}
	if !slices.Equal(optionValues("basic.gender"), []string{"MALE", "FEMALE"}) {
		t.Fatal("gender options drifted", optionValues("basic.gender"))
	}
	if !slices.Equal(optionValues("education.campus_areas"), []string{"NANHU", "JIANHU", "MAFANGSHAN_WEST", "MAFANGSHAN_EAST", "YUJIA_TOU", "JUNSHAN"}) {
		t.Fatal("campus options drifted", optionValues("education.campus_areas"))
	}
	assertDigits := func(key string, minimum, maximum int64) {
		t.Helper()
		constraints := byKey[key].Constraints
		if constraints.CharacterSet != pd.ASCIICharacters || constraints.MinLength == nil || *constraints.MinLength != minimum || constraints.MaxLength == nil || *constraints.MaxLength != maximum {
			t.Fatalf("%s constraints drifted: %#v", key, constraints)
		}
	}
	assertDigits("education.campus_card_number", 6, 6)
	assertDigits("contact.phone", 11, 11)
	assertDigits("contact.qq", 5, 12)
	assertLength := func(key string, minimum, maximum int64) {
		t.Helper()
		constraints := byKey[key].Constraints
		actualMinimum := int64(1)
		if constraints.MinLength != nil {
			actualMinimum = *constraints.MinLength
		}
		if actualMinimum != minimum || constraints.MaxLength == nil || *constraints.MaxLength != maximum {
			t.Fatalf("%s length constraints drifted: %#v", key, constraints)
		}
	}
	assertLength("basic.name", 1, 80)
	assertLength("education.major", 1, 128)
	birthday := byKey["personal.birthday"].Constraints
	if birthday.NotAfterToday == nil || !*birthday.NotAfterToday {
		t.Fatal("birthday upper bound drifted", birthday)
	}
	campus := byKey["education.campus_areas"].Constraints
	if campus.MinItems == nil || *campus.MinItems != 1 || campus.MaxItems == nil || *campus.MaxItems != 6 {
		t.Fatal("campus cardinality drifted", campus)
	}
	scopeJSON, err := os.ReadFile(filepath.Join(root, "oauth-scopes.production.json"))
	if err != nil {
		t.Fatal(err)
	}
	var scopes []d.Scope
	if err = json.Unmarshal(scopeJSON, &scopes); err != nil {
		t.Fatal(err)
	}
	if err = bindUserInfoProfileScopes(scopes, definitions); err != nil {
		t.Fatal(err)
	}
	if err = validateApplicationUserStorageScopes(scopes); err != nil {
		t.Fatal(err)
	}
	profileScopes := 0
	campusScopes := 0
	for _, scope := range scopes {
		if !scope.ValidMetadata() {
			t.Fatalf("invalid production scope metadata: %#v", scope)
		}
		if scope.Kind == "USERINFO_CAMPUS" {
			campusScopes++
			if scope.Name != "campus.whut" || !scope.Enabled || scope.Audience != "" || scope.ProfileField != "" || scope.ProfileValueType != "" {
				t.Fatalf("production campus disclosure drifted: %#v", scope)
			}
		}
		if scope.Kind == "USERINFO_PROFILE" {
			profileScopes++
			if !d.ValidProfileValueType(scope.ProfileValueType) {
				t.Fatalf("unbound profile scope: %#v", scope)
			}
		}
	}
	if profileScopes != 9 {
		t.Fatalf("production profile scopes = %d", profileScopes)
	}
	if campusScopes != 1 {
		t.Fatalf("production campus scopes = %d", campusScopes)
	}
}
