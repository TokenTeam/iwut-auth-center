package domain

import (
	"strings"
	"testing"
)

func commandFixture() Command {
	return Command{ActorAuthID: "admin", OperationID: "90c77db1-e62b-458c-a53b-98bc0bc44424", ExpectedRevision: 1, ExpectedDigest: strings.Repeat("a", 64), Reason: "correct definition", Changes: []Change{{Kind: "SET_ENABLED", Name: "email", Enabled: false}}}
}

func TestCommandBoundariesAndTypedChanges(t *testing.T) {
	base := commandFixture()
	if !base.Valid() {
		t.Fatal("base invalid")
	}
	for name, edit := range map[string]func(*Command){
		"uuid uppercase":  func(c *Command) { c.OperationID = strings.ToUpper(c.OperationID) },
		"uuid version":    func(c *Command) { c.OperationID = "90c77db1-e62b-158c-a53b-98bc0bc44424" },
		"uuid variant":    func(c *Command) { c.OperationID = "90c77db1-e62b-458c-753b-98bc0bc44424" },
		"digest":          func(c *Command) { c.ExpectedDigest = strings.Repeat("A", 64) },
		"reason bytes":    func(c *Command) { c.Reason = strings.Repeat("中", 342) },
		"duplicate":       func(c *Command) { c.Changes = append(c.Changes, c.Changes[0]) },
		"empty":           func(c *Command) { c.Changes = nil },
		"untyped fields":  func(c *Command) { c.Changes[0].Description = "not allowed" },
		"wrong operation": func(c *Command) { c.Changes[0].Kind = "DELETE" },
	} {
		t.Run(name, func(t *testing.T) {
			c := base
			c.Changes = append([]Change(nil), base.Changes...)
			edit(&c)
			if c.Valid() {
				t.Fatal("invalid command accepted")
			}
		})
	}
	base.Reason = strings.Repeat("a", 1024)
	if !base.Valid() {
		t.Fatal("max bytes rejected")
	}
	base.Reason = "  explanation  "
	if base.Valid() || !base.Normalize().Valid() {
		t.Fatal("normalization")
	}
}

func TestDigestCanonicalAndIncludesHiddenProfileType(t *testing.T) {
	profile := Definition{Name: "profile.basic.name", Label: "Name", Description: "Read name", Kind: "USERINFO_PROFILE", ProfileField: "basic.name", ProfileValueType: "STRING", Enabled: true}
	email := Definition{Name: "email", Label: "Email", Description: "Read email", Kind: "PROTOCOL", Enabled: true}
	a, err := Digest([]Definition{profile, email})
	if err != nil {
		t.Fatal(err)
	}
	b, _ := Digest([]Definition{email, profile})
	if a != b {
		t.Fatal("order-dependent digest")
	}
	profile.ProfileValueType = "DATE"
	b, _ = Digest([]Definition{email, profile})
	if a == b {
		t.Fatal("profile type omitted")
	}
	profile.ProfileValueType = "STRING"
	profile.Description += " corrected"
	b, _ = Digest([]Definition{email, profile})
	if a == b {
		t.Fatal("text omitted")
	}
	profile.Description = "Read name"
	profile.Enabled = false
	b, _ = Digest([]Definition{email, profile})
	if a == b {
		t.Fatal("enablement omitted")
	}
}

func TestRequestDigestBindsActorAndAllCommandFields(t *testing.T) {
	a := commandFixture()
	first, _ := RequestDigest(a)
	for _, edit := range []func(*Command){func(c *Command) { c.ActorAuthID = "other" }, func(c *Command) { c.Reason = "other" }, func(c *Command) { c.ExpectedRevision++ }, func(c *Command) { c.Changes[0].Enabled = true }} {
		b := a
		b.Changes = append([]Change(nil), a.Changes...)
		edit(&b)
		digest, err := RequestDigest(b)
		if err != nil || digest == first {
			t.Fatal("command field omitted", err)
		}
	}
}

func TestStableMetadataAndCapacity(t *testing.T) {
	v := Definition{Name: "openid", Label: "Login", Description: "Login identity", Kind: "PROTOCOL", Enabled: true}
	wrong := v
	wrong.Kind = "RESOURCE"
	wrong.Audience = "fake"
	if wrong.Valid() {
		t.Fatal("reserved name redefined")
	}
	if _, err := CanonicalDefinitions([]Definition{v, v}); err == nil {
		t.Fatal("duplicate name accepted")
	}
	scopes := []Definition{}
	for i := 0; i < 33; i++ {
		s := Definition{Name: "data." + strings.Repeat("x", i+1), Label: "Data", Description: "Read data", Kind: "RESOURCE", Audience: "data"}
		scopes = append(scopes, s)
	}
	if _, err := CanonicalDefinitions(scopes[:32]); err != nil {
		t.Fatal("32 rejected", err)
	}
	if _, err := CanonicalDefinitions(scopes); err == nil {
		t.Fatal("33 accepted")
	}
}
