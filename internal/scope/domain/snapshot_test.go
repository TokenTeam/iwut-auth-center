package domain

import (
	"errors"
	"reflect"
	"testing"
	"time"
)

func TestSnapshot_BR_SCP_002And003_ValidatesCopiesAndSorts(t *testing.T) {
	generatedAt := time.Date(2026, time.September, 21, 8, 0, 0, 0, time.FixedZone("test", 8*60*60))
	second, _ := NewScopeDefinition("schedule.read", true)
	first, _ := NewScopeDefinition("profile.basic", true)
	values := []ScopeDefinition{second, first}

	snapshot, err := NewSnapshot(7, generatedAt, values)
	if err != nil {
		t.Fatalf("NewSnapshot() error = %v", err)
	}
	values[0] = ScopeDefinition{}

	if snapshot.Revision() != 7 || !snapshot.GeneratedAt().Equal(generatedAt.UTC()) {
		t.Fatalf("snapshot metadata = (%d, %v)", snapshot.Revision(), snapshot.GeneratedAt())
	}
	got := snapshot.Scopes()
	if names := []string{got[0].Name(), got[1].Name()}; !reflect.DeepEqual(names, []string{"profile.basic", "schedule.read"}) {
		t.Fatalf("scope names = %v", names)
	}
	got[0] = ScopeDefinition{}
	if snapshot.Scopes()[0].Name() != "profile.basic" {
		t.Fatal("Scopes() exposed mutable internal storage")
	}
}

func TestSnapshot_BR_SCP_002And003_RejectsInvalidValues(t *testing.T) {
	valid, _ := NewScopeDefinition("profile.basic", true)
	now := time.Now()
	tests := []struct {
		name        string
		revision    int64
		generated   time.Time
		definitions []ScopeDefinition
	}{
		{name: "non-positive revision", revision: 0, generated: now},
		{name: "zero generatedAt", revision: 1},
		{name: "empty name", revision: 1, generated: now, definitions: []ScopeDefinition{{}}},
		{name: "duplicate name", revision: 1, generated: now, definitions: []ScopeDefinition{valid, valid}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := NewSnapshot(test.revision, test.generated, test.definitions)
			if !errors.Is(err, ErrInvalidScopeCatalogSnapshot) {
				t.Fatalf("NewSnapshot() error = %v", err)
			}
		})
	}
}

func TestNewScopeDefinition_BR_SCP_004_RejectsEmptyName(t *testing.T) {
	if _, err := NewScopeDefinition("", true); !errors.Is(err, ErrInvalidScopeCatalogSnapshot) {
		t.Fatalf("NewScopeDefinition() error = %v", err)
	}
}
