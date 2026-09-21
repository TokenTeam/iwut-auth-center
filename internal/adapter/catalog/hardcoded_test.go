package catalog

import (
	"reflect"
	"testing"
)

func TestHardcodedCatalog_BR_SCP_002_ReturnsStableCompleteSnapshot(t *testing.T) {
	catalog, err := NewHardcodedCatalog()
	if err != nil {
		t.Fatalf("NewHardcodedCatalog() error = %v", err)
	}
	first, err := catalog.GetSnapshot(t.Context())
	if err != nil {
		t.Fatalf("GetSnapshot() error = %v", err)
	}
	second, err := catalog.GetSnapshot(t.Context())
	if err != nil {
		t.Fatalf("GetSnapshot() second error = %v", err)
	}
	if first.Revision() != HardcodedRevision || !first.GeneratedAt().Equal(HardcodedGeneratedAt) {
		t.Fatalf("snapshot metadata = (%d, %v)", first.Revision(), first.GeneratedAt())
	}
	var names []string
	for _, definition := range first.Scopes() {
		names = append(names, definition.Name())
	}
	if !reflect.DeepEqual(names, []string{"legacy.profile", "profile.basic", "schedule.read"}) {
		t.Fatalf("scope names = %v", names)
	}
	if second.Revision() != first.Revision() || !second.GeneratedAt().Equal(first.GeneratedAt()) {
		t.Fatal("same hardcoded revision changed across reads")
	}
}
