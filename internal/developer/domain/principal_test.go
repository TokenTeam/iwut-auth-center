package domain

import (
	"strings"
	"testing"
)

func TestNewAuthIDPreservesOpaqueValue(t *testing.T) {
	id, err := NewAuthID("  Auth-ID/Ä  ")
	if err != nil || id.String() != "  Auth-ID/Ä  " {
		t.Fatalf("NewAuthID() = (%q, %v)", id, err)
	}
}

func TestNewAuthIDRejectsInvalidValues(t *testing.T) {
	for _, value := range []string{"", strings.Repeat("a", MaxAuthIDBytes+1), string([]byte{0xff})} {
		if _, err := NewAuthID(value); err == nil {
			t.Fatalf("NewAuthID(%q) accepted", value)
		}
	}
}

func TestNewPrincipalEnforcesTypeSpecificStatus(t *testing.T) {
	id, _ := NewAuthID("auth-1")
	if principal, err := NewPrincipal(id, PrincipalTypeUser, ""); err != nil || principal.DeveloperStatus() != "" {
		t.Fatalf("ordinary USER rejected: (%#v, %v)", principal, err)
	}
	if _, err := NewPrincipal(id, PrincipalTypeUser, "UNKNOWN"); err == nil {
		t.Fatal("USER with invalid status accepted")
	}
	if _, err := NewPrincipal(id, PrincipalTypeSystem, DeveloperStatusApproved); err == nil {
		t.Fatal("SYSTEM with developer status accepted")
	}
	if _, err := NewPrincipal(id, PrincipalTypeUser, DeveloperStatusSuspended); err != nil {
		t.Fatalf("valid USER rejected: %v", err)
	}
}
