package domain

import (
	"math"
	"testing"
)

func TestCredentialCutoffAndGovernance(t *testing.T) {
	// Disable/restore may increase account revision but not the cutoff.
	if !EligibleCredential(1, 1, 3) {
		t.Fatal("restore retired a valid device")
	}
	if EligibleCredential(1, 4, 4) || !EligibleCredential(4, 4, 4) || EligibleCredential(5, 4, 4) {
		t.Fatal("cutoff invalid")
	}
	for _, values := range [][3]int64{{0, 1, 1}, {1, 0, 1}, {1, 2, 1}, {1, 1, 0}, {math.MaxInt64, 1, 1}, {1, 1, math.MaxInt64}} {
		if _, _, err := NextRevisions(values[0], values[1], values[2]); err == nil {
			t.Fatal("bad revision accepted")
		}
	}
	account, password, err := NextRevisions(3, 1, 2)
	if err != nil || account != 4 || password != 3 {
		t.Fatal("wrong next revision")
	}
}
