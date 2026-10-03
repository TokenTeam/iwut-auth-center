package oauthclock

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestSigningClockGate(t *testing.T) {
	p := filepath.Join(t.TempDir(), "clock.json")
	if Healthy(p) {
		t.Fatal("missing clock accepted")
	}
	for _, tc := range []struct {
		o    Observation
		want bool
	}{{Observation{time.Now().Add(-time.Second), 0}, true}, {Observation{time.Now().Add(-11 * time.Second), 0}, false}, {Observation{time.Now().Add(time.Second), 0}, false}, {Observation{time.Now().Add(-time.Second), 1001}, false}, {Observation{time.Now().Add(-time.Second), -1001}, false}} {
		b, _ := json.Marshal(tc.o)
		if e := os.WriteFile(p, b, 0600); e != nil {
			t.Fatal(e)
		}
		if Healthy(p) != tc.want {
			t.Fatal(tc)
		}
	}
	b, _ := json.Marshal(map[string]any{"observedAt": time.Now().Add(-time.Second)})
	_ = os.WriteFile(p, b, 0600)
	if Healthy(p) {
		t.Fatal("missing offset accepted")
	}
}
