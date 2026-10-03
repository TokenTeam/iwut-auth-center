package usecase

import "testing"

func TestDelegationCanonicalPathBinding(t *testing.T) {
	for _, p := range []string{"/data/%2f", "/data/%5c", "/data/..", "/data/%2e%2e", "/data/%252f", "/data/a?token=x", "/data//a", "/data/a\\b", "/data/%00"} {
		if matchPath("/data/{id}", p) {
			t.Fatal("ambiguous path accepted", p)
		}
	}
	if !matchPath("/data/{id}", "/data/abc") || matchPath("/data/{id}", "/other/abc") {
		t.Fatal("path binding")
	}
}
