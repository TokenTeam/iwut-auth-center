package transport

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestOAuthStrictFormsAndClientCarriers(t *testing.T) {
	for _, body := range []string{"client_id=a&client_id=b", "client_id=a&client_secret=x", "client_id=a&unknown=x", "client_id=%zz"} {
		r := httptest.NewRequest("POST", "/token", strings.NewReader(body))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		if _, e := oauthForm(r, "client_id"); e == nil {
			t.Fatal(body)
		}
	}
	r := httptest.NewRequest("POST", "/token", nil)
	r.Header.Set("Authorization", "Basic Y2xpZW50OnNlY3JldA==")
	if _, e := oauthProof(r, url.Values{"client_id": {"client"}}); e == nil {
		t.Fatal("mixed authentication")
	}
	for _, v := range []string{"JWT value", "Bearer a", "Bearer " + strings.Repeat("a", 43) + "="} {
		r.Header.Set("Authorization", v)
		if _, e := oauthBearer(r); e == nil {
			t.Fatal("invalid bearer")
		}
	}
	r = httptest.NewRequest("POST", "/confirm", strings.NewReader("interaction=x&csrf=y&decision=approve&scope=openid&scope=email"))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	v, e := oauthConsentForm(r)
	if e != nil || len(v["scope"]) != 2 {
		t.Fatal(e)
	}
}
func TestOAuthDefaultClosedAndPathIsolation(t *testing.T) {
	h := &OAuthHTTP{Issuer: "https://auth.example.test", SectorSuffix: "sectors.example.test"}
	for _, p := range []string{"/v1/users/me/profile", "/login", "/v1/sessions/current"} {
		if h.Handles(httptest.NewRequest("GET", p, nil)) {
			t.Fatal("root issuer captured ordinary endpoint", p)
		}
	}
	r := httptest.NewRequest("GET", "/authorize?client_id=unknown", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusNotFound {
		t.Fatal(w.Code)
	}
}
