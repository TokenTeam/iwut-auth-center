package transport

import (
	"encoding/json"
	d "iwut-auth-center/internal/oauth/domain"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
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
	r = httptest.NewRequest("POST", "/confirm", strings.NewReader("interaction=x&csrf=y&presentation=z&decision=approve&scope=openid&scope=email"))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	v, e := oauthConsentForm(r)
	if e != nil || len(v["scope"]) != 2 || v.Get("presentation") != "z" {
		t.Fatal(e)
	}
	r = httptest.NewRequest("POST", "/confirm", strings.NewReader("interaction=x&csrf=y&presentation=a&presentation=b&decision=approve"))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if _, err := oauthConsentForm(r); err == nil {
		t.Fatal("duplicate presentation accepted")
	}
}

func TestUserInfoResponseExtendedProfileJSON(t *testing.T) {
	confirmed := time.Now()
	response, err := userInfoResponse(d.UserInfo{Subject: "sub", Profile: []d.ProfileEntry{
		{Key: "education.campus_areas", Value: d.ProfileValue{Type: "STRING_SET", Strings: []string{"JIANHU", "NANHU"}}},
		{Key: "education.current_grade", Value: d.ProfileValue{Type: "ACADEMIC_GRADE", Integer: 4, Academic: &d.ProfileGrade{Stage: "UNDERGRADUATE", Year: 3, FinalYear: 4, AcademicYear: 2025, ConfirmedAt: &confirmed}}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(response)
	if err != nil {
		t.Fatal(err)
	}
	body := string(encoded)
	if !strings.Contains(body, `"education.campus_areas":["JIANHU","NANHU"]`) || !strings.Contains(body, `"education.current_grade":"UNDERGRADUATE_4"`) {
		t.Fatal("extended values missing", body)
	}
	for _, forbidden := range []string{"academicYear", "finalYear", "confirmedAt", "2025"} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("grade anchor leaked (%s): %s", forbidden, body)
		}
	}
}

func TestUserInfoCampusResponseOnlyExposesMinimalFact(t *testing.T) {
	response, err := userInfoResponse(d.UserInfo{Subject: "pairwise", Campus: &d.CampusCertification{AuthID: "internal-auth-id", Institution: "WHUT", CertifiedAt: time.Now()}})
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(response)
	if err != nil {
		t.Fatal(err)
	}
	if string(encoded) != `{"iwut_campus":{"certified":true,"institution":"WHUT"},"sub":"pairwise"}` {
		t.Fatalf("campus claim leaked extra fields: %s", encoded)
	}
	response, err = userInfoResponse(d.UserInfo{Subject: "pairwise"})
	if err != nil {
		t.Fatal(err)
	}
	if _, exists := response["iwut_campus"]; exists {
		t.Fatal("absent certification exposed")
	}
	if _, err = userInfoResponse(d.UserInfo{Subject: "pairwise", Campus: &d.CampusCertification{Institution: "OTHER", CertifiedAt: time.Now()}}); err == nil {
		t.Fatal("bad campus fact serialized")
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

func TestOAuthHTTPObservableOperationIsBounded(t *testing.T) {
	handler := &OAuthHTTP{Issuer: "https://auth.example.test/oidc", SectorSuffix: "sectors.example.test"}
	tests := []struct {
		path, host, want string
	}{
		{"/oidc/authorize", "auth.example.test", "oauth.authorize"},
		{"/oidc/token", "auth.example.test", "oauth.token"},
		{"/oidc/revoke", "auth.example.test", "oauth.revoke"},
		{"/oidc/userinfo", "auth.example.test", "oauth.userinfo"},
		{"/oidc/jwks", "auth.example.test", "oauth.jwks"},
		{"/oidc/.well-known/openid-configuration", "auth.example.test", "oauth.discovery"},
		{"/oidc/portal/session", "auth.example.test", "oauth.portal.session"},
		{"/oidc/portal/interaction", "auth.example.test", "oauth.portal.interaction"},
		{"/oidc/portal/interactions/attacker-controlled/confirm", "auth.example.test", "oauth.portal.confirm"},
		{"/oidc/attacker-controlled", "auth.example.test", "oauth.unmatched"},
		{"/redirect-uris.json", "client.sectors.example.test", "oauth.redirect_uris"},
	}
	for _, test := range tests {
		request := httptest.NewRequest(http.MethodGet, test.path, nil)
		request.Host = test.host
		if !handler.Handles(request) {
			t.Fatalf("%s was not handled", test.path)
		}
		if got := handler.ObservableOperation(request); got != test.want {
			t.Fatalf("%s operation = %q, want %q", test.path, got, test.want)
		} else if strings.Contains(got, "attacker-controlled") {
			t.Fatalf("operation leaked path: %q", got)
		}
	}
}
