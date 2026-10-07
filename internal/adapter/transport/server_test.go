package transport

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	kerrors "github.com/go-kratos/kratos/v2/errors"
	khttp "github.com/go-kratos/kratos/v2/transport/http"
	auth "iwut-auth-center/internal/authentication/domain"
	profiledomain "iwut-auth-center/internal/profile/domain"
)

var defaultServeMuxProbeSequence atomic.Uint64

type httpRegistration struct {
	source string
	calls  int
}

func (r *httpRegistration) Begin(_ context.Context, _ string, _ []byte, _ string, _ []byte, source string) (auth.Challenge, error) {
	r.source = source
	r.calls++
	return auth.Challenge{}, nil
}
func (r *httpRegistration) Complete(context.Context, string, []byte) (auth.Established, error) {
	return auth.Established{}, nil
}

func TestHTTPRegistrationUsesSocketPeerAndStrictJSON(t *testing.T) {
	uc := &httpRegistration{}
	server := newHTTPServer(ServerConfig{HTTPAddr: "127.0.0.1:0", UserEndpoints: &UserEndpoints{Authentication: &AuthenticationService{registration: NewRegistrationHandler(uc)}, Profile: &UserProfileServer{}, MaxAuthenticationMessageBytes: 16384}}, nil)
	for _, tc := range []struct {
		body, path string
		status     int
	}{
		{`{"credentialProposal":{},"association":{}}`, "/v1/registrations", 200},
		{`{"credentialProposal":{},"association":{},"unknown":"secret"}`, "/v1/registrations", 400},
		{`{"credentialProposal":{},"credential_proposal":{},"association":{}}`, "/v1/registrations", 400},
		{`{"credentialProposal":{},"association":{}}`, "/v1/registrations?association.schemeVersion=spoofed", 400},
		{strings.Repeat(" ", 16385), "/v1/registrations", 413},
	} {
		req := httptest.NewRequest("POST", tc.path, strings.NewReader(tc.body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Forwarded-For", "192.0.2.200")
		req.RemoteAddr = "192.0.2.1:12345"
		recorder := httptest.NewRecorder()
		server.ServeHTTP(recorder, req)
		if recorder.Code != tc.status {
			t.Fatalf("%s: %d %s", tc.path, recorder.Code, recorder.Body.String())
		}
		if strings.Contains(recorder.Body.String(), "secret") {
			t.Fatal("raw input leaked")
		}
	}
	if uc.calls != 1 || uc.source != "192.0.2.1" {
		t.Fatalf("calls=%d source=%s", uc.calls, uc.source)
	}
}

func TestHTTPDisabledEndpointsAndInvalidServerConfiguration(t *testing.T) {
	server := newHTTPServer(ServerConfig{HTTPAddr: "127.0.0.1:0"}, nil)
	for _, path := range []string{"/v1/registrations", "/v1/users/me/profile", "/v1/sessions/current", "/v1/identities"} {
		recorder := httptest.NewRecorder()
		server.ServeHTTP(recorder, httptest.NewRequest("POST", path, strings.NewReader(`{}`)))
		if recorder.Code != 404 {
			t.Fatalf("disabled route %s: %d", path, recorder.Code)
		}
	}
	if _, err := NewServers(ServerConfig{}, nil, nil, nil, nil); err == nil {
		t.Fatal("missing HTTP address accepted")
	}
}

func TestHTTPFallbacksDoNotUseDefaultServeMux(t *testing.T) {
	server := newHTTPServer(ServerConfig{HTTPAddr: "127.0.0.1:0"}, nil)
	probeID := defaultServeMuxProbeSequence.Add(1)
	notFoundPath := fmt.Sprintf("/__default_mux_not_found_probe_%d", probeID)
	methodNotAllowedPath := fmt.Sprintf("/__default_mux_method_probe_%d", probeID)
	const defaultMuxStatus = http.StatusTeapot

	http.DefaultServeMux.HandleFunc(notFoundPath, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(defaultMuxStatus)
	})
	http.DefaultServeMux.HandleFunc(methodNotAllowedPath, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(defaultMuxStatus)
	})
	server.Route("/").POST(methodNotAllowedPath, func(khttp.Context) error { return nil })

	tests := []struct {
		name       string
		method     string
		path       string
		wantStatus int
	}{
		{name: "unmatched path", method: http.MethodGet, path: notFoundPath, wantStatus: http.StatusNotFound},
		{name: "unsupported method", method: http.MethodGet, path: methodNotAllowedPath, wantStatus: http.StatusMethodNotAllowed},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			server.ServeHTTP(recorder, httptest.NewRequest(test.method, test.path, nil))
			if recorder.Code != test.wantStatus {
				t.Fatalf("response status = %d, want %d; DefaultServeMux fallback status is %d", recorder.Code, test.wantStatus, defaultMuxStatus)
			}
		})
	}
}

func TestHTTPErrorStatusPreservesBusinessReason(t *testing.T) {
	for _, tc := range []struct {
		err    error
		status int
		reason string
	}{
		{profileError(profiledomain.ErrLimit), 413, "USER_PROFILE_LIMIT_EXCEEDED"},
		{profileError(profiledomain.ErrExhausted), 409, "USER_PROFILE_REVISION_EXHAUSTED"},
		{profileError(profiledomain.ErrConflict), 409, "USER_PROFILE_REVISION_CONFLICT"},
		{kerrors.New(429, "REGISTRATION_RATE_LIMITED", "limited"), 429, "REGISTRATION_RATE_LIMITED"},
	} {
		recorder := httptest.NewRecorder()
		authHTTPErrorEncoder(recorder, httptest.NewRequest("PATCH", "/v1/users/me/profile", nil), tc.err)
		if recorder.Code != tc.status || !strings.Contains(recorder.Body.String(), tc.reason) {
			t.Fatalf("%d %s", recorder.Code, recorder.Body.String())
		}
	}
}

// Decoding must bound reads even without Content-Length (chunked clients).
type httpCountingBody struct{ read int }

func (b *httpCountingBody) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = ' '
	}
	b.read += len(p)
	return len(p), nil
}
func (*httpCountingBody) Close() error { return nil }
func TestHTTPBoundsChunkedBodyBeforeAllocation(t *testing.T) {
	b := &httpCountingBody{}
	req := httptest.NewRequest("POST", "/v1/device-logins", nil)
	req.Body = b
	req.ContentLength = -1
	req.Header.Set("Content-Type", "application/json")
	err := authHTTPDecoder(64)(req, nil)
	if kerrors.FromError(err).Code != 413 || b.read != 65 {
		t.Fatalf("read=%d error=%v", b.read, err)
	}
}

func TestHTTPProfileIdentityCannotBeReplacedBySession(t *testing.T) {
	server := newHTTPServer(ServerConfig{HTTPAddr: "127.0.0.1:0", UserEndpoints: &UserEndpoints{Authentication: &AuthenticationService{}, Profile: &UserProfileServer{}, MaxAuthenticationMessageBytes: 16384}}, nil)
	req := httptest.NewRequest("GET", "/v1/users/me/profile", nil)
	req.Header.Set("X-Iwut-Session", strings.Repeat("A", 43))
	recorder := httptest.NewRecorder()
	server.ServeHTTP(recorder, req)
	if recorder.Code != 401 {
		t.Fatalf("missing profile identity accepted: %d", recorder.Code)
	}
}

var _ io.ReadCloser = (*httpCountingBody)(nil)

func TestHTTPProfilePreservesRevisionAndNullValidation(t *testing.T) {
	for _, tc := range []struct{ body, reason string }{
		{`{"expectedRevision":"9223372036854775808","remove":["x"]}`, "INVALID_USER_PROFILE_EXPECTED_REVISION"},
		{`{"expectedRevision":null,"remove":["x"]}`, "INVALID_USER_PROFILE_EXPECTED_REVISION"},
		{`{"remove":["x"]}`, "INVALID_USER_PROFILE_EXPECTED_REVISION"},
		{`{"expectedRevision":"1","set":null,"remove":["x"]}`, "INVALID_USER_PROFILE_EDIT"},
		{`{"expectedRevision":"1","set":[{"key":"x","value":{"booleanValue":null,"stringValue":"x"}}]}`, "INVALID_USER_PROFILE_EDIT"},
	} {
		err := validateProfileJSON([]byte(tc.body))
		if err == nil || kerrors.FromError(err).Reason != tc.reason {
			t.Fatalf("%s: %v", tc.body, err)
		}
	}
}
