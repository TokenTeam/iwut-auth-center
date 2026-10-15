package transport

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	kerrors "github.com/go-kratos/kratos/v2/errors"
	khttp "github.com/go-kratos/kratos/v2/transport/http"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/test/bufconn"
	profiledomain "iwut-auth-center/internal/profile/domain"
)

var defaultServeMuxProbeSequence atomic.Uint64

func TestHTTPNoEmailRegistrationIsRetired(t *testing.T) {
	server := newHTTPServer(ServerConfig{HTTPAddr: "127.0.0.1:0", UserEndpoints: &UserEndpoints{Authentication: &AuthenticationService{}, Profile: &UserProfileServer{}, MaxAuthenticationMessageBytes: 16384}}, nil)
	for _, path := range []string{"/v1/registrations", "/v1/registrations/11111111-1111-4111-8111-111111111111/completion"} {
		for _, body := range []string{`{"credentialProposal":{},"association":{}}`, `{"unknown":"secret"}`, strings.Repeat(" ", 16385)} {
			req := httptest.NewRequest("POST", path, strings.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			recorder := httptest.NewRecorder()
			server.ServeHTTP(recorder, req)
			if recorder.Code != http.StatusNotFound {
				t.Fatalf("%s still callable: %d %s", path, recorder.Code, recorder.Body.String())
			}
			if strings.Contains(recorder.Body.String(), "secret") {
				t.Fatal("raw input leaked")
			}
		}
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

func TestGRPCStandardHealthIsServing(t *testing.T) {
	server := newGRPCServer(
		ServerConfig{GRPCAddr: "127.0.0.1:0"},
		nil,
		NewScopeCatalogService(nil),
		NewDeveloperStatusService(nil),
		NewSystemPrincipalService(nil),
	)
	listener := bufconn.Listen(1 << 20)
	go func() { _ = server.Server.Serve(listener) }()
	t.Cleanup(server.Server.Stop)
	connection, err := grpc.DialContext(t.Context(), "bufnet",
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return listener.Dial() }),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatalf("dial health server: %v", err)
	}
	t.Cleanup(func() { _ = connection.Close() })
	response, err := healthpb.NewHealthClient(connection).Check(t.Context(), &healthpb.HealthCheckRequest{})
	if err != nil || response.GetStatus() != healthpb.HealthCheckResponse_SERVING {
		t.Fatalf("gRPC health = %v, %v", response, err)
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

func TestHTTPRoutesUseConfiguredObservabilityBoundaries(t *testing.T) {
	observed := make(chan string, 4)
	wrap := func(operation string, next http.Handler) http.Handler {
		return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			observed <- operation
			next.ServeHTTP(writer, request)
		})
	}
	server := newHTTPServer(ServerConfig{
		HTTPAddr:             "127.0.0.1:0",
		OAuth:                &OAuthHTTP{Issuer: "https://auth.example.test", Enabled: false},
		DirectHTTPMiddleware: wrap,
		ReadinessCheck:       func(context.Context) error { return nil },
		ReadinessTimeout:     time.Second,
	}, nil)

	for _, test := range []struct {
		method, path, operation string
		status                  int
	}{
		{http.MethodPost, "/token", "oauth.token", http.StatusNotFound},
		{http.MethodGet, "/livez", "http.health.livez", http.StatusOK},
		{http.MethodGet, "/readyz", "http.health.readyz", http.StatusOK},
	} {
		recorder := httptest.NewRecorder()
		server.ServeHTTP(recorder, httptest.NewRequest(test.method, test.path, nil))
		if recorder.Code != test.status {
			t.Fatalf("%s status = %d, want %d", test.path, recorder.Code, test.status)
		}
		select {
		case operation := <-observed:
			if operation != test.operation {
				t.Fatalf("%s operation = %q, want %q", test.path, operation, test.operation)
			}
		default:
			t.Fatalf("%s bypassed direct observability", test.path)
		}
	}
}

func TestHTTPUsesConfiguredFallbackHandlers(t *testing.T) {
	notFoundCalls, methodCalls := 0, 0
	server := newHTTPServer(ServerConfig{
		HTTPAddr: "127.0.0.1:0",
		HTTPNotFoundHandler: http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
			notFoundCalls++
			writer.WriteHeader(http.StatusNotFound)
		}),
		HTTPMethodNotAllowedHandler: http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
			methodCalls++
			writer.WriteHeader(http.StatusMethodNotAllowed)
		}),
	}, nil)
	server.Route("/").POST("/method-only", func(khttp.Context) error { return nil })
	server.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/missing-sensitive-id", nil))
	server.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/method-only", nil))
	if notFoundCalls != 1 || methodCalls != 1 {
		t.Fatalf("fallback calls = notFound %d, method %d", notFoundCalls, methodCalls)
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
