package transport

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	pb "github.com/TokenTeam/iwut-api-proto/gen/go/auth_center/v1/session_management"
	kerrors "github.com/go-kratos/kratos/v2/errors"
	"github.com/go-kratos/kratos/v2/middleware"
	kt "github.com/go-kratos/kratos/v2/transport"
	kgrpc "github.com/go-kratos/kratos/v2/transport/grpc"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/encoding"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
	d "iwut-auth-center/internal/sessionmanagement/domain"
)

type sessionManagementStub struct {
	calls   int
	digest  []byte
	size    int
	cursor  string
	targets []string
	page    d.Page
	err     error
}

func (s *sessionManagementStub) List(_ context.Context, digest []byte, size int, cursor string) (d.Page, error) {
	s.calls++
	s.digest = append([]byte(nil), digest...)
	s.size = size
	s.cursor = cursor
	return s.page, s.err
}
func (s *sessionManagementStub) Revoke(_ context.Context, digest []byte, ids []string) error {
	s.calls++
	s.digest = append([]byte(nil), digest...)
	s.targets = append([]string(nil), ids...)
	return s.err
}

type sessionManagementGate struct {
	denied bool
	source string
}

func (g *sessionManagementGate) AllowSource(source string, _ time.Time) bool {
	g.source = source
	return !g.denied
}
func managementToken() string {
	return base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x31}, 32))
}
func managementContext(t *testing.T) context.Context {
	return metadata.NewIncomingContext(t.Context(), metadata.Pairs("x-iwut-session", managementToken()))
}
func managementPage() d.Page {
	stamp := time.Unix(1800000000, 123000000).UTC()
	return d.Page{CurrentSessionID: "current", ObservedAt: stamp, NextCursor: "filtered-anchor", Sessions: []d.Summary{
		{SessionID: "current", CredentialID: "device", AuthenticationMethod: "DEVICE_CREDENTIAL", AuthenticatedAt: stamp, CreatedAt: stamp, LastUsedAt: stamp, ExpiresAt: stamp.Add(time.Hour), IsCurrent: true},
		{SessionID: "email", CredentialID: "other-device", AuthenticationMethod: "EMAIL_CODE_AND_DEVICE", AuthenticatedAt: stamp, CreatedAt: stamp, LastUsedAt: stamp, ExpiresAt: stamp.Add(time.Hour)},
	}}
}
func TestSessionManagementCanonicalCarrier(t *testing.T) {
	token := managementToken()
	tests := []struct {
		name string
		md   metadata.MD
	}{
		{"missing", nil}, {"empty", metadata.Pairs("x-iwut-session", "")},
		{"duplicate", metadata.Pairs("x-iwut-session", token, "x-iwut-session", token)},
		{"padded", metadata.Pairs("x-iwut-session", token+"=")},
		{"whitespace", metadata.Pairs("x-iwut-session", " "+token)},
		{"noncanonical-pad-bits", metadata.Pairs("x-iwut-session", strings.Repeat("A", 42)+"B")},
	}
	for _, header := range []string{"authorization", "cookie", "x-iwut-identity", "x-iwut-service-identity"} {
		tests = append(tests, struct {
			name string
			md   metadata.MD
		}{header, metadata.Pairs("x-iwut-session", token, header, "")})
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h := &sessionManagementStub{}
			s := NewSessionManagementService(h, &sessionManagementGate{})
			_, err := s.ListOwnSessions(metadata.NewIncomingContext(t.Context(), tc.md), &pb.ListOwnSessionsRequest{})
			if status.Code(err) != codes.InvalidArgument || kerrors.FromError(err).Reason != "INVALID_SESSION_TOKEN" || h.calls != 0 {
				t.Fatalf("err=%v calls=%d", err, h.calls)
			}
		})
	}
}
func TestSessionManagementConversionAndDefaults(t *testing.T) {
	h := &sessionManagementStub{page: managementPage()}
	s := NewSessionManagementService(h, &sessionManagementGate{})
	out, err := s.ListOwnSessions(managementContext(t), &pb.ListOwnSessionsRequest{})
	digest := sha256.Sum256(bytes.Repeat([]byte{0x31}, 32))
	if err != nil || h.size != 10 || !bytes.Equal(h.digest, digest[:]) {
		t.Fatalf("output=%v err=%v size=%d digest=%x", out, err, h.size, h.digest)
	}
	if out.CurrentSessionId != "current" || out.NextCursor != "filtered-anchor" || len(out.Sessions) != 2 || out.Sessions[0].AuthenticationMethod != pb.AuthenticationMethod_DEVICE_CREDENTIAL || !out.Sessions[0].IsCurrent || out.Sessions[1].AuthenticationMethod != pb.AuthenticationMethod_EMAIL_CODE_AND_DEVICE || !out.ObservedAt.AsTime().Equal(h.page.ObservedAt) {
		t.Fatal(out)
	}
	size := int32(23)
	if _, err = s.ListOwnSessions(managementContext(t), &pb.ListOwnSessionsRequest{PageSize: &size, Cursor: "anchor"}); err != nil || h.size != 23 || h.cursor != "anchor" {
		t.Fatal(h, err)
	}
	targets := []string{"explicit-target-one", "explicit-target-two"}
	if _, err = s.RevokeOwnSessions(managementContext(t), &pb.RevokeOwnSessionsRequest{SessionIds: targets}); err != nil || !reflect.DeepEqual(h.targets, targets) {
		t.Fatal(h, err)
	}
	h.page.Sessions = nil
	out, err = s.ListOwnSessions(managementContext(t), &pb.ListOwnSessionsRequest{})
	if err != nil || len(out.Sessions) != 0 || out.NextCursor != "filtered-anchor" {
		t.Fatalf("empty page lost continuation: %v %v", out, err)
	}
	h.page.Sessions = []d.Summary{{AuthenticationMethod: "UNRECOGNIZED"}}
	if _, err = s.ListOwnSessions(managementContext(t), &pb.ListOwnSessionsRequest{}); status.Code(err) != codes.Unavailable {
		t.Fatal(err)
	}
	h.page = managementPage()
	h.page.ObservedAt = time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC)
	if _, err = s.ListOwnSessions(managementContext(t), &pb.ListOwnSessionsRequest{}); status.Code(err) != codes.Unavailable {
		t.Fatal(err)
	}
}
func TestSessionManagementErrorMapping(t *testing.T) {
	for _, tc := range []struct {
		err    error
		code   codes.Code
		http   int
		reason string
	}{
		{d.ErrInvalidRequest, codes.InvalidArgument, 400, d.ErrInvalidRequest.Error()},
		{fmt.Errorf("private detail: %w", d.ErrInvalidCursor), codes.InvalidArgument, 400, d.ErrInvalidCursor.Error()},
		{d.ErrCurrentSession, codes.InvalidArgument, 400, d.ErrCurrentSession.Error()},
		{d.ErrSessionInvalid, codes.Unauthenticated, 401, d.ErrSessionInvalid.Error()},
		{d.ErrRateLimited, codes.ResourceExhausted, 429, d.ErrRateLimited.Error()},
		{fmt.Errorf("private detail"), codes.Unavailable, 503, d.ErrUnavailable.Error()},
	} {
		t.Run(tc.reason, func(t *testing.T) {
			err := sessionManagementError(t.Context(), tc.err)
			if status.Code(err) != tc.code || kerrors.FromError(err).Reason != tc.reason {
				t.Fatal(err)
			}
			w := httptest.NewRecorder()
			authHTTPErrorEncoder(w, httptest.NewRequest("POST", "/v1/users/me/sessions:list", nil), err)
			if w.Code != tc.http || w.Header().Get("Cache-Control") != "no-store" || strings.Contains(w.Body.String(), "private detail") {
				t.Fatalf("%d %s %v", w.Code, w.Body.String(), w.Header())
			}
			if tc.http == 429 && w.Header().Get("Retry-After") != "60" {
				t.Fatal(w.Header())
			}
		})
	}
}
func TestSessionManagementRequestAndWireBoundaries(t *testing.T) {
	codec := NewProfileStrictCodec()
	bytesField := func(n protowire.Number, v string) []byte {
		return protowire.AppendString(protowire.AppendTag(nil, n, protowire.BytesType), v)
	}
	for _, tc := range []struct {
		name    string
		data    []byte
		request proto.Message
	}{
		{"duplicate-size", []byte{8, 10, 8, 11}, &pb.ListOwnSessionsRequest{}},
		{"duplicate-cursor", append(bytesField(2, "a"), bytesField(2, "b")...), &pb.ListOwnSessionsRequest{}},
		{"unknown-list", []byte{24, 1}, &pb.ListOwnSessionsRequest{}},
		{"zero-size", []byte{8, 0}, &pb.ListOwnSessionsRequest{}},
		{"overflow-size", protowire.AppendVarint([]byte{8}, 1<<32+1), &pb.ListOwnSessionsRequest{}},
		{"unknown-revoke", bytesField(2, "a"), &pb.RevokeOwnSessionsRequest{}},
		{"wrong-wire-type", []byte{8, 1}, &pb.RevokeOwnSessionsRequest{}},
		{"invalid-utf8", bytesField(1, string([]byte{0xff})), &pb.RevokeOwnSessionsRequest{}},
		{"too-many-targets", bytes.Repeat(bytesField(1, "a"), 51), &pb.RevokeOwnSessionsRequest{}},
		{"oversize", bytesField(2, strings.Repeat("a", 16384)), &pb.ListOwnSessionsRequest{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := codec.Unmarshal(tc.data, tc.request); err != nil {
				t.Fatalf("codec must defer UC020 rejection to handler: %v", err)
			}
			h := &sessionManagementStub{}
			service := NewSessionManagementService(h, &sessionManagementGate{})
			var err error
			switch request := tc.request.(type) {
			case *pb.ListOwnSessionsRequest:
				_, err = service.ListOwnSessions(managementContext(t), request)
			case *pb.RevokeOwnSessionsRequest:
				_, err = service.RevokeOwnSessions(managementContext(t), request)
			}
			if status.Code(err) != codes.InvalidArgument || kerrors.FromError(err).Reason != d.ErrInvalidRequest.Error() || h.calls != 0 {
				t.Fatalf("invalid wire reached usecase or lost reason: %v calls=%d", err, h.calls)
			}
		})
	}
	request := &pb.RevokeOwnSessionsRequest{}
	if err := codec.Unmarshal(append(bytesField(1, "first"), bytesField(1, "second")...), request); err != nil || !reflect.DeepEqual(request.SessionIds, []string{"first", "second"}) {
		t.Fatal(request, err)
	}
	h := &sessionManagementStub{}
	s := NewSessionManagementService(h, &sessionManagementGate{})
	for _, request := range []*pb.ListOwnSessionsRequest{nil, {Cursor: strings.Repeat("x", 16384)}} {
		if _, err := s.ListOwnSessions(managementContext(t), request); status.Code(err) != codes.InvalidArgument {
			t.Fatal(err)
		}
	}
	unknown := &pb.ListOwnSessionsRequest{}
	unknown.ProtoReflect().SetUnknown([]byte{24, 1})
	if _, err := s.ListOwnSessions(managementContext(t), unknown); status.Code(err) != codes.InvalidArgument || h.calls != 0 {
		t.Fatal(err, h.calls)
	}
}
func TestSessionManagementHTTPStrictBoundary(t *testing.T) {
	h := &sessionManagementStub{page: managementPage()}
	gate := &sessionManagementGate{}
	server := newHTTPServer(ServerConfig{HTTPAddr: "127.0.0.1:0", UserEndpoints: &UserEndpoints{Authentication: &AuthenticationService{}, Profile: &UserProfileServer{}, SessionManagement: NewSessionManagementService(h, gate), MaxAuthenticationMessageBytes: 65536}}, nil)
	for _, tc := range []struct {
		name, body, suffix string
		want               int
	}{
		{"valid", "{}", "list", 200}, {"null-root", "null", "list", 400}, {"null-page-size", `{"pageSize":null}`, "list", 400},
		{"null-cursor", `{"cursor":null}`, "list", 400}, {"unknown", `{"secret":"private"}`, "list", 400},
		{"duplicate", `{"pageSize":1,"pageSize":2}`, "list", 400}, {"alias-duplicate", `{"pageSize":1,"page_size":2}`, "list", 400},
		{"oversize", strings.Repeat(" ", 16385) + `{}`, "list", 400}, {"query", "{}", "list?pageSize=1", 400},
		{"null-list", `{"sessionIds":null}`, "revoke", 400}, {"null-item", `{"sessionIds":[null]}`, "revoke", 400},
	} {
		t.Run(tc.name, func(t *testing.T) {
			before := h.calls
			r := httptest.NewRequest("POST", "/v1/users/me/sessions:"+tc.suffix, strings.NewReader(tc.body))
			r.Header.Set("Content-Type", "application/json")
			r.Header.Set("X-Iwut-Session", managementToken())
			r.Header.Set("X-Forwarded-For", "192.0.2.99")
			r.RemoteAddr = "192.0.2.1:12000"
			w := httptest.NewRecorder()
			server.ServeHTTP(w, r)
			if w.Code != tc.want || w.Header().Get("Cache-Control") != "no-store" {
				t.Fatalf("%d %s %v", w.Code, w.Body.String(), w.Header())
			}
			if tc.want == 400 && (h.calls != before || !strings.Contains(w.Body.String(), d.ErrInvalidRequest.Error())) {
				t.Fatal(w.Body.String(), h.calls, before)
			}
		})
	}
	if gate.source != "192.0.2.1" {
		t.Fatal(gate.source)
	}
	for _, header := range []string{"Authorization", "Cookie", "X-Iwut-Identity", "X-Iwut-Service-Identity"} {
		r := httptest.NewRequest("POST", "/v1/users/me/sessions:list", strings.NewReader(`{}`))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("X-Iwut-Session", managementToken())
		r.Header[header] = []string{""}
		w := httptest.NewRecorder()
		server.ServeHTTP(w, r)
		if w.Code != 400 || !strings.Contains(w.Body.String(), "INVALID_SESSION_TOKEN") {
			t.Fatal(header, w.Code, w.Body.String())
		}
	}
	gate.denied = true
	r := httptest.NewRequest("POST", "/v1/users/me/sessions:list", strings.NewReader(`{}`))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("X-Iwut-Session", managementToken())
	w := httptest.NewRecorder()
	server.ServeHTTP(w, r)
	if w.Code != 429 || w.Header().Get("Retry-After") != "60" {
		t.Fatal(w.Code, w.Header(), w.Body.String())
	}
}
func TestSessionManagementExactDispatchDoesNotTouchSession(t *testing.T) {
	touches := 0
	touching := func(next middleware.Handler) middleware.Handler {
		return func(ctx context.Context, r any) (any, error) { touches++; return next(ctx, r) }
	}
	calls := 0
	handler := userEndpointAuthenticationMiddleware(nil, touching, touching, true)(func(context.Context, any) (any, error) { calls++; return nil, nil })
	for _, method := range []string{pb.SessionManagementService_ListOwnSessions_FullMethodName, pb.SessionManagementService_RevokeOwnSessions_FullMethodName} {
		if _, err := handler(kt.NewServerContext(t.Context(), dispatchTransport{method}), &pb.ListOwnSessionsRequest{}); err != nil {
			t.Fatal(err)
		}
		if _, err := handler(kt.NewServerContext(t.Context(), dispatchTransport{method + "Unknown"}), &pb.ListOwnSessionsRequest{}); status.Code(err) != codes.PermissionDenied {
			t.Fatal(err)
		}
	}
	if calls != 2 || touches != 0 {
		t.Fatal(calls, touches)
	}
}
func TestSessionManagementNativeListenerMetadata(t *testing.T) {
	for _, tc := range []struct {
		name    string
		failure error
		denied  bool
		code    codes.Code
	}{
		{"success", nil, false, codes.OK}, {"invalid-session", d.ErrSessionInvalid, false, codes.Unauthenticated},
		{"account-rate", d.ErrRateLimited, false, codes.ResourceExhausted}, {"source-rate", nil, true, codes.ResourceExhausted},
		{"unavailable", d.ErrUnavailable, false, codes.Unavailable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			h := &sessionManagementStub{page: managementPage(), err: tc.failure}
			gate := &sessionManagementGate{denied: tc.denied}
			server := kgrpc.NewServer(kgrpc.Listener(listener), kgrpc.Middleware(userEndpointAuthenticationMiddleware(nil, nil, nil, true)), kgrpc.Options(grpc.ForceServerCodec(NewProfileStrictCodec())))
			pb.RegisterSessionManagementServiceServer(server, NewSessionManagementService(h, gate))
			done := make(chan error, 1)
			go func() { done <- server.Start(context.Background()) }()
			t.Cleanup(func() { _ = server.Stop(context.Background()); <-done })
			conn, err := grpc.NewClient(listener.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			client := pb.NewSessionManagementServiceClient(conn)
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			ctx = metadata.NewOutgoingContext(ctx, metadata.Pairs("x-iwut-session", managementToken(), "x-forwarded-for", "192.0.2.99"))
			var headers metadata.MD
			out, err := client.ListOwnSessions(ctx, &pb.ListOwnSessionsRequest{}, grpc.Header(&headers))
			if status.Code(err) != tc.code || !reflect.DeepEqual(headers.Get("cache-control"), []string{"no-store"}) {
				t.Fatal(out, err, headers)
			}
			if tc.code == codes.OK && out.GetCurrentSessionId() != "current" {
				t.Fatal(out)
			}
			if tc.code == codes.ResourceExhausted && !reflect.DeepEqual(headers.Get("retry-after"), []string{"60"}) {
				t.Fatal(headers)
			}
			// Await server shutdown before inspecting the handler's captured socket peer.
			_ = server.Stop(context.Background())
			if gate.source != "127.0.0.1" {
				t.Fatal(gate.source)
			}
		})
	}
}

// Marshal deliberately preserves malformed wire bytes while response decoding
// remains the normal Proto codec. This verifies grpc-go's actual decoder path.
type managementRawCodec struct{ encoding.Codec }

func (c managementRawCodec) Marshal(v any) ([]byte, error) {
	if data, ok := v.([]byte); ok {
		return data, nil
	}
	return c.Codec.Marshal(v)
}
func TestSessionManagementNativeMalformedWireReturnsBusinessError(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	h := &sessionManagementStub{page: managementPage()}
	gate := &sessionManagementGate{}
	server := kgrpc.NewServer(kgrpc.Listener(listener), kgrpc.Middleware(userEndpointAuthenticationMiddleware(nil, nil, nil, true)), kgrpc.Options(grpc.ForceServerCodec(NewProfileStrictCodec())))
	pb.RegisterSessionManagementServiceServer(server, NewSessionManagementService(h, gate))
	done := make(chan error, 1)
	go func() { done <- server.Start(context.Background()) }()
	t.Cleanup(func() { _ = server.Stop(context.Background()); <-done })
	conn, err := grpc.NewClient(listener.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	ctx = metadata.NewOutgoingContext(ctx, metadata.Pairs("x-iwut-session", managementToken()))
	rawCodec := managementRawCodec{encoding.GetCodec("proto")}
	for _, tc := range []struct {
		name   string
		data   []byte
		method string
	}{
		{"duplicate-size", []byte{8, 10, 8, 11}, pb.SessionManagementService_ListOwnSessions_FullMethodName},
		{"unknown", []byte{24, 1}, pb.SessionManagementService_ListOwnSessions_FullMethodName},
		{"truncated", []byte{18, 3, 'a'}, pb.SessionManagementService_ListOwnSessions_FullMethodName},
		{"oversize", protowire.AppendString([]byte{18}, strings.Repeat("x", 16384)), pb.SessionManagementService_ListOwnSessions_FullMethodName},
		{"revoke-truncated", []byte{10, 3, 'a'}, pb.SessionManagementService_RevokeOwnSessions_FullMethodName},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var headers metadata.MD
			var response proto.Message = &pb.OwnSessionPage{}
			if tc.method == pb.SessionManagementService_RevokeOwnSessions_FullMethodName {
				response = &pb.SessionsRevoked{}
			}
			err := conn.Invoke(ctx, tc.method, tc.data, response, grpc.ForceCodec(rawCodec), grpc.Header(&headers))
			if status.Code(err) != codes.InvalidArgument || kerrors.FromError(err).Reason != d.ErrInvalidRequest.Error() || !reflect.DeepEqual(headers.Get("cache-control"), []string{"no-store"}) {
				t.Fatalf("error=%v headers=%v", err, headers)
			}
		})
	}
	var headers metadata.MD
	zero := int32(0)
	_, err = pb.NewSessionManagementServiceClient(conn).ListOwnSessions(ctx, &pb.ListOwnSessionsRequest{PageSize: &zero}, grpc.Header(&headers))
	if status.Code(err) != codes.InvalidArgument || kerrors.FromError(err).Reason != d.ErrInvalidRequest.Error() || !reflect.DeepEqual(headers.Get("cache-control"), []string{"no-store"}) {
		t.Fatalf("explicit zero: error=%v headers=%v", err, headers)
	}
	_ = server.Stop(context.Background())
	if h.calls != 0 || gate.source != "127.0.0.1" {
		t.Fatalf("malformed request calls=%d source=%q", h.calls, gate.source)
	}
}
