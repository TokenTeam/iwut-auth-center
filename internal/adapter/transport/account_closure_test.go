package transport

import (
	"context"
	"encoding/base64"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	pb "github.com/TokenTeam/iwut-api-proto/gen/go/auth_center/v1/account_closure"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protowire"
	d "iwut-auth-center/internal/accountclosure/domain"
	"iwut-auth-center/internal/adapter/deviceprotocol"
)

type closureStub struct{ calls int }

func (s *closureStub) Begin(context.Context, d.BeginInput) (d.Challenge, error) {
	s.calls++
	return d.Challenge{OperationID: "99999999-9999-4999-8999-000000000001", ExpiresAt: time.Unix(1800000300, 0)}, nil
}
func (s *closureStub) Prepare(context.Context, string, []byte) (d.Preparation, error) {
	s.calls++
	return d.Preparation{Outcome: "BLOCKED", Blocker: d.AdminBlocker}, nil
}
func (s *closureStub) Confirm(context.Context, string, string, string, string) (d.Status, error) {
	s.calls++
	return d.Status{State: d.TerminationPending, CleanupProgress: "AUTH_PENDING"}, nil
}
func (s *closureStub) Cancel(context.Context, string, string) (d.Status, error) {
	s.calls++
	return d.Status{State: d.Cancelled, CleanupProgress: "NOT_STARTED"}, nil
}
func (s *closureStub) Get(context.Context, string, string) (d.Status, error) {
	s.calls++
	return d.Status{State: d.CleanupComplete, CleanupProgress: "COMPLETE"}, nil
}
func closureTransportFixture(t *testing.T, enabled bool) (*AccountClosureService, *closureStub) {
	t.Helper()
	gate, err := deviceprotocol.NewLimiter(deviceprotocol.RateLimits{BeginGlobal: 1000, CompleteGlobal: 1000, BeginSource: 1000, CompleteLocator: 1000, MaxBuckets: 1000})
	if err != nil {
		t.Fatal(err)
	}
	h := &closureStub{}
	return NewAccountClosureService(h, enabled, gate), h
}
func TestClosureDedicatedTokenCarriers(t *testing.T) {
	token := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	for _, tc := range []struct {
		name string
		md   metadata.MD
		want codes.Code
	}{
		{"valid", metadata.Pairs(ClosureReceiptHeader, token), codes.OK},
		{"missing", nil, codes.Unauthenticated},
		{"wrong_purpose", metadata.Pairs(ClosureConfirmationHeader, token), codes.Unauthenticated},
		{"duplicate", metadata.Pairs(ClosureReceiptHeader, token, ClosureReceiptHeader, token), codes.Unauthenticated},
		{"bearer", metadata.Pairs(ClosureReceiptHeader, token, "authorization", ""), codes.Unauthenticated},
		{"session", metadata.Pairs(ClosureReceiptHeader, token, "x-iwut-session", token), codes.Unauthenticated},
		{"identity", metadata.Pairs(ClosureReceiptHeader, token, UserIdentityHeader, ""), codes.Unauthenticated},
		{"whitespace", metadata.Pairs(ClosureReceiptHeader, " "+token), codes.Unauthenticated},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, h := closureTransportFixture(t, true)
			ctx := metadata.NewIncomingContext(t.Context(), tc.md)
			_, err := s.GetAccountClosure(ctx, &pb.GetAccountClosureRequest{OperationId: "operation"})
			if status.Code(err) != tc.want {
				t.Fatalf("got %v want %v", err, tc.want)
			}
			if tc.want != codes.OK && h.calls != 0 {
				t.Fatal("invalid carrier reached core")
			}
		})
	}
	s, h := closureTransportFixture(t, true)
	ctx := metadata.NewIncomingContext(t.Context(), metadata.Pairs(ClosureReceiptHeader, token))
	if _, err := s.ConfirmAccountClosure(ctx, &pb.ConfirmAccountClosureRequest{}); status.Code(err) != codes.Unauthenticated || h.calls != 0 {
		t.Fatal("receipt authorized confirmation", err)
	}
}
func TestClosurePublicGatePreservesReceiptAndCancellation(t *testing.T) {
	s, h := closureTransportFixture(t, false)
	token := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	if _, err := s.BeginAccountClosure(t.Context(), &pb.BeginAccountClosureRequest{}); status.Code(err) != codes.Unavailable {
		t.Fatal(err)
	}
	if h.calls != 0 {
		t.Fatal("disabled mutation reached core")
	}
	ctx := metadata.NewIncomingContext(t.Context(), metadata.Pairs(ClosureReceiptHeader, token))
	if _, err := s.GetAccountClosure(ctx, &pb.GetAccountClosureRequest{}); err != nil {
		t.Fatal(err)
	}
	ctx = metadata.NewIncomingContext(t.Context(), metadata.Pairs(ClosureConfirmationHeader, token))
	if _, err := s.CancelAccountClosure(ctx, &pb.CancelAccountClosureRequest{}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ConfirmAccountClosure(ctx, &pb.ConfirmAccountClosureRequest{}); status.Code(err) != codes.Unavailable {
		t.Fatal(err)
	}
}
func TestClosureStrictHTTPAndNoStore(t *testing.T) {
	s, _ := closureTransportFixture(t, true)
	server := newHTTPServer(ServerConfig{HTTPAddr: "127.0.0.1:0", AccountClosure: s, UserEndpoints: &UserEndpoints{Authentication: &AuthenticationService{}, Profile: &UserProfileServer{}, MaxAuthenticationMessageBytes: 64 * 1024}}, nil)
	for _, tc := range []struct {
		body, path string
		status     int
	}{
		{`{"requestId":"request","credentialId":"44444444-4444-4444-8444-444444444444"}`, "/v1/account-closures:begin", 200},
		{`{"requestId":"a","request_id":"b"}`, "/v1/account-closures:begin", 400},
		{`{"requestId":"a","unknown":"secret"}`, "/v1/account-closures:begin", 400},
		{`{"operationId":"a"}`, "/v1/account-closures:get?receiptToken=secret", 400},
		{strings.Repeat(" ", 16385), "/v1/account-closures:begin", 413},
	} {
		r := httptest.NewRequest("POST", tc.path, strings.NewReader(tc.body))
		r.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		server.ServeHTTP(w, r)
		if w.Code != tc.status || w.Header().Get("Cache-Control") != "no-store" || strings.Contains(w.Body.String(), "secret") {
			t.Fatalf("%s: %d %s", tc.path, w.Code, w.Body.String())
		}
	}
}
func TestClosureWireRejectsDuplicateAndConflictingLocator(t *testing.T) {
	field := func(n protowire.Number, v string) []byte {
		return protowire.AppendString(protowire.AppendTag(nil, n, protowire.BytesType), v)
	}
	valid := append(field(1, "request"), field(2, "credential")...)
	codec := NewProfileStrictCodec(64 * 1024)
	for _, data := range [][]byte{append(append([]byte{}, valid...), field(2, "other")...), append(append([]byte{}, valid...), field(3, "fingerprint")...), field(9, "unknown"), []byte{0x0a, 0xff}, make([]byte, 16385)} {
		if err := codec.Unmarshal(data, &pb.BeginAccountClosureRequest{}); err == nil {
			t.Fatal("invalid wire accepted")
		}
	}
	if err := codec.Unmarshal(valid, &pb.BeginAccountClosureRequest{}); err != nil {
		t.Fatal(err)
	}
	var nilRequest *pb.BeginAccountClosureRequest
	s, _ := closureTransportFixture(t, true)
	if _, err := s.BeginAccountClosure(t.Context(), nilRequest); status.Code(err) != codes.InvalidArgument {
		t.Fatal("nil request accepted", err)
	}
}
