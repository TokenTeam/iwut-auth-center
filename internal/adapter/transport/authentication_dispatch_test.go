package transport

import (
	"context"
	"testing"

	"github.com/go-kratos/kratos/v2/middleware"
	kt "github.com/go-kratos/kratos/v2/transport"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	authv1 "iwut-auth-center/api/gen/go/auth_center/v1/authentication"
)

type dispatchTransport struct{ operation string }

func (t dispatchTransport) Kind() kt.Kind            { return kt.KindGRPC }
func (t dispatchTransport) Endpoint() string         { return "grpc://test" }
func (t dispatchTransport) Operation() string        { return t.operation }
func (t dispatchTransport) RequestHeader() kt.Header { return dispatchHeader{} }
func (t dispatchTransport) ReplyHeader() kt.Header   { return dispatchHeader{} }

type dispatchHeader struct{}

func (dispatchHeader) Get(string) string      { return "" }
func (dispatchHeader) Set(string, string)     {}
func (dispatchHeader) Add(string, string)     {}
func (dispatchHeader) Keys() []string         { return nil }
func (dispatchHeader) Values(string) []string { return nil }

func TestAuthenticationDispatchExactMethodsAndMissingPolicies(t *testing.T) {
	for _, test := range []struct {
		method string
		want   codes.Code
	}{
		{authv1.AuthenticationService_BeginDeviceLogin_FullMethodName, codes.OK},
		{authv1.AuthenticationService_RevokeCurrentSession_FullMethodName, codes.OK},
		{authv1.AuthenticationService_RevokeOwnCredential_FullMethodName, codes.Unauthenticated},
		{"/auth_center.v1.user_profile.UserProfileService/EditOwnProfile", codes.Unauthenticated},
		{"/auth_center.v1.authentication.AuthenticationService/Unknown", codes.PermissionDenied},
		{authv1.AuthenticationService_BeginDeviceLogin_FullMethodName + "/other", codes.PermissionDenied},
	} {
		t.Run(test.method, func(t *testing.T) {
			called := false
			h := userEndpointAuthenticationMiddleware(nil, nil, nil, true)(func(context.Context, any) (any, error) {
				called = true
				return nil, nil
			})
			ctx := kt.NewServerContext(t.Context(), dispatchTransport{test.method})
			_, err := h(ctx, &authv1.RevokeCurrentSessionRequest{})
			if status.Code(err) != test.want || called != (test.want == codes.OK) {
				t.Fatalf("code=%v called=%t want=%v", status.Code(err), called, test.want)
			}
		})
	}
}

func TestAuthenticationDispatchDoesNotSubstituteCredentialTypes(t *testing.T) {
	var profileCalls, sessionCalls int
	count := func(counter *int) middleware.Middleware {
		return func(next middleware.Handler) middleware.Handler {
			return func(ctx context.Context, req any) (any, error) {
				*counter++
				return next(ctx, req)
			}
		}
	}
	h := userEndpointAuthenticationMiddleware(nil, count(&profileCalls), count(&sessionCalls), true)(func(context.Context, any) (any, error) { return nil, nil })
	for _, method := range []string{
		authv1.AuthenticationService_RevokeCurrentSession_FullMethodName,
		authv1.AuthenticationService_RevokeOwnCredential_FullMethodName,
		"/auth_center.v1.user_profile.UserProfileService/GetOwnProfile",
	} {
		if _, err := h(kt.NewServerContext(t.Context(), dispatchTransport{method}), &authv1.RevokeCurrentSessionRequest{}); err != nil {
			t.Fatal(err)
		}
	}
	if profileCalls != 1 || sessionCalls != 1 {
		t.Fatalf("profile=%d session=%d", profileCalls, sessionCalls)
	}
}

func TestAuthenticationDispatchRejectsOversizedProof(t *testing.T) {
	h := userEndpointAuthenticationMiddleware(nil, nil, nil, true)(func(context.Context, any) (any, error) {
		t.Fatal("oversized request reached handler")
		return nil, nil
	})
	ctx := kt.NewServerContext(t.Context(), dispatchTransport{authv1.AuthenticationService_CompleteDeviceLogin_FullMethodName})
	_, err := h(ctx, &authv1.CompleteDeviceLoginRequest{Proof: &authv1.CredentialProof{Signature: make([]byte, 16*1024)}})
	if status.Code(err) != codes.ResourceExhausted {
		t.Fatal(err)
	}
}
