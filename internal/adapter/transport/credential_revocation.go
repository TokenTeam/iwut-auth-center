package transport

import (
	"context"
	"encoding/base64"
	"errors"

	"github.com/go-kratos/kratos/v2/middleware"
	kratostransport "github.com/go-kratos/kratos/v2/transport"
	"google.golang.org/grpc/codes"

	authv1 "github.com/TokenTeam/iwut-api-proto/gen/go/auth_center/v1/authentication"
	"iwut-auth-center/internal/authentication/domain"
	"iwut-auth-center/internal/authentication/port"
	"iwut-auth-center/internal/authentication/usecase"
)

type userSessionContextKey struct{}

// UserSessionMiddleware is deliberately restricted to the sole Session-authenticated
// RPC. Token-directed session revocation must not use it.
func UserSessionMiddleware(checker port.SessionChecker) middleware.Middleware {
	return func(next middleware.Handler) middleware.Handler {
		return func(ctx context.Context, request any) (any, error) {
			tr, ok := kratostransport.FromServerContext(ctx)
			if !ok || tr.Operation() != authv1.AuthenticationService_RevokeOwnCredential_FullMethodName {
				return nil, credentialRevocationError(port.ErrSessionInvalid)
			}
			values := tr.RequestHeader().Values("x-iwut-session")
			if len(values) != 1 || !canonicalSessionToken(values[0]) {
				return nil, credentialRevocationError(port.ErrSessionInvalid)
			}
			if checker == nil {
				return nil, credentialRevocationError(port.ErrUnavailable)
			}
			caller, err := checker.Check(ctx, values[0])
			if err != nil {
				return nil, credentialRevocationError(err)
			}
			return next(context.WithValue(ctx, userSessionContextKey{}, caller), request)
		}
	}
}

func canonicalSessionToken(token string) bool {
	if len(token) != 43 {
		return false
	}
	raw, err := base64.RawURLEncoding.Strict().DecodeString(token)
	return err == nil && len(raw) == 32 && base64.RawURLEncoding.EncodeToString(raw) == token
}

type CredentialRevocationHandler struct{ revoke *usecase.CredentialRevocation }

func NewCredentialRevocationHandler(revoke *usecase.CredentialRevocation) *CredentialRevocationHandler {
	return &CredentialRevocationHandler{revoke: revoke}
}
func (h *CredentialRevocationHandler) RevokeOwnCredential(ctx context.Context, request *authv1.RevokeOwnCredentialRequest) (*authv1.CredentialRevoked, error) {
	caller, ok := ctx.Value(userSessionContextKey{}).(domain.Session)
	if !ok {
		return nil, credentialRevocationError(port.ErrSessionInvalid)
	}
	if h == nil || h.revoke == nil {
		return nil, credentialRevocationError(port.ErrUnavailable)
	}
	if err := h.revoke.Revoke(ctx, caller, request.GetCredentialId()); err != nil {
		return nil, credentialRevocationError(err)
	}
	return &authv1.CredentialRevoked{}, nil
}
func credentialRevocationError(err error) error {
	switch {
	case errors.Is(err, port.ErrSessionInvalid), errors.Is(err, port.ErrAuthenticationFailed):
		return transportStatus(codes.Unauthenticated, "SESSION_INVALID", "session is invalid")
	case errors.Is(err, port.ErrInvalidInput):
		return transportStatus(codes.InvalidArgument, "INVALID_CREDENTIAL_ID", "credential ID is invalid")
	case errors.Is(err, port.ErrNotFound):
		return transportStatus(codes.NotFound, "CREDENTIAL_NOT_FOUND", "credential not found")
	case errors.Is(err, port.ErrCredentialReauthRequired):
		return transportStatus(codes.PermissionDenied, "CREDENTIAL_REAUTH_REQUIRED", "use reviewed device reauthentication")
	default:
		return transportStatus(codes.Unavailable, "CREDENTIAL_REVOCATION_UNAVAILABLE", "credential revocation is unavailable")
	}
}
