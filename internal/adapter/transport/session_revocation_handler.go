package transport

import (
	"context"
	"errors"

	kratostransport "github.com/go-kratos/kratos/v2/transport"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"

	authenticationv1 "iwut-auth-center/api/gen/go/auth_center/v1/authentication"
	"iwut-auth-center/internal/authentication/port"
)

const (
	ReasonInvalidSessionToken          = "ERROR_REASON_INVALID_SESSION_TOKEN"
	ReasonSessionRevocationUnavailable = "ERROR_REASON_SESSION_REVOCATION_UNAVAILABLE"
)

type CurrentSessionRevoker interface {
	Handle(context.Context, string) error
}

type SessionRevocationHandler struct {
	revoker CurrentSessionRevoker
}

func NewSessionRevocationHandler(revoker CurrentSessionRevoker) *SessionRevocationHandler {
	return &SessionRevocationHandler{revoker: revoker}
}

func (handler *SessionRevocationHandler) RevokeCurrentSession(ctx context.Context, _ *authenticationv1.RevokeCurrentSessionRequest) (*authenticationv1.SessionRevoked, error) {
	md, _ := metadata.FromIncomingContext(ctx)
	values := md.Get("x-iwut-session")
	if tr, ok := kratostransport.FromServerContext(ctx); ok {
		values = tr.RequestHeader().Values("x-iwut-session")
	}
	if len(values) != 1 {
		return nil, transportStatus(codes.InvalidArgument, ReasonInvalidSessionToken, "session token is invalid")
	}
	// This endpoint intentionally does not inspect user JWS or validate current
	// session identity: both would break revocation retries after success.
	if err := handler.revoker.Handle(ctx, values[0]); err != nil {
		if errors.Is(err, port.ErrInvalidSessionToken) {
			return nil, transportStatus(codes.InvalidArgument, ReasonInvalidSessionToken, "session token is invalid")
		}
		return nil, transportStatus(codes.Unavailable, ReasonSessionRevocationUnavailable, "session revocation is unavailable")
	}
	return &authenticationv1.SessionRevoked{}, nil
}
