package transport

import (
	"context"
	"errors"
	"net"

	khttp "github.com/go-kratos/kratos/v2/transport/http"

	authv1 "iwut-auth-center/api/gen/go/auth_center/v1/authentication"
	"iwut-auth-center/internal/authentication/domain"
	"iwut-auth-center/internal/authentication/port"
	"iwut-auth-center/internal/authentication/usecase"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/peer"
)

type LoginHandler struct{ login *usecase.Login }

func NewLoginHandler(login *usecase.Login) *LoginHandler { return &LoginHandler{login: login} }

func (h *LoginHandler) BeginDeviceLogin(ctx context.Context, request *authv1.BeginDeviceLoginRequest) (*authv1.AuthenticationChallenge, error) {
	if h == nil || h.login == nil {
		return nil, authenticationError(port.ErrUnavailable)
	}
	var locator domain.Locator
	switch v := request.GetCredentialLocator().(type) {
	case *authv1.BeginDeviceLoginRequest_CredentialId:
		locator = domain.Locator{Kind: domain.CredentialIDLocator, Value: []byte(v.CredentialId)}
	case *authv1.BeginDeviceLoginRequest_PublicKeyFingerprint:
		locator = domain.Locator{Kind: domain.FingerprintLocator, Value: v.PublicKeyFingerprint}
	default:
		return nil, authenticationError(port.ErrInvalidInput)
	}
	result, err := h.login.Begin(ctx, locator, authenticationPeer(ctx))
	if err != nil {
		return nil, authenticationError(err)
	}
	return &authv1.AuthenticationChallenge{OperationId: result.OperationID, Challenge: result.Challenge, ProtocolVersion: result.ProtocolVersion, ExpiresAtUnixMs: result.ExpiresAt.UnixMilli(), SigningPayload: result.SigningPayload}, nil
}

func (h *LoginHandler) CompleteDeviceLogin(ctx context.Context, request *authv1.CompleteDeviceLoginRequest) (*authv1.SessionEstablished, error) {
	if h == nil || h.login == nil {
		return nil, authenticationError(port.ErrUnavailable)
	}
	result, err := h.login.Complete(ctx, request.GetOperationId(), request.GetProof().GetSignature())
	if err != nil {
		return nil, authenticationError(err)
	}
	return &authv1.SessionEstablished{AuthId: result.AuthID, CredentialId: result.CredentialID, SessionId: result.SessionID, SessionToken: result.SessionToken, ExpiresAtUnixMs: result.ExpiresAt.UnixMilli()}, nil
}

func authenticationPeer(ctx context.Context) string {
	if p, ok := peer.FromContext(ctx); ok && p.Addr != nil {
		if host, _, err := net.SplitHostPort(p.Addr.String()); err == nil {
			return host
		}
		return p.Addr.String()
	}
	if request, ok := khttp.RequestFromServerContext(ctx); ok {
		if host, _, err := net.SplitHostPort(request.RemoteAddr); err == nil {
			return host
		}
		return request.RemoteAddr
	}
	return "unknown-network-peer"
}

func authenticationError(err error) error {
	switch {
	case errors.Is(err, port.ErrInvalidInput):
		return transportStatus(codes.InvalidArgument, "INVALID_LOGIN_INPUT", "login input is invalid")
	case errors.Is(err, port.ErrAuthenticationFailed), errors.Is(err, port.ErrNotFound):
		return transportStatus(codes.Unauthenticated, "AUTHENTICATION_FAILED", "authentication failed")
	case errors.Is(err, port.ErrAlreadyCompleted):
		return transportStatus(codes.AlreadyExists, "LOGIN_ALREADY_COMPLETED", "login already completed")
	case errors.Is(err, port.ErrSessionInvalid):
		return transportStatus(codes.Unauthenticated, "SESSION_INVALID", "session is invalid")
	case errors.Is(err, port.ErrLimitExceeded):
		return transportStatus(codes.ResourceExhausted, "AUTHENTICATION_LIMIT_EXCEEDED", "authentication limit exceeded")
	default:
		return transportStatus(codes.Unavailable, "AUTHENTICATION_UNAVAILABLE", "authentication is unavailable")
	}
}
