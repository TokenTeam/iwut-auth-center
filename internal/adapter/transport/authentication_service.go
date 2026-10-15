package transport

import (
	"context"
	"errors"

	authv1 "github.com/TokenTeam/iwut-api-proto/gen/go/auth_center/v1/authentication"
)

// These interfaces keep the RPC facade independent from the implementation
// work packages. Authorization is selected by exact method in the server.
type RegistrationRPC interface {
	BeginUserRegistration(context.Context, *authv1.BeginUserRegistrationRequest) (*authv1.AuthenticationChallenge, error)
	CompleteUserRegistration(context.Context, *authv1.CompleteUserRegistrationRequest) (*authv1.UserRegistrationResult, error)
}

type DeviceLoginRPC interface {
	BeginDeviceLogin(context.Context, *authv1.BeginDeviceLoginRequest) (*authv1.AuthenticationChallenge, error)
	CompleteDeviceLogin(context.Context, *authv1.CompleteDeviceLoginRequest) (*authv1.SessionEstablished, error)
}

type SessionRevocationRPC interface {
	RevokeCurrentSession(context.Context, *authv1.RevokeCurrentSessionRequest) (*authv1.SessionRevoked, error)
}

type CredentialRevocationRPC interface {
	RevokeOwnCredential(context.Context, *authv1.RevokeOwnCredentialRequest) (*authv1.CredentialRevoked, error)
}

type AuthenticationService struct {
	authv1.UnimplementedAuthenticationServiceServer
	login       DeviceLoginRPC
	sessions    SessionRevocationRPC
	credentials CredentialRevocationRPC
}

func NewAuthenticationService(_ RegistrationRPC, login DeviceLoginRPC, sessions SessionRevocationRPC, credentials CredentialRevocationRPC) (*AuthenticationService, error) {
	if login == nil || sessions == nil || credentials == nil {
		return nil, errors.New("all authentication handlers are required")
	}
	return &AuthenticationService{login: login, sessions: sessions, credentials: credentials}, nil
}

func (s *AuthenticationService) BeginUserRegistration(ctx context.Context, request *authv1.BeginUserRegistrationRequest) (*authv1.AuthenticationChallenge, error) {
	return s.UnimplementedAuthenticationServiceServer.BeginUserRegistration(ctx, request)
}

func (s *AuthenticationService) CompleteUserRegistration(ctx context.Context, request *authv1.CompleteUserRegistrationRequest) (*authv1.UserRegistrationResult, error) {
	return s.UnimplementedAuthenticationServiceServer.CompleteUserRegistration(ctx, request)
}

func (s *AuthenticationService) BeginDeviceLogin(ctx context.Context, request *authv1.BeginDeviceLoginRequest) (*authv1.AuthenticationChallenge, error) {
	return s.login.BeginDeviceLogin(ctx, request)
}

func (s *AuthenticationService) CompleteDeviceLogin(ctx context.Context, request *authv1.CompleteDeviceLoginRequest) (*authv1.SessionEstablished, error) {
	return s.login.CompleteDeviceLogin(ctx, request)
}

func (s *AuthenticationService) RevokeCurrentSession(ctx context.Context, request *authv1.RevokeCurrentSessionRequest) (*authv1.SessionRevoked, error) {
	return s.sessions.RevokeCurrentSession(ctx, request)
}

func (s *AuthenticationService) RevokeOwnCredential(ctx context.Context, request *authv1.RevokeOwnCredentialRequest) (*authv1.CredentialRevoked, error) {
	return s.credentials.RevokeOwnCredential(ctx, request)
}
