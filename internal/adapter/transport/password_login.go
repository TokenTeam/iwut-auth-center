package transport

import (
	"context"
	authpb "github.com/TokenTeam/iwut-api-proto/gen/go/auth_center/v1/authentication"
	pb "github.com/TokenTeam/iwut-api-proto/gen/go/auth_center/v1/password_login"
	d "iwut-auth-center/internal/password/domain"
	uc "iwut-auth-center/internal/password/usecase"
)

type PasswordLoginService struct {
	pb.UnimplementedPasswordLoginServiceServer
	service *uc.LoginService
}

func NewPasswordLoginService(service *uc.LoginService) *PasswordLoginService {
	return &PasswordLoginService{service: service}
}
func passwordLoginMethod(method string) bool {
	return method == pb.PasswordLoginService_BeginPasswordLogin_FullMethodName || method == pb.PasswordLoginService_CompletePasswordLogin_FullMethodName
}
func passwordLoginHTTPPath(path string) bool {
	return path == "/v1/password-logins" || path == "/v1/password-logins:complete"
}
func (s *PasswordLoginService) BeginPasswordLogin(ctx context.Context, r *pb.BeginPasswordLoginRequest) (*pb.PasswordLoginStarted, error) {
	if _, err := passwordInput(ctx, r, false); err != nil {
		return nil, err
	}
	if r.CredentialProposal == nil {
		return nil, passwordError(d.ErrInvalidInput)
	}
	o, err := s.service.Begin(ctx, r.RequestId, r.LoginEmail, r.CredentialProposal.ProtocolVersion, r.CredentialProposal.PublicKey, authenticationPeer(ctx))
	if err != nil {
		return nil, passwordError(err)
	}
	return &pb.PasswordLoginStarted{OperationId: o.OperationID, Challenge: o.Challenge, SigningPayload: o.SigningPayload, ProtocolVersion: o.ProtocolVersion, ExpiresAtUnixMs: o.ExpiresAt.UnixMilli()}, nil
}
func (s *PasswordLoginService) CompletePasswordLogin(ctx context.Context, r *pb.CompletePasswordLoginRequest) (*pb.PasswordLoginResult, error) {
	if _, err := passwordInput(ctx, r, false); err != nil {
		return nil, err
	}
	if r.Proof == nil {
		return nil, passwordError(d.ErrInvalidInput)
	}
	o, err := s.service.Complete(ctx, r.OperationId, r.Password, r.Proof.Signature, authenticationPeer(ctx))
	if err != nil {
		return nil, passwordError(err)
	}
	return &pb.PasswordLoginResult{AuthId: o.AuthID, CredentialId: o.CredentialID, Session: &authpb.SessionEstablished{AuthId: o.AuthID, CredentialId: o.CredentialID, SessionId: o.SessionID, SessionToken: o.SessionToken, ExpiresAtUnixMs: o.ExpiresAt.UnixMilli()}}, nil
}
