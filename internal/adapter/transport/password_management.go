package transport

import (
	"context"
	"errors"
	authpb "github.com/TokenTeam/iwut-api-proto/gen/go/auth_center/v1/authentication"
	pb "github.com/TokenTeam/iwut-api-proto/gen/go/auth_center/v1/password_management"
	kerrors "github.com/go-kratos/kratos/v2/errors"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/proto"
	d "iwut-auth-center/internal/password/domain"
	uc "iwut-auth-center/internal/password/usecase"
)

type PasswordManagementService struct {
	pb.UnimplementedPasswordManagementServiceServer
	change *uc.ChangeService
	reset  *uc.ResetService
}

func NewPasswordManagementService(change *uc.ChangeService, reset *uc.ResetService) *PasswordManagementService {
	return &PasswordManagementService{change: change, reset: reset}
}
func passwordManagementMethod(method string) bool {
	switch method {
	case pb.PasswordManagementService_ChangeOwnPassword_FullMethodName, pb.PasswordManagementService_GetOwnPasswordChange_FullMethodName, pb.PasswordManagementService_BeginPasswordReset_FullMethodName, pb.PasswordManagementService_CompletePasswordReset_FullMethodName:
		return true
	}
	return false
}
func passwordManagementHTTPPath(path string) bool {
	switch path {
	case "/v1/users/me/password:change", "/v1/users/me/password-changes:get", "/v1/password-resets", "/v1/password-resets:complete":
		return true
	}
	return false
}
func passwordInput(ctx context.Context, r proto.Message, own bool) (string, error) {
	_ = grpc.SetHeader(ctx, metadata.Pairs("cache-control", "no-store"))
	if r == nil || !r.ProtoReflect().IsValid() {
		return "", passwordError(d.ErrInvalidInput)
	}
	if proto.Size(r) > 16384 {
		return "", transportStatus(codes.ResourceExhausted, "PASSWORD_REQUEST_TOO_LARGE", "password request is too large")
	}
	if hasUnknown(r) {
		return "", passwordError(d.ErrInvalidInput)
	}
	token, err := emailAccountCarrier(ctx, own)
	if err != nil {
		if own {
			return "", passwordError(d.ErrSessionInvalid)
		}
		return "", passwordError(d.ErrInvalidInput)
	}
	return token, nil
}
func (s *PasswordManagementService) ChangeOwnPassword(ctx context.Context, r *pb.ChangeOwnPasswordRequest) (*pb.PasswordChanged, error) {
	token, err := passwordInput(ctx, r, true)
	if err != nil {
		return nil, err
	}
	if r.RequestId == "" || r.CurrentPassword == "" || r.NewPassword == "" {
		return nil, passwordError(d.ErrInvalidInput)
	}
	op, session, err := s.change.Change(ctx, token, r.RequestId, r.CurrentPassword, r.NewPassword, authenticationPeer(ctx))
	if err != nil {
		return nil, passwordError(err)
	}
	return &pb.PasswordChanged{OperationId: op, Session: &authpb.SessionEstablished{AuthId: session.AuthID, CredentialId: session.CredentialID, SessionId: session.SessionID, SessionToken: session.SessionToken, ExpiresAtUnixMs: session.ExpiresAt.UnixMilli()}}, nil
}
func (s *PasswordManagementService) GetOwnPasswordChange(ctx context.Context, r *pb.GetOwnPasswordChangeRequest) (*pb.OwnPasswordChange, error) {
	token, err := passwordInput(ctx, r, true)
	if err != nil {
		return nil, err
	}
	o, found, observed, err := s.change.Get(ctx, token, r.RequestId, authenticationPeer(ctx))
	if err != nil {
		return nil, passwordError(err)
	}
	result := &pb.OwnPasswordChange{Status: pb.PasswordChangeStatus_NOT_FOUND, ObservedAtUnixMs: observed.UnixMilli()}
	if found {
		result.Status = pb.PasswordChangeStatus_COMPLETED
		result.OperationId = &o.OperationID
	}
	return result, nil
}
func (s *PasswordManagementService) BeginPasswordReset(ctx context.Context, r *pb.BeginPasswordResetRequest) (*pb.PasswordResetStarted, error) {
	if _, err := passwordInput(ctx, r, false); err != nil {
		return nil, err
	}
	o, err := s.reset.Begin(ctx, r.RequestId, r.LoginEmail, authenticationPeer(ctx))
	if err != nil {
		return nil, passwordError(err)
	}
	return &pb.PasswordResetStarted{OperationId: o.OperationID, ExpiresAtUnixMs: o.ExpiresAt.UnixMilli(), ResendAfterUnixMs: o.ResendAfter.UnixMilli()}, nil
}
func (s *PasswordManagementService) CompletePasswordReset(ctx context.Context, r *pb.CompletePasswordResetRequest) (*pb.PasswordResetCompleted, error) {
	if _, err := passwordInput(ctx, r, false); err != nil {
		return nil, err
	}
	if err := s.reset.Complete(ctx, r.OperationId, r.Code, r.NewPassword, authenticationPeer(ctx)); err != nil {
		return nil, passwordError(err)
	}
	return &pb.PasswordResetCompleted{OperationId: r.OperationId}, nil
}
func passwordError(err error) error {
	code, reason := codes.Unavailable, "PASSWORD_UNAVAILABLE"
	for _, item := range []struct {
		err    error
		code   codes.Code
		reason string
	}{
		{d.ErrInvalidInput, codes.InvalidArgument, "INVALID_PASSWORD_REQUEST"}, {d.ErrPolicy, codes.InvalidArgument, "PASSWORD_POLICY_REJECTED"}, {d.ErrUnchanged, codes.InvalidArgument, "PASSWORD_UNCHANGED"},
		{d.ErrSessionInvalid, codes.Unauthenticated, "SESSION_INVALID"}, {d.ErrAuthentication, codes.Unauthenticated, "PASSWORD_AUTHENTICATION_FAILED"}, {d.ErrReset, codes.Unauthenticated, "PASSWORD_RESET_FAILED"},
		{d.ErrConflict, codes.Aborted, "PASSWORD_REVISION_CONFLICT"}, {d.ErrRequestConflict, codes.AlreadyExists, "PASSWORD_REQUEST_CONFLICT"}, {d.ErrAlreadyCompleted, codes.AlreadyExists, "PASSWORD_CHANGE_ALREADY_COMPLETED"},
		{d.ErrLoginCompleted, codes.AlreadyExists, "PASSWORD_LOGIN_ALREADY_COMPLETED"},
		{d.ErrLimited, codes.ResourceExhausted, "PASSWORD_RATE_LIMITED"}, {d.ErrDelivery, codes.Unavailable, "EMAIL_DELIVERY_UNAVAILABLE"},
	} {
		if errors.Is(err, item.err) {
			code, reason = item.code, item.reason
			break
		}
	}
	if code == codes.ResourceExhausted {
		return kerrors.New(429, reason, "password rate limited").WithMetadata(map[string]string{"retryAfterSeconds": "60"})
	}
	return transportStatus(code, reason, reason)
}
