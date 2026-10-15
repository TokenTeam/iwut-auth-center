package transport

import (
	"context"
	"errors"
	authpb "github.com/TokenTeam/iwut-api-proto/gen/go/auth_center/v1/authentication"
	pb "github.com/TokenTeam/iwut-api-proto/gen/go/auth_center/v3/email_account"
	kerrors "github.com/go-kratos/kratos/v2/errors"
	kt "github.com/go-kratos/kratos/v2/transport"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/proto"
	campus "iwut-auth-center/internal/campuscertification/domain"
	d "iwut-auth-center/internal/emailaccount/domain"
	"iwut-auth-center/internal/emailaccount/usecase"
	pwd "iwut-auth-center/internal/password/domain"
)

type EmailAccountService struct {
	pb.UnimplementedEmailAccountServiceServer
	service *usecase.Service
}

func NewEmailAccountService(s *usecase.Service) *EmailAccountService {
	return &EmailAccountService{service: s}
}
func emailAccountMethod(method string) bool {
	switch method {
	case pb.EmailAccountService_BeginEmailRegistration_FullMethodName, pb.EmailAccountService_CompleteEmailRegistration_FullMethodName, pb.EmailAccountService_GetOwnEmails_FullMethodName, pb.EmailAccountService_BeginAddOwnEmail_FullMethodName, pb.EmailAccountService_CompleteAddOwnEmail_FullMethodName, pb.EmailAccountService_SwitchOwnLoginEmail_FullMethodName, pb.EmailAccountService_RemoveOwnEmail_FullMethodName:
		return true
	}
	return false
}

// DIRECT methods accept exactly their own carrier. Even an empty supplied
// Session is not an anonymous registration request; alternate identities never
// repair an invalid Session.
func emailAccountCarrier(ctx context.Context, own bool) (string, error) {
	_ = grpc.SetHeader(ctx, metadata.Pairs("cache-control", "no-store"))
	md, _ := metadata.FromIncomingContext(ctx)
	values, present := md["x-iwut-session"]
	forbidden := false
	reject := func(k string) bool {
		return equalHeader(k, "authorization") || equalHeader(k, "cookie") || equalHeader(k, "x-iwut-identity") || equalHeader(k, "x-iwut-service-identity")
	}
	for key := range md {
		if reject(key) {
			forbidden = true
		}
	}
	if tr, ok := kt.FromServerContext(ctx); ok {
		values = tr.RequestHeader().Values("x-iwut-session")
		present = false
		for _, key := range tr.RequestHeader().Keys() {
			if equalHeader(key, "x-iwut-session") {
				present = true
			}
			if reject(key) {
				forbidden = true
			}
		}
	}
	if forbidden || (!own && present) || (own && (!present || len(values) != 1 || !canonicalSessionToken(values[0]))) {
		return "", emailAccountError(d.ErrSession)
	}
	if !own {
		return "", nil
	}
	return values[0], nil
}
func (s *EmailAccountService) input(ctx context.Context, r proto.Message, own bool) (string, error) {
	_ = grpc.SetHeader(ctx, metadata.Pairs("cache-control", "no-store"))
	if s == nil || s.service == nil {
		return "", transportStatus(codes.Unimplemented, "UNIMPLEMENTED", "email account is disabled")
	}
	token, err := emailAccountCarrier(ctx, own)
	if err != nil {
		return "", err
	}
	if r == nil || !r.ProtoReflect().IsValid() {
		return "", emailAccountError(d.ErrInvalid)
	}
	if proto.Size(r) > 16*1024 {
		return "", transportStatus(codes.ResourceExhausted, "EMAIL_REQUEST_TOO_LARGE", "request is too large")
	}
	if hasUnknown(r) {
		return "", emailAccountError(d.ErrInvalid)
	}
	return token, nil
}
func (s *EmailAccountService) BeginEmailRegistration(ctx context.Context, r *pb.BeginEmailRegistrationRequest) (*pb.EmailRegistrationStarted, error) {
	token, err := s.input(ctx, r, false)
	if err != nil {
		return nil, err
	}
	if r.CredentialProposal == nil {
		return nil, emailAccountError(d.ErrInvalid)
	}
	out, err := s.service.Begin(ctx, token, d.Begin{RequestID: r.RequestId, Email: r.Email, DeviceVersion: r.CredentialProposal.ProtocolVersion, PublicKey: r.CredentialProposal.PublicKey, Source: authenticationPeer(ctx)}, true)
	if err != nil {
		return nil, emailAccountError(err)
	}
	o := out.Operation
	return &pb.EmailRegistrationStarted{OperationId: o.OperationID, TargetEmail: o.Email, Challenge: o.Challenge, SigningPayload: out.SigningPayload, ProtocolVersion: d.ProtocolVersion, ExpiresAtUnixMs: o.ExpiresAt.UnixMilli(), ResendAfterUnixMs: o.ResendAfter.UnixMilli()}, nil
}
func (s *EmailAccountService) CompleteEmailRegistration(ctx context.Context, r *pb.CompleteEmailRegistrationRequest) (*pb.EmailRegistrationCompleted, error) {
	token, err := s.input(ctx, r, false)
	if err != nil {
		return nil, err
	}
	if r.Proof == nil {
		return nil, emailAccountError(d.ErrInvalid)
	}
	out, err := s.service.Complete(ctx, token, r.OperationId, r.Code, r.Password, r.Proof.Signature, true, authenticationPeer(ctx))
	if err != nil {
		return nil, emailAccountError(err)
	}
	a := out.Registration
	if a == nil {
		return nil, emailAccountError(d.ErrUnavailable)
	}
	return &pb.EmailRegistrationCompleted{OperationId: out.OperationID, RegistrationResult: &authpb.UserRegistrationResult{AuthId: a.AuthID, CredentialId: a.CredentialID, Session: &authpb.SessionEstablished{AuthId: a.AuthID, CredentialId: a.CredentialID, SessionId: a.SessionID, SessionToken: a.SessionToken, ExpiresAtUnixMs: a.ExpiresAt.UnixMilli()}}}, nil
}
func emailDirectoryResponse(dir d.Directory) *pb.OwnEmails {
	out := &pb.OwnEmails{DirectoryRevision: dir.Revision, LoginRoleRevision: dir.LoginRoleRevision, Emails: []*pb.OwnEmail{}, Pending: []*pb.PendingOwnEmail{}}
	for _, b := range dir.Bindings {
		out.Emails = append(out.Emails, &pb.OwnEmail{BindingId: b.BindingID, Email: b.Email, VerifiedAtUnixMs: b.VerifiedAt.UnixMilli(), IsLogin: b.BindingID == dir.LoginBindingID, IsWhut: campus.IsWHUTEmail(b.Email)})
	}
	for _, p := range dir.Pending {
		out.Pending = append(out.Pending, &pb.PendingOwnEmail{OperationId: p.OperationID, TargetEmail: p.Email, ExpiresAtUnixMs: p.ExpiresAt.UnixMilli(), ResendAfterUnixMs: p.ResendAfter.UnixMilli()})
	}
	return out
}
func (s *EmailAccountService) GetOwnEmails(ctx context.Context, r *pb.GetOwnEmailsRequest) (*pb.OwnEmails, error) {
	token, err := s.input(ctx, r, true)
	if err != nil {
		return nil, err
	}
	out, err := s.service.Own(ctx, token, authenticationPeer(ctx))
	if err != nil {
		return nil, emailAccountError(err)
	}
	return emailDirectoryResponse(out), nil
}
func (s *EmailAccountService) BeginAddOwnEmail(ctx context.Context, r *pb.BeginAddOwnEmailRequest) (*pb.OwnEmailVerificationStarted, error) {
	token, err := s.input(ctx, r, true)
	if err != nil {
		return nil, err
	}
	out, err := s.service.Begin(ctx, token, d.Begin{RequestID: r.RequestId, Email: r.Email, ExpectedDirectoryRevision: r.ExpectedDirectoryRevision, Source: authenticationPeer(ctx)}, false)
	if err != nil {
		return nil, emailAccountError(err)
	}
	o := out.Operation
	return &pb.OwnEmailVerificationStarted{OperationId: o.OperationID, TargetEmail: o.Email, ExpiresAtUnixMs: o.ExpiresAt.UnixMilli(), ResendAfterUnixMs: o.ResendAfter.UnixMilli()}, nil
}
func (s *EmailAccountService) CompleteAddOwnEmail(ctx context.Context, r *pb.CompleteAddOwnEmailRequest) (*pb.OwnEmailAdded, error) {
	token, err := s.input(ctx, r, true)
	if err != nil {
		return nil, err
	}
	out, err := s.service.Complete(ctx, token, r.OperationId, r.Code, "", nil, false, authenticationPeer(ctx))
	if err != nil {
		return nil, emailAccountError(err)
	}
	return &pb.OwnEmailAdded{OperationId: out.OperationID, Emails: emailDirectoryResponse(out.Directory)}, nil
}
func (s *EmailAccountService) SwitchOwnLoginEmail(ctx context.Context, r *pb.SwitchOwnLoginEmailRequest) (*pb.LoginEmailSwitched, error) {
	token, err := s.input(ctx, r, true)
	if err != nil {
		return nil, err
	}
	id, out, err := s.service.Mutate(ctx, token, d.Mutation{RequestID: r.RequestId, BindingID: r.TargetBindingId, Password: r.CurrentPassword, ExpectedDirectoryRevision: r.ExpectedDirectoryRevision, ExpectedLoginRoleRevision: r.ExpectedLoginRoleRevision, Source: authenticationPeer(ctx)}, true)
	if err != nil {
		return nil, emailAccountError(err)
	}
	return &pb.LoginEmailSwitched{OperationId: id, Emails: emailDirectoryResponse(out)}, nil
}
func (s *EmailAccountService) RemoveOwnEmail(ctx context.Context, r *pb.RemoveOwnEmailRequest) (*pb.OwnEmailRemoved, error) {
	token, err := s.input(ctx, r, true)
	if err != nil {
		return nil, err
	}
	id, out, err := s.service.Mutate(ctx, token, d.Mutation{RequestID: r.RequestId, BindingID: r.BindingId, ExpectedDirectoryRevision: r.ExpectedDirectoryRevision, Source: authenticationPeer(ctx)}, false)
	if err != nil {
		return nil, emailAccountError(err)
	}
	return &pb.OwnEmailRemoved{OperationId: id, Emails: emailDirectoryResponse(out)}, nil
}
func emailAccountError(err error) error {
	if err == nil {
		return nil
	}
	reason, code := d.ErrUnavailable.Error(), codes.Unavailable
	for _, known := range append(append([]error{}, d.Errors...), pwd.Errors...) {
		if errors.Is(err, known) {
			reason = known.Error()
			break
		}
	}
	switch reason {
	case d.ErrInvalid.Error(), d.ErrVerification.Error(), pwd.ErrInvalidInput.Error(), pwd.ErrPolicy.Error():
		code = codes.InvalidArgument
	case d.ErrSession.Error(), pwd.ErrSessionInvalid.Error(), pwd.ErrAuthentication.Error():
		code = codes.Unauthenticated
	case d.ErrDirectoryConflict.Error(), d.ErrRoleConflict.Error(), pwd.ErrConflict.Error():
		code = codes.Aborted
	case d.ErrBindingLimit.Error(), d.ErrLoginRemoval.Error():
		code = codes.AlreadyExists
	case d.ErrBindingNotFound.Error():
		code = codes.NotFound
	case d.ErrConflict.Error(), d.ErrOccupied.Error(), d.ErrCompleted.Error(), d.ErrCredential.Error():
		code = codes.AlreadyExists
	case d.ErrLimited.Error(), pwd.ErrLimited.Error():
		if errors.Is(err, pwd.ErrLimited) {
			reason = "PASSWORD_RATE_LIMITED"
		}
		return kerrors.New(429, reason, "email account rate limited").WithMetadata(map[string]string{"retryAfterSeconds": "60"})
	}
	passwordReasons := map[string]string{pwd.ErrInvalidInput.Error(): "INVALID_PASSWORD_REQUEST", pwd.ErrPolicy.Error(): "PASSWORD_POLICY_REJECTED", pwd.ErrAuthentication.Error(): "PASSWORD_AUTHENTICATION_FAILED", pwd.ErrConflict.Error(): "PASSWORD_REVISION_CONFLICT", pwd.ErrSessionInvalid.Error(): "SESSION_INVALID", pwd.ErrUnavailable.Error(): "PASSWORD_UNAVAILABLE", pwd.ErrLimited.Error(): "PASSWORD_RATE_LIMITED"}
	if mapped, ok := passwordReasons[reason]; ok {
		reason = mapped
	}
	return transportStatus(code, reason, "email account request failed")
}
