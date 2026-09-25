package transport

import (
	"context"
	"errors"

	authpb "github.com/TokenTeam/iwut-api-proto/gen/go/auth_center/v1/authentication"
	pb "github.com/TokenTeam/iwut-api-proto/gen/go/auth_center/v1/email_login"
	kerrors "github.com/go-kratos/kratos/v2/errors"
	kt "github.com/go-kratos/kratos/v2/transport"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/proto"
	d "iwut-auth-center/internal/emaillogin/domain"
	"iwut-auth-center/internal/emaillogin/usecase"
)

type EmailLoginService struct {
	pb.UnimplementedEmailLoginServiceServer
	service  *usecase.Login
	maxBytes int
}

func NewEmailLoginService(s *usecase.Login, maxBytes int) *EmailLoginService {
	return &EmailLoginService{service: s, maxBytes: maxBytes}
}
func (s *EmailLoginService) validate(ctx context.Context, r proto.Message, begin bool) error {
	if s == nil || s.service == nil {
		return transportStatus(codes.Unimplemented, "UNIMPLEMENTED", "email login is disabled")
	}
	invalid := false
	md, _ := metadata.FromIncomingContext(ctx)
	if _, present := md["x-iwut-session"]; present {
		invalid = true
	}
	if tr, ok := kt.FromServerContext(ctx); ok {
		for _, key := range tr.RequestHeader().Keys() {
			if equalHeader(key, "x-iwut-session") {
				invalid = true
			}
		}
	}
	if invalid || r == nil || !r.ProtoReflect().IsValid() || hasUnknown(r) {
		return emailLoginError(s.service.Reject(authenticationPeer(ctx), begin))
	}
	if proto.Size(r) > s.maxBytes {
		if e := s.service.Reject(authenticationPeer(ctx), begin); errors.Is(e, d.ErrRate) {
			return emailLoginError(e)
		}
		return transportStatus(codes.ResourceExhausted, "EMAIL_LOGIN_REQUEST_TOO_LARGE", "request is too large")
	}
	return nil
}
func (s *EmailLoginService) BeginEmailLogin(ctx context.Context, r *pb.BeginEmailLoginRequest) (*pb.EmailLoginChallenge, error) {
	if e := s.validate(ctx, r, true); e != nil {
		return nil, e
	}
	if r.CredentialProposal == nil {
		return nil, emailLoginError(s.service.Reject(authenticationPeer(ctx), true))
	}
	out, e := s.service.Begin(ctx, d.Begin{RequestID: r.RequestId, Email: r.Email, ProtocolVersion: r.CredentialProposal.ProtocolVersion, PublicKey: r.CredentialProposal.PublicKey, Source: authenticationPeer(ctx)})
	if e != nil {
		return nil, emailLoginError(e)
	}
	return &pb.EmailLoginChallenge{OperationId: out.OperationID, Challenge: out.Challenge, SigningPayload: out.SigningPayload, ProtocolVersion: out.ProtocolVersion, ExpiresAtUnixMs: out.ExpiresAt.UnixMilli(), ResendAfterUnixMs: out.ResendAfter.UnixMilli()}, nil
}
func (s *EmailLoginService) CompleteEmailLogin(ctx context.Context, r *pb.CompleteEmailLoginRequest) (*pb.EmailLoginResult, error) {
	if e := s.validate(ctx, r, false); e != nil {
		return nil, e
	}
	if r.Proof == nil {
		return nil, emailLoginError(s.service.Reject(authenticationPeer(ctx), false))
	}
	out, e := s.service.Complete(ctx, r.OperationId, r.Code, r.Proof.Signature, authenticationPeer(ctx))
	if e != nil {
		return nil, emailLoginError(e)
	}
	return &pb.EmailLoginResult{AuthId: out.AuthID, CredentialId: out.CredentialID, Session: &authpb.SessionEstablished{AuthId: out.AuthID, CredentialId: out.CredentialID, SessionId: out.SessionID, SessionToken: out.SessionToken, ExpiresAtUnixMs: out.ExpiresAt.UnixMilli()}}, nil
}
func emailLoginError(e error) error {
	if e == nil {
		return nil
	}
	reason := d.ErrUnavailable.Error()
	code := codes.Unavailable
	for _, known := range d.Errors {
		if errors.Is(e, known) {
			reason = known.Error()
			break
		}
	}
	switch reason {
	case d.ErrInvalid.Error():
		code = codes.InvalidArgument
	case d.ErrFailed.Error():
		code = codes.Unauthenticated
	case d.ErrCredential.Error(), d.ErrConflict.Error(), d.ErrCompleted.Error():
		code = codes.AlreadyExists
	case d.ErrRate.Error():
		return kerrors.New(429, reason, "email login rate limited").WithMetadata(map[string]string{"retryAfterSeconds": "3600"})
	}
	return transportStatus(code, reason, "email login failed")
}
func emailLoginMethod(method string) bool {
	return method == pb.EmailLoginService_BeginEmailLogin_FullMethodName || method == pb.EmailLoginService_CompleteEmailLogin_FullMethodName
}
