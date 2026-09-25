package transport

import (
	"context"
	"errors"
	authpb "github.com/TokenTeam/iwut-api-proto/gen/go/auth_center/v1/authentication"
	pb "github.com/TokenTeam/iwut-api-proto/gen/go/auth_center/v1/email_binding"
	kerrors "github.com/go-kratos/kratos/v2/errors"
	kt "github.com/go-kratos/kratos/v2/transport"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	d "iwut-auth-center/internal/emailbinding/domain"
	"iwut-auth-center/internal/emailbinding/usecase"
)

type EmailBindingService struct {
	pb.UnimplementedEmailBindingServiceServer
	service *usecase.Service
}

func NewEmailBindingService(s *usecase.Service) *EmailBindingService {
	return &EmailBindingService{service: s}
}
func (s *EmailBindingService) authorize(ctx context.Context) ([]byte, error) {
	if s == nil || s.service == nil {
		return nil, transportStatus(codes.Unimplemented, "UNIMPLEMENTED", "email binding is disabled")
	}
	md, _ := metadata.FromIncomingContext(ctx)
	values, present := md["x-iwut-session"]
	if tr, ok := kt.FromServerContext(ctx); ok {
		values = tr.RequestHeader().Values("x-iwut-session")
		present = false
		for _, key := range tr.RequestHeader().Keys() {
			if equalHeader(key, "x-iwut-session") {
				present = true
				break
			}
		}
	}
	var token *string
	if present {
		if len(values) != 1 || !canonicalSessionToken(values[0]) {
			return nil, emailError(d.ErrSession)
		}
		token = &values[0]
	}
	digest, e := s.service.Authorize(ctx, token)
	return digest, emailError(e)
}
func equalHeader(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		c := a[i]
		if c >= 'A' && c <= 'Z' {
			c += 32
		}
		if c != b[i] {
			return false
		}
	}
	return true
}
func (s *EmailBindingService) BeginSetEmail(ctx context.Context, r *pb.BeginSetEmailRequest) (*pb.EmailVerificationStarted, error) {
	digest, e := s.authorize(ctx)
	if e != nil {
		return nil, e
	}
	if e = checkEmailMessage(r); e != nil {
		return nil, e
	}
	b := d.Begin{RequestID: r.GetRequestId(), Email: r.GetEmail(), Source: authenticationPeer(ctx)}
	switch x := r.GetIntent().(type) {
	case *pb.BeginSetEmailRequest_Binding:
		if x.Binding == nil || x.Binding.ExpectedRevision == nil {
			return nil, emailError(d.ErrInvalid)
		}
		b.Mode = d.Bind
		b.Revision = x.Binding.ExpectedRevision
	case *pb.BeginSetEmailRequest_Registration:
		if x.Registration == nil || x.Registration.CredentialProposal == nil || x.Registration.Association == nil {
			return nil, emailError(d.ErrInvalid)
		}
		b.Mode = d.Register
		b.ProtocolVersion = x.Registration.CredentialProposal.ProtocolVersion
		b.PublicKey = x.Registration.CredentialProposal.PublicKey
		b.Scheme = x.Registration.Association.SchemeVersion
		b.Token = x.Registration.Association.AssociationToken
	default:
		return nil, emailError(d.ErrInvalid)
	}
	result, e := s.service.Begin(ctx, b, digest)
	if e != nil {
		return nil, emailError(e)
	}
	o := result.Operation
	out := &pb.EmailVerificationStarted{OperationId: o.Proof.OperationID, Mode: emailMode(o.Mode), TargetEmail: o.Email, ExpiresAtUnixMs: o.Proof.ExpiresAt.UnixMilli(), ResendAfterUnixMs: o.ResendAfter.UnixMilli()}
	if o.Mode == d.Register {
		out.RegistrationChallenge = &pb.EmailRegistrationChallenge{Challenge: o.Proof.Challenge, SigningPayload: result.SigningPayload, ProtocolVersion: d.ProtocolVersion}
	}
	return out, nil
}
func (s *EmailBindingService) CompleteSetEmail(ctx context.Context, r *pb.CompleteSetEmailRequest) (*pb.EmailActivated, error) {
	digest, e := s.authorize(ctx)
	if e != nil {
		return nil, e
	}
	if e = checkEmailMessage(r); e != nil {
		return nil, e
	}
	result, e := s.service.Complete(ctx, r.GetOperationId(), r.GetCode(), r.GetRegistrationProof().GetSignature(), r.GetRegistrationProof() != nil, digest)
	if e != nil {
		return nil, emailError(e)
	}
	out := &pb.EmailActivated{OperationId: result.OperationID, Mode: emailMode(result.Mode), Email: result.Email, VerifiedAtUnixMs: result.VerifiedAt.UnixMilli(), Revision: result.Revision}
	if a := result.Registration; a != nil {
		out.RegistrationResult = &authpb.UserRegistrationResult{AuthId: a.AuthID, CredentialId: a.CredentialID, Session: &authpb.SessionEstablished{AuthId: a.AuthID, CredentialId: a.CredentialID, SessionId: a.SessionID, SessionToken: a.SessionToken, ExpiresAtUnixMs: a.ExpiresAt.UnixMilli()}}
	}
	return out, nil
}
func (s *EmailBindingService) GetOwnEmailBinding(ctx context.Context, r *pb.GetOwnEmailBindingRequest) (*pb.OwnEmailBinding, error) {
	digest, e := s.authorize(ctx)
	if e != nil {
		return nil, e
	}
	if e = checkEmailMessage(r); e != nil {
		return nil, e
	}
	b, e := s.service.Own(ctx, digest)
	if e != nil {
		return nil, emailError(e)
	}
	out := &pb.OwnEmailBinding{Revision: b.Revision}
	if b.Email != "" {
		out.ActiveEmail = &pb.ActiveEmail{Email: b.Email, VerifiedAtUnixMs: b.VerifiedAt.UnixMilli()}
	}
	if p := b.Pending; p != nil {
		out.Pending = &pb.PendingEmailBinding{OperationId: p.Proof.OperationID, TargetEmail: p.Email, ExpiresAtUnixMs: p.Proof.ExpiresAt.UnixMilli(), ResendAfterUnixMs: p.ResendAfter.UnixMilli()}
	}
	return out, nil
}
func emailMode(s string) pb.EmailMode {
	if s == d.Register {
		return pb.EmailMode_EMAIL_MODE_REGISTER
	}
	return pb.EmailMode_EMAIL_MODE_BIND
}
func checkEmailMessage(p proto.Message) error {
	if p == nil || !p.ProtoReflect().IsValid() {
		return emailError(d.ErrInvalid)
	}
	if proto.Size(p) > 16*1024 {
		return transportStatus(codes.ResourceExhausted, "EMAIL_REQUEST_TOO_LARGE", "request is too large")
	}
	if hasUnknown(p) {
		return emailError(d.ErrInvalid)
	}
	return nil
}
func hasUnknown(p proto.Message) bool {
	m := p.ProtoReflect()
	if len(m.GetUnknown()) > 0 {
		return true
	}
	bad := false
	m.Range(func(fd protoreflect.FieldDescriptor, v protoreflect.Value) bool {
		if fd.Message() != nil && !fd.IsList() && !fd.IsMap() {
			bad = hasUnknown(v.Message().Interface())
		}
		return !bad
	})
	return bad
}
func emailError(e error) error {
	if e == nil {
		return nil
	}
	code := codes.Unavailable
	reason := d.ErrUnavailable.Error()
	for _, known := range d.Errors {
		if errors.Is(e, known) {
			reason = known.Error()
			break
		}
	}
	switch reason {
	case d.ErrInvalid.Error(), d.ErrVerification.Error():
		code = codes.InvalidArgument
	case d.ErrSession.Error():
		code = codes.Unauthenticated
	case d.ErrFlow.Error():
		code = codes.FailedPrecondition
	case d.ErrRevision.Error():
		code = codes.Aborted
	case d.ErrConflict.Error(), d.ErrActive.Error(), d.ErrOccupied.Error(), d.ErrCompleted.Error(), d.ErrCredential.Error():
		code = codes.AlreadyExists
	case d.ErrRate.Error():
		return kerrors.New(429, reason, "email request rate limited").WithMetadata(map[string]string{"retryAfterSeconds": "3600"})
	}
	return transportStatus(code, reason, "email request failed")
}
func emailMethod(method string) bool {
	switch method {
	case pb.EmailBindingService_BeginSetEmail_FullMethodName, pb.EmailBindingService_CompleteSetEmail_FullMethodName, pb.EmailBindingService_GetOwnEmailBinding_FullMethodName:
		return true
	}
	return false
}
