package transport

import (
	"context"
	"errors"
	pb "github.com/TokenTeam/iwut-api-proto/gen/go/auth_center/v1/email_binding"
	kerrors "github.com/go-kratos/kratos/v2/errors"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	accountdomain "iwut-auth-center/internal/emailaccount/domain"
	accountusecase "iwut-auth-center/internal/emailaccount/usecase"
	d "iwut-auth-center/internal/emailbinding/domain"
)

type EmailBindingService struct {
	pb.UnimplementedEmailBindingServiceServer
	account *accountusecase.Service
}

func NewEmailBindingService(s *accountusecase.Service) *EmailBindingService {
	return &EmailBindingService{account: s}
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
func NewEmailBindingProjection(s *accountusecase.Service) *EmailBindingService {
	return &EmailBindingService{account: s}
}
func (s *EmailBindingService) BeginSetEmail(context.Context, *pb.BeginSetEmailRequest) (*pb.EmailVerificationStarted, error) {
	return nil, transportStatus(codes.Unimplemented, "EMAIL_FLOW_RETIRED", "use email account v3")
}
func (s *EmailBindingService) CompleteSetEmail(context.Context, *pb.CompleteSetEmailRequest) (*pb.EmailActivated, error) {
	return nil, transportStatus(codes.Unimplemented, "EMAIL_FLOW_RETIRED", "use email account v3")
}
func (s *EmailBindingService) GetOwnEmailBinding(ctx context.Context, r *pb.GetOwnEmailBindingRequest) (*pb.OwnEmailBinding, error) {
	if s == nil || s.account == nil {
		return nil, transportStatus(codes.Unimplemented, "UNIMPLEMENTED", "email directory is disabled")
	}
	token, err := emailAccountCarrier(ctx, true)
	if err != nil {
		return nil, err
	}
	if err = checkEmailMessage(r); err != nil {
		return nil, err
	}
	dir, err := s.account.Own(ctx, token, authenticationPeer(ctx))
	if err != nil {
		return nil, emailAccountError(err)
	}
	b, ok := dir.Primary()
	if !ok {
		return nil, emailAccountError(accountdomain.ErrUnavailable)
	}
	return &pb.OwnEmailBinding{Revision: dir.LoginRoleRevision, ActiveEmail: &pb.ActiveEmail{Email: b.Email, VerifiedAtUnixMs: b.VerifiedAt.UnixMilli()}}, nil
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
