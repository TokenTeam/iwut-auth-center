package transport

import (
	"context"
	"errors"
	pb "github.com/TokenTeam/iwut-api-proto/gen/go/auth_center/v1/campus_certification"
	kerrors "github.com/go-kratos/kratos/v2/errors"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
	d "iwut-auth-center/internal/campuscertification/domain"
	accountdomain "iwut-auth-center/internal/emailaccount/domain"
	accountusecase "iwut-auth-center/internal/emailaccount/usecase"
	"unicode/utf8"
)

type CampusCertificationService struct {
	pb.UnimplementedCampusCertificationServiceServer
	account *accountusecase.Service
}

func NewCampusCertificationService(service *accountusecase.Service) *CampusCertificationService {
	return &CampusCertificationService{account: service}
}
func campusCertificationMethod(method string) bool {
	return method == pb.CampusCertificationService_BeginOwnCampusCertification_FullMethodName || method == pb.CampusCertificationService_CompleteOwnCampusCertification_FullMethodName || method == pb.CampusCertificationService_GetOwnCampusCertification_FullMethodName
}
func NewCampusEmailAlias(service *accountusecase.Service) *CampusCertificationService {
	return &CampusCertificationService{account: service}
}
func (s *CampusCertificationService) accountInput(ctx context.Context, r proto.Message) (string, error) {
	if s == nil || s.account == nil {
		return "", transportStatus(codes.Unimplemented, "UNIMPLEMENTED", "campus certification is disabled")
	}
	token, err := emailAccountCarrier(ctx, true)
	if err != nil {
		return "", err
	}
	if r == nil || !r.ProtoReflect().IsValid() || hasUnknown(r) {
		return "", campusCertificationError(d.ErrInvalid)
	}
	if proto.Size(r) > 16*1024 {
		return "", transportStatus(codes.ResourceExhausted, "CAMPUS_CERTIFICATION_REQUEST_TOO_LARGE", "request is too large")
	}
	return token, nil
}
func (s *CampusCertificationService) BeginOwnCampusCertification(ctx context.Context, r *pb.BeginOwnCampusCertificationRequest) (*pb.CampusVerificationStarted, error) {
	token, err := s.accountInput(ctx, r)
	if err != nil {
		return nil, err
	}
	out, err := s.account.BeginCampus(ctx, token, r.RequestId, r.Email, authenticationPeer(ctx))
	if err != nil {
		return nil, emailAccountError(err)
	}
	o := out.Operation
	return &pb.CampusVerificationStarted{OperationId: o.OperationID, TargetEmail: o.Email, ExpiresAtUnixMs: o.ExpiresAt.UnixMilli(), ResendAfterUnixMs: o.ResendAfter.UnixMilli()}, nil
}
func (s *CampusCertificationService) CompleteOwnCampusCertification(ctx context.Context, r *pb.CompleteOwnCampusCertificationRequest) (*pb.OwnCampusCertification, error) {
	token, err := s.accountInput(ctx, r)
	if err != nil {
		return nil, err
	}
	dir, err := s.account.CompleteCampus(ctx, token, r.OperationId, r.Code, authenticationPeer(ctx))
	if err != nil {
		return nil, emailAccountError(err)
	}
	return campusDirectoryResponse(dir), nil
}
func (s *CampusCertificationService) GetOwnCampusCertification(ctx context.Context, r *pb.GetOwnCampusCertificationRequest) (*pb.OwnCampusCertification, error) {
	token, err := s.accountInput(ctx, r)
	if err != nil {
		return nil, err
	}
	dir, err := s.account.Own(ctx, token, authenticationPeer(ctx))
	if err != nil {
		return nil, emailAccountError(err)
	}
	return campusDirectoryResponse(dir), nil
}
func campusDirectoryResponse(dir accountdomain.Directory) *pb.OwnCampusCertification {
	fact := d.Certification{Institution: d.Institution}
	for _, b := range dir.Bindings {
		if d.IsWHUTEmail(b.Email) && (fact.CertifiedAt.IsZero() || b.VerifiedAt.Before(fact.CertifiedAt)) {
			fact.CertifiedAt = b.VerifiedAt
		}
	}
	return campusCertificationResponse(fact)
}
func campusCertificationResponse(fact d.Certification) *pb.OwnCampusCertification {
	result := &pb.OwnCampusCertification{Institution: d.Institution}
	if fact.Valid() {
		at := fact.CertifiedAt.UnixMilli()
		result.Certified = true
		result.CertifiedAtUnixMs = &at
	}
	return result
}
func campusCertificationError(err error) error {
	if err == nil {
		return nil
	}
	code, reason := codes.Unavailable, d.ErrUnavailable.Error()
	for _, entry := range []struct {
		err  error
		code codes.Code
	}{{d.ErrInvalid, codes.InvalidArgument}, {d.ErrSession, codes.Unauthenticated}, {d.ErrVerification, codes.InvalidArgument}, {d.ErrConflict, codes.AlreadyExists}, {d.ErrCertified, codes.AlreadyExists}, {d.ErrDelivery, codes.Unavailable}} {
		if errors.Is(err, entry.err) {
			code, reason = entry.code, entry.err.Error()
			break
		}
	}
	if errors.Is(err, d.ErrRate) {
		return kerrors.New(429, d.ErrRate.Error(), "campus request rate limited").WithMetadata(map[string]string{"retryAfterSeconds": "3600"})
	}
	return transportStatus(code, reason, "campus certification request failed")
}

// Validate before protobuf unmarshal discards duplicate or unknown fields.
func campusCertificationWire(data []byte, v any) error {
	maxField := protowire.Number(2)
	switch v.(type) {
	case *pb.BeginOwnCampusCertificationRequest, *pb.CompleteOwnCampusCertificationRequest:
	case *pb.GetOwnCampusCertificationRequest:
		maxField = 0
	default:
		return nil
	}
	if len(data) > 16*1024 {
		return d.ErrInvalid
	}
	seen := map[protowire.Number]bool{}
	for len(data) > 0 {
		n, kind, k := protowire.ConsumeTag(data)
		if k < 0 || n < 1 || n > maxField || seen[n] || kind != protowire.BytesType {
			return d.ErrInvalid
		}
		seen[n] = true
		body, k2 := protowire.ConsumeBytes(data[k:])
		if k2 < 0 || !utf8.Valid(body) {
			return d.ErrInvalid
		}
		data = data[k+k2:]
	}
	return nil
}
