package transport

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	pb "github.com/TokenTeam/iwut-api-proto/gen/go/auth_center/v1/developer_withdrawal"
	kerrors "github.com/go-kratos/kratos/v2/errors"
	kt "github.com/go-kratos/kratos/v2/transport"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
	d "iwut-auth-center/internal/developerwithdrawal/domain"
	"iwut-auth-center/internal/developerwithdrawal/usecase"
)

type DeveloperWithdrawalService struct {
	pb.UnimplementedDeveloperWithdrawalServiceServer
	service *usecase.Service
}

func NewDeveloperWithdrawalService(s *usecase.Service) *DeveloperWithdrawalService {
	return &DeveloperWithdrawalService{service: s}
}
func developerWithdrawalMethod(method string) bool {
	switch method {
	case pb.DeveloperWithdrawalService_PrepareDeveloperWithdrawal_FullMethodName, pb.DeveloperWithdrawalService_ConfirmDeveloperWithdrawal_FullMethodName, pb.DeveloperWithdrawalService_CancelDeveloperWithdrawal_FullMethodName, pb.DeveloperWithdrawalService_GetDeveloperWithdrawal_FullMethodName:
		return true
	}
	return false
}
func (s *DeveloperWithdrawalService) authorize(ctx context.Context, r proto.Message) ([]byte, error) {
	if s == nil || s.service == nil {
		return nil, withdrawalError(d.ErrUnavailable)
	}
	if r == nil || !r.ProtoReflect().IsValid() || hasUnknown(r) {
		return nil, withdrawalError(d.ErrInvalid)
	}
	if proto.Size(r) > 16*1024 {
		return nil, transportStatus(codes.ResourceExhausted, "DEVELOPER_WITHDRAWAL_REQUEST_TOO_LARGE", "request is too large")
	}
	md, _ := metadata.FromIncomingContext(ctx)
	values := md.Get("x-iwut-session")
	invalid := len(md.Get("authorization"))+len(md.Get("cookie"))+len(md.Get("x-iwut-identity")) > 0
	if tr, ok := kt.FromServerContext(ctx); ok {
		values = tr.RequestHeader().Values("x-iwut-session")
		for _, key := range tr.RequestHeader().Keys() {
			if equalHeader(key, "authorization") || equalHeader(key, "cookie") || equalHeader(key, "x-iwut-identity") {
				invalid = true
			}
		}
	}
	if invalid || len(values) != 1 || !canonicalSessionToken(values[0]) {
		return nil, withdrawalError(d.ErrSession)
	}
	raw, _ := base64.RawURLEncoding.Strict().DecodeString(values[0])
	digest := sha256.Sum256(raw)
	return digest[:], nil
}
func withdrawalResult(v d.Result, e error) (*pb.DeveloperWithdrawalOperation, error) {
	if e != nil {
		return nil, withdrawalError(e)
	}
	out := &pb.DeveloperWithdrawalOperation{OperationId: v.OperationID, State: v.State, ExpiresAt: timestamppb.New(v.ExpiresAt), DeveloperStatus: v.DeveloperStatus, DeveloperRevision: v.DeveloperRevision, Blocker: v.Blocker}
	if v.CompletedAt != nil {
		out.CompletedAt = timestamppb.New(*v.CompletedAt)
	}
	return out, nil
}
func (s *DeveloperWithdrawalService) PrepareDeveloperWithdrawal(ctx context.Context, r *pb.PrepareDeveloperWithdrawalRequest) (*pb.DeveloperWithdrawalOperation, error) {
	digest, e := s.authorize(ctx, r)
	if e != nil {
		return nil, e
	}
	return withdrawalResult(s.service.Prepare(ctx, digest, r.GetRequestId(), r.GetExpectedDeveloperRevision()))
}
func (s *DeveloperWithdrawalService) ConfirmDeveloperWithdrawal(ctx context.Context, r *pb.ConfirmDeveloperWithdrawalRequest) (*pb.DeveloperWithdrawalOperation, error) {
	digest, e := s.authorize(ctx, r)
	if e != nil {
		return nil, e
	}
	return withdrawalResult(s.service.Confirm(ctx, digest, r.GetOperationId(), r.GetConfirmation()))
}
func (s *DeveloperWithdrawalService) CancelDeveloperWithdrawal(ctx context.Context, r *pb.CancelDeveloperWithdrawalRequest) (*pb.DeveloperWithdrawalOperation, error) {
	digest, e := s.authorize(ctx, r)
	if e != nil {
		return nil, e
	}
	return withdrawalResult(s.service.Cancel(ctx, digest, r.GetOperationId()))
}
func (s *DeveloperWithdrawalService) GetDeveloperWithdrawal(ctx context.Context, r *pb.GetDeveloperWithdrawalRequest) (*pb.DeveloperWithdrawalOperation, error) {
	digest, e := s.authorize(ctx, r)
	if e != nil {
		return nil, e
	}
	return withdrawalResult(s.service.Get(ctx, digest, r.GetOperationId()))
}
func withdrawalError(e error) error {
	switch {
	case errors.Is(e, d.ErrSession):
		return transportStatus(codes.Unauthenticated, d.ErrSession.Error(), "session is invalid")
	case errors.Is(e, d.ErrInvalid):
		return transportStatus(codes.InvalidArgument, d.ErrInvalid.Error(), "invalid request")
	case errors.Is(e, d.ErrNotFound):
		return transportStatus(codes.NotFound, d.ErrNotFound.Error(), "operation not found")
	case errors.Is(e, d.ErrConflict), errors.Is(e, d.ErrWithdrawn):
		return kerrors.Conflict(e.Error(), "withdrawal state conflict")
	case errors.Is(e, d.ErrRate):
		return kerrors.New(429, d.ErrRate.Error(), "request rate limited").WithMetadata(map[string]string{"retryAfterSeconds": "60"})
	default:
		return transportStatus(codes.Unavailable, d.ErrUnavailable.Error(), "withdrawal unavailable")
	}
}
func withdrawalWire(data []byte, v any) error {
	var msg proto.Message
	switch r := v.(type) {
	case *pb.PrepareDeveloperWithdrawalRequest:
		msg = r
	case *pb.ConfirmDeveloperWithdrawalRequest:
		msg = r
	case *pb.CancelDeveloperWithdrawalRequest:
		msg = r
	case *pb.GetDeveloperWithdrawalRequest:
		msg = r
	default:
		return nil
	}
	if len(data) > 16*1024 {
		return transportStatus(codes.ResourceExhausted, "DEVELOPER_WITHDRAWAL_REQUEST_TOO_LARGE", "request is too large")
	}
	if !strictEmailWire(data, msg.ProtoReflect().Descriptor()) {
		return withdrawalError(d.ErrInvalid)
	}
	return nil
}
