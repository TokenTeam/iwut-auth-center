package transport

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	pb "github.com/TokenTeam/iwut-api-proto/gen/go/auth_center/v1/developer_application"
	kerrors "github.com/go-kratos/kratos/v2/errors"
	kt "github.com/go-kratos/kratos/v2/transport"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/proto"
	d "iwut-auth-center/internal/developer/domain"
	"iwut-auth-center/internal/developer/usecase"
)

type DeveloperApplicationService struct {
	pb.UnimplementedDeveloperApplicationServiceServer
	service  *usecase.Application
	maxBytes int
}

func NewDeveloperApplicationService(s *usecase.Application, maxBytes int) *DeveloperApplicationService {
	return &DeveloperApplicationService{service: s, maxBytes: maxBytes}
}
func developerApplicationMethod(method string) bool {
	return method == pb.DeveloperApplicationService_ApplyForDeveloper_FullMethodName || method == pb.DeveloperApplicationService_GetOwnDeveloperEligibility_FullMethodName
}
func (s *DeveloperApplicationService) authorize(ctx context.Context, request proto.Message) ([]byte, error) {
	if s == nil || s.service == nil {
		return nil, developerApplicationError(d.ErrApplicationUnavailable)
	}
	if err := s.service.AdmitSource(authenticationPeer(ctx)); err != nil {
		return nil, developerApplicationError(err)
	}
	if request == nil || !request.ProtoReflect().IsValid() {
		return nil, developerApplicationError(d.ErrApplicationInvalid)
	}
	if proto.Size(request) > s.maxBytes {
		return nil, transportStatus(codes.ResourceExhausted, "DEVELOPER_APPLICATION_REQUEST_TOO_LARGE", "request is too large")
	}
	if hasUnknown(request) {
		return nil, developerApplicationError(d.ErrApplicationInvalid)
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
		return nil, developerApplicationError(d.ErrApplicationSession)
	}
	raw, _ := base64.RawURLEncoding.Strict().DecodeString(values[0])
	digest := sha256.Sum256(raw)
	return digest[:], nil
}
func (s *DeveloperApplicationService) ApplyForDeveloper(ctx context.Context, r *pb.ApplyForDeveloperRequest) (*pb.DeveloperApplicationResult, error) {
	digest, err := s.authorize(ctx, r)
	if err != nil {
		return nil, err
	}
	state, _, err := s.service.Execute(ctx, digest, true)
	if err != nil {
		return nil, developerApplicationError(err)
	}
	status, ok := developerStatusToProto(state.Status)
	if !ok || state.Status != d.DeveloperStatusApproved {
		return nil, developerApplicationError(d.ErrApplicationUnavailable)
	}
	out := &pb.DeveloperApplicationResult{DeveloperStatus: status}
	if state.ActivatedAt != nil {
		v := state.ActivatedAt.UnixMilli()
		out.ActivatedAtUnixMs = &v
	}
	return out, nil
}
func (s *DeveloperApplicationService) GetOwnDeveloperEligibility(ctx context.Context, r *pb.GetOwnDeveloperEligibilityRequest) (*pb.OwnDeveloperEligibility, error) {
	digest, err := s.authorize(ctx, r)
	if err != nil {
		return nil, err
	}
	state, blockers, err := s.service.Execute(ctx, digest, false)
	if err != nil {
		return nil, developerApplicationError(err)
	}
	out := &pb.OwnDeveloperEligibility{CanApply: len(blockers) == 0}
	if state.Status != "" {
		status, ok := developerStatusToProto(state.Status)
		if !ok {
			return nil, developerApplicationError(d.ErrApplicationUnavailable)
		}
		out.DeveloperStatus = &status
	}
	if state.ActivatedAt != nil {
		v := state.ActivatedAt.UnixMilli()
		out.ActivatedAtUnixMs = &v
	}
	for _, b := range blockers {
		v, ok := pb.DeveloperApplicationBlocker_value["DEVELOPER_APPLICATION_BLOCKER_"+string(b)]
		if !ok || v == 0 {
			return nil, developerApplicationError(d.ErrApplicationUnavailable)
		}
		out.Blockers = append(out.Blockers, pb.DeveloperApplicationBlocker(v))
	}
	return out, nil
}
func developerApplicationError(err error) error {
	switch {
	case errors.Is(err, d.ErrApplicationInvalid):
		return transportStatus(codes.InvalidArgument, d.ErrApplicationInvalid.Error(), "invalid request")
	case errors.Is(err, d.ErrApplicationSession):
		return transportStatus(codes.Unauthenticated, d.ErrApplicationSession.Error(), "session is invalid")
	case errors.Is(err, d.ErrEmailRequired):
		return transportStatus(codes.FailedPrecondition, d.ErrEmailRequired.Error(), "activated email is required")
	case errors.Is(err, d.ErrEmailLoginUnavailable):
		return transportStatus(codes.Unavailable, d.ErrEmailLoginUnavailable.Error(), "email recovery is unavailable")
	case errors.Is(err, d.ErrApplicationExists):
		return transportStatus(codes.AlreadyExists, d.ErrApplicationExists.Error(), "developer application already exists")
	case errors.Is(err, d.ErrReapplication):
		return transportStatus(codes.PermissionDenied, d.ErrReapplication.Error(), "reapplication is not allowed")
	case errors.Is(err, d.ErrApplicationRate):
		return kerrors.New(429, d.ErrApplicationRate.Error(), "request rate limited").WithMetadata(map[string]string{"retryAfterSeconds": "60"})
	default:
		return transportStatus(codes.Unavailable, d.ErrApplicationUnavailable.Error(), "developer application unavailable")
	}
}
