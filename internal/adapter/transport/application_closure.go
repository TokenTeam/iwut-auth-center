package transport

import (
	"context"
	"errors"
	"time"

	pb "github.com/TokenTeam/iwut-api-proto/gen/go/auth_center/v1/application_closure"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
	d "iwut-auth-center/internal/applicationclosure/domain"
)

const (
	PermissionApplicationClosureApply = "auth.application-closure.apply"
	PermissionApplicationClosureRead  = "auth.application-closure.read"
)

type ApplicationClosureHandler interface {
	Apply(context.Context, string, string, time.Time, string) (d.Tombstone, error)
	Get(context.Context, string, string) (d.Tombstone, error)
}

type ApplicationClosureService struct {
	pb.UnimplementedApplicationClosureServiceServer
	handler      ApplicationClosureHandler
	appServiceID string
}

func NewApplicationClosureService(handler ApplicationClosureHandler, appServiceID string) *ApplicationClosureService {
	return &ApplicationClosureService{handler: handler, appServiceID: appServiceID}
}

func (s *ApplicationClosureService) authorize(ctx context.Context, permission string) (ServiceIdentity, error) {
	if s == nil || s.handler == nil || s.appServiceID == "" {
		return ServiceIdentity{}, applicationClosureError(d.ErrUnavailable)
	}
	identity, ok := serviceIdentityFromContext(ctx)
	if !ok {
		return ServiceIdentity{}, serviceIdentityError(errServiceIdentityRequired, "")
	}
	if identity.ServiceID != s.appServiceID || !identity.HasPermission(permission) {
		return ServiceIdentity{}, transportStatus(codes.PermissionDenied, "ERROR_REASON_APPLICATION_CLOSURE_PERMISSION_DENIED", "Application closure permission denied")
	}
	return identity, nil
}

func (s *ApplicationClosureService) ApplyApplicationClosure(ctx context.Context, r *pb.ApplyApplicationClosureRequest) (*pb.ApplicationClosureStatus, error) {
	identity, err := s.authorize(ctx, PermissionApplicationClosureApply)
	if err != nil {
		return nil, err
	}
	if r == nil || hasUnknown(r) || proto.Size(r) > 16*1024 || r.ClosingStartedAt == nil || r.ClosingStartedAt.CheckValid() != nil {
		return nil, applicationClosureError(d.ErrInvalid)
	}
	v, err := s.handler.Apply(ctx, r.ApplicationId, r.ClosureId, r.ClosingStartedAt.AsTime(), identity.ServiceID)
	return applicationClosureStatus(v, err)
}

func (s *ApplicationClosureService) GetApplicationClosureStatus(ctx context.Context, r *pb.GetApplicationClosureStatusRequest) (*pb.ApplicationClosureStatus, error) {
	if _, err := s.authorize(ctx, PermissionApplicationClosureRead); err != nil {
		return nil, err
	}
	if r == nil || hasUnknown(r) || proto.Size(r) > 16*1024 {
		return nil, applicationClosureError(d.ErrInvalid)
	}
	v, err := s.handler.Get(ctx, r.ApplicationId, r.ClosureId)
	return applicationClosureStatus(v, err)
}

func applicationClosureStatus(v d.Tombstone, err error) (*pb.ApplicationClosureStatus, error) {
	if err != nil {
		return nil, applicationClosureError(err)
	}
	at := timestamppb.New(v.AppliedAt)
	if at.CheckValid() != nil {
		return nil, applicationClosureError(d.ErrInconsistent)
	}
	return &pb.ApplicationClosureStatus{ApplicationId: v.ApplicationID, ClosureId: v.ClosureID, State: pb.ApplicationClosureState_APPLICATION_CLOSURE_STATE_APPLIED, ReceiptId: v.ReceiptID, AppliedAt: at}, nil
}

func applicationClosureError(err error) error {
	switch {
	case errors.Is(err, d.ErrInvalid):
		return transportStatus(codes.InvalidArgument, "ERROR_REASON_INVALID_APPLICATION_CLOSURE_REQUEST", "invalid Application closure request")
	case errors.Is(err, d.ErrNotFound):
		return transportStatus(codes.NotFound, "ERROR_REASON_APPLICATION_CLOSURE_NOT_FOUND", "Application closure not found")
	case errors.Is(err, d.ErrConflict):
		return transportStatus(codes.AlreadyExists, "ERROR_REASON_APPLICATION_CLOSURE_CONFLICT", "Application closure conflicts with an existing binding")
	case errors.Is(err, d.ErrInconsistent):
		return transportStatus(codes.Internal, "ERROR_REASON_APPLICATION_CLOSURE_STATE_INCONSISTENT", "Application closure state is inconsistent")
	default:
		return transportStatus(codes.Unavailable, "ERROR_REASON_APPLICATION_CLOSURE_UNAVAILABLE", "Application closure unavailable")
	}
}
