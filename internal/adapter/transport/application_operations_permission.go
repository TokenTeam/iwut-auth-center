package transport

import (
	"context"
	"errors"

	pb "github.com/TokenTeam/iwut-api-proto/gen/go/auth_center/v1/application_operations_permission"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	domain "iwut-auth-center/internal/applicationoperations/domain"
	"iwut-auth-center/internal/applicationoperations/usecase"
)

func applicationOperationsPermissionMethod(operation string) bool {
	return operation == pb.ApplicationOperationsPermissionService_ManageApplicationOperationsPermission_FullMethodName ||
		operation == pb.ApplicationOperationsPermissionService_GetApplicationOperationsPermissions_FullMethodName
}

type ApplicationOperationsPermissionService struct {
	pb.UnimplementedApplicationOperationsPermissionServiceServer
	service *usecase.Service
}

func NewApplicationOperationsPermissionService(service *usecase.Service) *ApplicationOperationsPermissionService {
	return &ApplicationOperationsPermissionService{service: service}
}

func (s *ApplicationOperationsPermissionService) ManageApplicationOperationsPermission(ctx context.Context, request *pb.ManageApplicationOperationsPermissionRequest) (*pb.ApplicationOperationsPermissions, error) {
	actor, err := profileAuthID(ctx)
	if err != nil {
		return nil, applicationOperationsPermissionError(domain.ErrIdentity)
	}
	if request == nil || request.ExpectedPermissionRevision == nil || len(request.ProtoReflect().GetUnknown()) != 0 {
		return nil, applicationOperationsPermissionError(domain.ErrInvalid)
	}
	action := ""
	switch request.Action {
	case pb.ApplicationOperationsPermissionAction_APPLICATION_OPERATIONS_PERMISSION_ACTION_GRANT:
		action = "GRANT"
	case pb.ApplicationOperationsPermissionAction_APPLICATION_OPERATIONS_PERMISSION_ACTION_REVOKE:
		action = "REVOKE"
	}
	out, err := s.service.Manage(ctx, domain.Command{ActorAuthID: actor, SubjectAuthID: request.SubjectAuthId, Permission: request.Permission, Action: action, ExpectedRevision: request.GetExpectedPermissionRevision(), Reason: request.Reason})
	if err != nil {
		return nil, applicationOperationsPermissionError(err)
	}
	return applicationOperationsPermissionResponse(out), nil
}

func (s *ApplicationOperationsPermissionService) GetApplicationOperationsPermissions(ctx context.Context, request *pb.GetApplicationOperationsPermissionsRequest) (*pb.ApplicationOperationsPermissions, error) {
	actor, err := profileAuthID(ctx)
	if err != nil {
		return nil, applicationOperationsPermissionError(domain.ErrIdentity)
	}
	if request == nil || len(request.ProtoReflect().GetUnknown()) != 0 {
		return nil, applicationOperationsPermissionError(domain.ErrInvalid)
	}
	out, err := s.service.Get(ctx, actor, request.SubjectAuthId)
	if err != nil {
		return nil, applicationOperationsPermissionError(err)
	}
	return applicationOperationsPermissionResponse(out), nil
}

func applicationOperationsPermissionResponse(state domain.State) *pb.ApplicationOperationsPermissions {
	response := &pb.ApplicationOperationsPermissions{
		SubjectAuthId:      state.AuthID,
		AccountStatus:      pb.ApplicationOperationsAccountStatus(pb.ApplicationOperationsAccountStatus_value["APPLICATION_OPERATIONS_ACCOUNT_STATUS_"+state.AccountStatus]),
		Permissions:        []*pb.ApplicationOperationsPermission{},
		PermissionRevision: state.Revision,
		GrantBlockers:      []pb.ApplicationOperationsGrantBlocker{},
	}
	for _, permission := range state.Permissions {
		response.Permissions = append(response.Permissions, &pb.ApplicationOperationsPermission{Permission: permission.Name, Granted: permission.Granted, Effective: permission.Effective})
	}
	for _, blocker := range state.GrantBlockers {
		response.GrantBlockers = append(response.GrantBlockers, pb.ApplicationOperationsGrantBlocker(pb.ApplicationOperationsGrantBlocker_value["APPLICATION_OPERATIONS_GRANT_BLOCKER_"+blocker]))
	}
	return response
}

func applicationOperationsPermissionError(err error) error {
	code, reason := codes.Unavailable, domain.ErrUnavailable.Error()
	for _, mapping := range []struct {
		err  error
		code codes.Code
	}{
		{domain.ErrIdentity, codes.Unauthenticated},
		{domain.ErrInvalid, codes.InvalidArgument},
		{domain.ErrForbidden, codes.PermissionDenied},
		{domain.ErrSubject, codes.NotFound},
		{domain.ErrConflict, codes.Aborted},
		{domain.ErrGrantBlocked, codes.FailedPrecondition},
		{domain.ErrExhausted, codes.FailedPrecondition},
		{domain.ErrRate, codes.ResourceExhausted},
	} {
		if errors.Is(err, mapping.err) {
			code, reason = mapping.code, mapping.err.Error()
			break
		}
	}
	if errors.Is(err, context.Canceled) {
		code = codes.Canceled
	}
	if errors.Is(err, context.DeadlineExceeded) {
		code = codes.DeadlineExceeded
	}
	fallback := transportStatus(code, reason, "application operations permission request failed")
	var blocked *domain.Blocked
	if errors.As(err, &blocked) {
		withDetails, detailErr := status.New(code, "application operations permission request failed").WithDetails(&errdetails.ErrorInfo{Reason: reason, Metadata: map[string]string{"blocker": blocked.Blocker}})
		if detailErr == nil {
			return withDetails.Err()
		}
	}
	return fallback
}
