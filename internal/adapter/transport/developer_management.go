package transport

import (
	"context"
	"errors"
	pb "github.com/TokenTeam/iwut-api-proto/gen/go/auth_center/v1/developer_management"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/types/known/timestamppb"
	d "iwut-auth-center/internal/developer/domain"
	"iwut-auth-center/internal/developer/usecase"
)

func isDeveloperManagementOperation(op string) bool {
	return op == pb.DeveloperManagementService_ManageDeveloperStatus_FullMethodName || op == pb.DeveloperManagementService_GetManagedDeveloperStatus_FullMethodName
}

type DeveloperManagementService struct {
	pb.UnimplementedDeveloperManagementServiceServer
	service *usecase.Management
}

func NewDeveloperManagementService(s *usecase.Management) *DeveloperManagementService {
	return &DeveloperManagementService{service: s}
}
func (s *DeveloperManagementService) ManageDeveloperStatus(ctx context.Context, r *pb.ManageDeveloperStatusRequest) (*pb.ManagedDeveloperStatus, error) {
	actor, e := profileAuthID(ctx)
	if e != nil {
		return nil, e
	}
	if r == nil || r.ExpectedDeveloperRevision == nil || len(r.ProtoReflect().GetUnknown()) != 0 {
		return nil, developerManagementError(d.ErrManagementInvalid)
	}
	action := ""
	switch r.Action {
	case pb.Action_SUSPEND:
		action = "SUSPEND"
	case pb.Action_RESTORE:
		action = "RESTORE"
	}
	out, e := s.service.Manage(ctx, d.ManageDeveloperCommand{ActorAuthID: actor, SubjectAuthID: r.SubjectAuthId, Action: action, ExpectedRevision: r.GetExpectedDeveloperRevision(), Reason: r.Reason})
	if e != nil {
		return nil, developerManagementError(e)
	}
	return developerManagementResponse(out), nil
}
func (s *DeveloperManagementService) GetManagedDeveloperStatus(ctx context.Context, r *pb.GetManagedDeveloperStatusRequest) (*pb.ManagedDeveloperStatus, error) {
	actor, e := profileAuthID(ctx)
	if e != nil {
		return nil, e
	}
	if r == nil || len(r.ProtoReflect().GetUnknown()) != 0 {
		return nil, developerManagementError(d.ErrManagementInvalid)
	}
	out, e := s.service.Get(ctx, actor, r.SubjectAuthId)
	if e != nil {
		return nil, developerManagementError(e)
	}
	return developerManagementResponse(out), nil
}
func developerManagementResponse(s d.ManagedDeveloperState) *pb.ManagedDeveloperStatus {
	out := &pb.ManagedDeveloperStatus{SubjectAuthId: s.AuthID, AccountStatus: pb.AccountStatus(pb.AccountStatus_value[s.AccountStatus]), DeveloperStatus: pb.DeveloperStatus(pb.DeveloperStatus_value[s.Status]), DeveloperRevision: s.Revision}
	if s.StatusChangedAt != nil {
		out.StatusChangedAt = timestamppb.New(*s.StatusChangedAt)
	}
	return out
}
func developerManagementError(err error) error {
	code, reason := codes.Unavailable, d.ErrManagementUnavailable.Error()
	for _, p := range []struct {
		err  error
		code codes.Code
	}{{d.ErrManagementIdentity, codes.Unauthenticated}, {d.ErrManagementInvalid, codes.InvalidArgument}, {d.ErrManagementForbidden, codes.PermissionDenied}, {d.ErrManagementSubject, codes.NotFound}, {d.ErrManagementConflict, codes.Aborted}, {d.ErrRestoreBlocked, codes.FailedPrecondition}, {d.ErrDeveloperRevisionExhausted, codes.FailedPrecondition}, {d.ErrManagementRate, codes.ResourceExhausted}} {
		if errors.Is(err, p.err) {
			code, reason = p.code, p.err.Error()
			break
		}
	}
	if errors.Is(err, context.Canceled) {
		code = codes.Canceled
	}
	if errors.Is(err, context.DeadlineExceeded) {
		code = codes.DeadlineExceeded
	}
	return transportStatus(code, reason, "developer management request failed")
}
