package transport

import (
	"context"
	"errors"
	pb "github.com/TokenTeam/iwut-api-proto/gen/go/auth_center/v1/platform_administrator"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
	d "iwut-auth-center/internal/administrator/domain"
	"iwut-auth-center/internal/administrator/usecase"
)

func isPlatformAdministratorOperation(op string) bool {
	return op == pb.PlatformAdministratorService_ManagePlatformAdministrator_FullMethodName || op == pb.PlatformAdministratorService_GetPlatformAdministrator_FullMethodName || op == pb.PlatformAdministratorService_ListPlatformAdministrators_FullMethodName
}

type PlatformAdministratorService struct {
	pb.UnimplementedPlatformAdministratorServiceServer
	service *usecase.Service
}

func NewPlatformAdministratorService(s *usecase.Service) *PlatformAdministratorService {
	return &PlatformAdministratorService{service: s}
}
func (s *PlatformAdministratorService) ManagePlatformAdministrator(ctx context.Context, r *pb.ManagePlatformAdministratorRequest) (*pb.PlatformAdministratorState, error) {
	actor, e := profileAuthID(ctx)
	if e != nil {
		return nil, e
	}
	if r == nil || r.ExpectedPermissionRevision == nil || len(r.ProtoReflect().GetUnknown()) != 0 {
		return nil, platformAdministratorError(d.ErrInvalid)
	}
	action := ""
	switch r.Action {
	case pb.Action_GRANT:
		action = "GRANT"
	case pb.Action_REVOKE:
		action = "REVOKE"
	}
	out, e := s.service.Manage(ctx, d.Command{ActorAuthID: actor, SubjectAuthID: r.SubjectAuthId, Action: action, ExpectedRevision: r.GetExpectedPermissionRevision(), Reason: r.Reason})
	if e != nil {
		return nil, platformAdministratorError(e)
	}
	return platformAdministratorResponse(out), nil
}
func (s *PlatformAdministratorService) GetPlatformAdministrator(ctx context.Context, r *pb.GetPlatformAdministratorRequest) (*pb.PlatformAdministratorState, error) {
	actor, e := profileAuthID(ctx)
	if e != nil {
		return nil, e
	}
	if r == nil || len(r.ProtoReflect().GetUnknown()) != 0 {
		return nil, platformAdministratorError(d.ErrInvalid)
	}
	out, e := s.service.Get(ctx, actor, r.SubjectAuthId)
	if e != nil {
		return nil, platformAdministratorError(e)
	}
	return platformAdministratorResponse(out), nil
}
func (s *PlatformAdministratorService) ListPlatformAdministrators(ctx context.Context, r *pb.ListPlatformAdministratorsRequest) (*pb.PlatformAdministratorPage, error) {
	actor, e := profileAuthID(ctx)
	if e != nil {
		return nil, e
	}
	if r == nil || len(r.ProtoReflect().GetUnknown()) != 0 {
		return nil, platformAdministratorError(d.ErrInvalid)
	}
	size := 20
	if r.PageSize != nil {
		size = int(r.GetPageSize())
	}
	out, e := s.service.List(ctx, actor, r.AfterAuthId, size)
	if e != nil {
		return nil, platformAdministratorError(e)
	}
	response := &pb.PlatformAdministratorPage{Items: []*pb.PlatformAdministratorState{}, NextAfterAuthId: out.NextAfterAuthID, ObservedAt: timestamppb.New(out.ObservedAt)}
	for _, state := range out.Items {
		response.Items = append(response.Items, platformAdministratorResponse(state))
	}
	return response, nil
}
func platformAdministratorResponse(s d.State) *pb.PlatformAdministratorState {
	out := &pb.PlatformAdministratorState{SubjectAuthId: s.AuthID, AccountStatus: pb.AccountStatus(pb.AccountStatus_value[s.AccountStatus]), Membership: pb.Membership_NONE, Effective: s.Effective(), PermissionRevision: s.Revision, GrantBlockers: []pb.GrantBlocker{}}
	if s.Granted {
		out.Membership = pb.Membership_GRANTED
	}
	for _, b := range s.Blockers {
		out.GrantBlockers = append(out.GrantBlockers, pb.GrantBlocker(pb.GrantBlocker_value[b]))
	}
	return out
}
func platformAdministratorError(err error) error {
	code, reason := codes.Unavailable, d.ErrUnavailable.Error()
	for _, p := range []struct {
		err  error
		code codes.Code
	}{{d.ErrInvalid, codes.InvalidArgument}, {d.ErrForbidden, codes.PermissionDenied}, {d.ErrSubject, codes.NotFound}, {d.ErrConflict, codes.Aborted}, {d.ErrGrantBlocked, codes.FailedPrecondition}, {d.ErrLast, codes.FailedPrecondition}, {d.ErrExhausted, codes.FailedPrecondition}, {d.ErrRate, codes.ResourceExhausted}} {
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
	out := transportStatus(code, reason, "platform administrator request failed")
	var blocked *d.Blocked
	if errors.As(err, &blocked) {
		with, e := status.New(code, "platform administrator request failed").WithDetails(&errdetails.ErrorInfo{Reason: reason, Metadata: map[string]string{"blocker": blocked.Blocker}})
		if e != nil {
			return out
		}
		return with.Err()
	}
	return out
}
