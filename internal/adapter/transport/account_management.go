package transport

import (
	"context"
	"errors"
	pb "github.com/TokenTeam/iwut-api-proto/gen/go/auth_center/v1/account_management"
	"github.com/go-kratos/kratos/v2/middleware"
	kt "github.com/go-kratos/kratos/v2/transport"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
	d "iwut-auth-center/internal/account/domain"
	"iwut-auth-center/internal/account/usecase"
	"slices"
)

type AccountManagementService struct {
	pb.UnimplementedAccountManagementServiceServer
	service *usecase.Service
}

func NewAccountManagementService(s *usecase.Service) *AccountManagementService {
	return &AccountManagementService{service: s}
}
func accountManagementMethod(op string) bool {
	return op == pb.AccountManagementService_ManageUserAccountStatus_FullMethodName || op == pb.AccountManagementService_GetUserAccountStatus_FullMethodName
}
func (s *AccountManagementService) ManageUserAccountStatus(ctx context.Context, r *pb.ManageUserAccountStatusRequest) (*pb.UserAccountStatus, error) {
	actor, err := profileAuthID(ctx)
	if err != nil {
		return nil, accountError(d.ErrIdentity)
	}
	if r == nil || len(r.ProtoReflect().GetUnknown()) > 0 || r.ExpectedAccountRevision == nil {
		return nil, accountError(d.ErrInvalid)
	}
	action := ""
	switch r.Action {
	case pb.AccountStatusAction_ACCOUNT_STATUS_ACTION_DISABLE:
		action = "DISABLE"
	case pb.AccountStatusAction_ACCOUNT_STATUS_ACTION_RESTORE:
		action = "RESTORE"
	default:
		return nil, accountError(d.ErrInvalid)
	}
	out, err := s.service.Manage(ctx, d.Command{ActorAuthID: actor, SubjectAuthID: r.SubjectAuthId, Action: action, ExpectedRevision: r.GetExpectedAccountRevision(), Reason: r.Reason})
	if err != nil {
		return nil, accountError(err)
	}
	return accountResponse(out), nil
}
func (s *AccountManagementService) GetUserAccountStatus(ctx context.Context, r *pb.GetUserAccountStatusRequest) (*pb.UserAccountStatus, error) {
	actor, err := profileAuthID(ctx)
	if err != nil {
		return nil, accountError(d.ErrIdentity)
	}
	if r == nil || len(r.ProtoReflect().GetUnknown()) > 0 {
		return nil, accountError(d.ErrInvalid)
	}
	out, err := s.service.Get(ctx, actor, r.SubjectAuthId)
	if err != nil {
		return nil, accountError(err)
	}
	return accountResponse(out), nil
}
func accountResponse(s d.State) *pb.UserAccountStatus {
	out := &pb.UserAccountStatus{SubjectAuthId: s.AuthID, AccountRevision: s.Revision, AccountStatus: pb.AccountStatus_ACCOUNT_STATUS_ACTIVE}
	if s.Status == "DISABLED" {
		out.AccountStatus = pb.AccountStatus_ACCOUNT_STATUS_DISABLED
	}
	if s.ChangedAt != nil {
		out.StatusChangedAt = timestamppb.New(*s.ChangedAt)
	}
	return out
}
func accountError(err error) error {
	code := codes.Unavailable
	reason := d.ErrUnavailable
	switch {
	case errors.Is(err, d.ErrIdentity):
		code = codes.Unauthenticated
		reason = d.ErrIdentity
	case errors.Is(err, d.ErrForbidden):
		code = codes.PermissionDenied
		reason = d.ErrForbidden
	case errors.Is(err, d.ErrInvalid):
		code = codes.InvalidArgument
		reason = d.ErrInvalid
	case errors.Is(err, d.ErrSubject):
		code = codes.NotFound
		reason = d.ErrSubject
	case errors.Is(err, d.ErrConflict):
		code = codes.Aborted
		reason = d.ErrConflict
	case errors.Is(err, d.ErrLastAdmin):
		code = codes.FailedPrecondition
		reason = d.ErrLastAdmin
	case errors.Is(err, d.ErrExhausted):
		code = codes.FailedPrecondition
		reason = d.ErrExhausted
	case errors.Is(err, d.ErrRate):
		code = codes.ResourceExhausted
		reason = d.ErrRate
	}
	return transportStatus(code, reason.Error(), reason.Error())
}

func accountManagementIdentity(v *UserIdentityVerifier) middleware.Middleware {
	return func(next middleware.Handler) middleware.Handler {
		return func(ctx context.Context, req any) (any, error) {
			tr, ok := kt.FromServerContext(ctx)
			if !ok || !accountManagementMethod(tr.Operation()) {
				return nil, accountError(d.ErrIdentity)
			}
			values := tr.RequestHeader().Values(UserIdentityHeader)
			if len(values) != 1 {
				return nil, accountError(d.ErrIdentity)
			}
			identity, err := v.verifyIdentity(values[0])
			if err != nil {
				return nil, accountError(d.ErrIdentity)
			}
			if !slices.Contains(identity.Permissions, "auth.account.manage") {
				return nil, accountError(d.ErrForbidden)
			}
			msg, ok := req.(proto.Message)
			if !ok || proto.Size(msg) > 16*1024 {
				return nil, accountError(d.ErrInvalid)
			}
			return next(context.WithValue(d.WithIdentity(ctx, identity.AuthID, identity.AccountRevision), userIdentityContextKey{}, identity.AuthID), req)
		}
	}
}
