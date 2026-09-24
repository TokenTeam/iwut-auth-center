package transport

import (
	"context"
	"errors"
	pb "github.com/TokenTeam/iwut-api-proto/gen/go/auth_center/v1/reviewer_permission"
	"github.com/go-kratos/kratos/v2/middleware"
	kt "github.com/go-kratos/kratos/v2/transport"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/proto"
	"iwut-auth-center/internal/reviewer/domain"
	"iwut-auth-center/internal/reviewer/usecase"
	"slices"
)

func isReviewerOperation(op string) bool {
	return op == pb.ReviewerPermissionService_ManageReviewerPermission_FullMethodName || op == pb.ReviewerPermissionService_GetReviewerPermission_FullMethodName
}

// Reuses the verifier without weakening profile's independent identity boundary.
func UserCapabilityIdentityMiddleware(v *UserIdentityVerifier) middleware.Middleware {
	return func(next middleware.Handler) middleware.Handler {
		return func(ctx context.Context, req any) (any, error) {
			tr, ok := kt.FromServerContext(ctx)
			if !ok {
				return nil, reviewerError(domain.ErrForbidden)
			}
			if !isReviewerOperation(tr.Operation()) {
				return UserProfileIdentityMiddleware(v)(next)(ctx, req)
			}
			values := tr.RequestHeader().Values(UserIdentityHeader)
			if len(values) == 0 {
				return nil, transportStatus(codes.Unauthenticated, "USER_IDENTITY_REQUIRED", "user identity required")
			}
			if len(values) != 1 {
				return nil, transportStatus(codes.Unauthenticated, "INVALID_USER_IDENTITY", "invalid user identity")
			}
			identity, err := v.verifyIdentity(values[0])
			if err != nil {
				return nil, transportStatus(codes.Unauthenticated, "INVALID_USER_IDENTITY", "invalid user identity")
			}
			if !slices.Contains(identity.Permissions, domain.Manager) {
				return nil, reviewerError(domain.ErrForbidden)
			}
			if msg, ok := req.(proto.Message); !ok || proto.Size(msg) > 16*1024 {
				return nil, transportStatus(codes.ResourceExhausted, "AUTHENTICATION_INPUT_TOO_LARGE", "request is too large")
			}
			return next(context.WithValue(ctx, userIdentityContextKey{}, identity.AuthID), req)
		}
	}
}

type ReviewerPermissionService struct {
	pb.UnimplementedReviewerPermissionServiceServer
	service *usecase.Service
}

func NewReviewerPermissionService(s *usecase.Service) *ReviewerPermissionService {
	return &ReviewerPermissionService{service: s}
}
func (s *ReviewerPermissionService) ManageReviewerPermission(ctx context.Context, r *pb.ManageReviewerPermissionRequest) (*pb.ReviewerPermission, error) {
	actor, err := profileAuthID(ctx)
	if err != nil {
		return nil, err
	}
	if r == nil || r.ExpectedRevision == nil || len(r.ProtoReflect().GetUnknown()) != 0 {
		return nil, reviewerError(domain.ErrInvalid)
	}
	action := ""
	switch r.Action {
	case pb.ReviewerPermissionAction_REVIEWER_PERMISSION_ACTION_GRANT:
		action = "GRANT"
	case pb.ReviewerPermissionAction_REVIEWER_PERMISSION_ACTION_REVOKE:
		action = "REVOKE"
	}
	result, err := s.service.Manage(ctx, domain.Command{ActorAuthID: actor, SubjectAuthID: r.SubjectAuthId, Action: action, Reason: r.Reason, ExpectedRevision: r.GetExpectedRevision()})
	if err != nil {
		return nil, reviewerError(err)
	}
	return reviewerResponse(result), nil
}
func (s *ReviewerPermissionService) GetReviewerPermission(ctx context.Context, r *pb.GetReviewerPermissionRequest) (*pb.ReviewerPermission, error) {
	actor, err := profileAuthID(ctx)
	if err != nil {
		return nil, err
	}
	if r == nil || len(r.ProtoReflect().GetUnknown()) != 0 {
		return nil, reviewerError(domain.ErrInvalid)
	}
	result, err := s.service.Get(ctx, actor, r.SubjectAuthId)
	if err != nil {
		return nil, reviewerError(err)
	}
	return reviewerResponse(result), nil
}
func reviewerResponse(s domain.State) *pb.ReviewerPermission {
	return &pb.ReviewerPermission{SubjectAuthId: s.AuthID, Reviewer: s.Has(domain.Reviewer), PermissionRevision: s.Revision}
}
func reviewerError(err error) error {
	code := codes.Unavailable
	reason := domain.ErrUnavailable.Error()
	for _, entry := range []struct {
		err  error
		code codes.Code
	}{{domain.ErrInvalid, codes.InvalidArgument}, {domain.ErrForbidden, codes.PermissionDenied}, {domain.ErrSubject, codes.NotFound}, {domain.ErrConflict, codes.Aborted}, {domain.ErrExhausted, codes.Aborted}} {
		if errors.Is(err, entry.err) {
			code = entry.code
			reason = entry.err.Error()
			break
		}
	}
	if errors.Is(err, context.Canceled) {
		code = codes.Canceled
	}
	if errors.Is(err, context.DeadlineExceeded) {
		code = codes.DeadlineExceeded
	}
	return transportStatus(code, reason, "reviewer permission request failed")
}
