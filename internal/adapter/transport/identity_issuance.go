package transport

import (
	"context"
	"errors"
	identityv1 "github.com/TokenTeam/iwut-api-proto/gen/go/auth_center/v1/identity"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"iwut-auth-center/internal/identity/domain"
	"iwut-auth-center/internal/identity/usecase"
)

const ReasonIdentityIssuanceForbidden = "IDENTITY_ISSUANCE_FORBIDDEN"

type UserIdentityService struct {
	identityv1.UnimplementedUserIdentityServiceServer
	service *usecase.Service
}

func NewUserIdentityService(service *usecase.Service) *UserIdentityService {
	return &UserIdentityService{service: service}
}
func (h *UserIdentityService) IssueUserIdentityFromSession(ctx context.Context, request *identityv1.IssueUserIdentityFromSessionRequest) (*identityv1.IssuedUserIdentity, error) {
	caller, ok := serviceIdentityFromContext(ctx)
	if !ok {
		return nil, serviceIdentityError(errServiceIdentityRequired, identityv1.UserIdentityService_IssueUserIdentityFromSession_FullMethodName)
	}
	if !caller.HasPermission(PermissionIdentityIssue) {
		return nil, identityIssuanceError(domain.ErrForbidden)
	}
	if request == nil || len(request.ProtoReflect().GetUnknown()) != 0 || !domain.KnownAudience(request.GetAudience()) {
		return nil, identityIssuanceError(domain.ErrInvalidRequest)
	}
	if !caller.MayIssueIdentity(request.Audience) {
		return nil, identityIssuanceError(domain.ErrForbidden)
	}
	md, _ := metadata.FromIncomingContext(ctx)
	values := md.Get("x-iwut-session")
	if len(values) != 1 || !canonicalSessionToken(values[0]) {
		return nil, identityIssuanceError(domain.ErrSessionInvalid)
	}
	result, err := h.service.Issue(ctx, values[0], request.Audience, []string{request.Audience})
	if err != nil {
		return nil, identityIssuanceError(err)
	}
	return &identityv1.IssuedUserIdentity{IdentityJws: result.JWS, ExpiresAtUnixSeconds: result.ExpiresAt}, nil
}
func identityIssuanceError(err error) error {
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return transportStatus(codes.DeadlineExceeded, "IDENTITY_ISSUANCE_TIMEOUT", "identity issuance timed out")
	case errors.Is(err, context.Canceled):
		return transportStatus(codes.Canceled, "IDENTITY_ISSUANCE_UNAVAILABLE", "identity issuance canceled")
	case errors.Is(err, domain.ErrInvalidRequest):
		return transportStatus(codes.InvalidArgument, "INVALID_IDENTITY_ISSUANCE_REQUEST", "identity issuance request is invalid")
	case errors.Is(err, domain.ErrForbidden):
		return transportStatus(codes.PermissionDenied, ReasonIdentityIssuanceForbidden, "identity issuance is forbidden")
	case errors.Is(err, domain.ErrSessionInvalid):
		return transportStatus(codes.Unauthenticated, "SESSION_INVALID", "session is invalid")
	default:
		return transportStatus(codes.Unavailable, "IDENTITY_ISSUANCE_UNAVAILABLE", "identity issuance unavailable")
	}
}
