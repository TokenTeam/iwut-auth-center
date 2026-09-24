package transport

import (
	"context"
	"errors"

	"google.golang.org/grpc/codes"

	systemprincipalv1 "github.com/TokenTeam/iwut-api-proto/gen/go/auth_center/v1/system_principal"
	"iwut-auth-center/internal/systemprincipal/domain"
	"iwut-auth-center/internal/systemprincipal/port"
	"iwut-auth-center/internal/systemprincipal/usecase"
)

const (
	ReasonInvalidSystemPrincipalPurpose = "ERROR_REASON_INVALID_SYSTEM_PRINCIPAL_PURPOSE"
	ReasonSystemPrincipalNotFound       = "ERROR_REASON_SYSTEM_PRINCIPAL_NOT_FOUND"
	ReasonSystemPrincipalUnavailable    = "ERROR_REASON_SYSTEM_PRINCIPAL_UNAVAILABLE"
)

type ResolveSystemPrincipalHandler interface {
	Handle(ctx context.Context, purpose string) (domain.Principal, error)
}

type SystemPrincipalService struct {
	systemprincipalv1.UnimplementedSystemPrincipalDirectoryServer
	handler ResolveSystemPrincipalHandler
}

func NewSystemPrincipalService(handler ResolveSystemPrincipalHandler) *SystemPrincipalService {
	return &SystemPrincipalService{handler: handler}
}

func (service *SystemPrincipalService) ResolveSystemPrincipal(
	ctx context.Context,
	request *systemprincipalv1.ResolveSystemPrincipalRequest,
) (*systemprincipalv1.ResolveSystemPrincipalResponse, error) {
	identity, ok := serviceIdentityFromContext(ctx)
	if !ok {
		return nil, serviceIdentityError(errServiceIdentityRequired, systemprincipalv1.SystemPrincipalDirectory_ResolveSystemPrincipal_FullMethodName)
	}
	purpose, rawPurpose := systemPurposeFromProto(request.GetPurpose())
	if rawPurpose == "" {
		return nil, transportStatus(codes.InvalidArgument, ReasonInvalidSystemPrincipalPurpose, "system principal purpose is invalid")
	}
	if !identity.MayResolveSystemPrincipal(rawPurpose) {
		return nil, transportStatus(codes.PermissionDenied, ReasonSystemPrincipalReadForbidden, "system principal purpose is forbidden")
	}
	principal, err := service.handler.Handle(ctx, rawPurpose)
	if err != nil {
		switch {
		case errors.Is(err, usecase.ErrInvalidSystemPrincipalPurpose):
			return nil, transportStatus(codes.InvalidArgument, ReasonInvalidSystemPrincipalPurpose, "system principal purpose is invalid")
		case errors.Is(err, port.ErrSystemPrincipalNotFound):
			return nil, transportStatus(codes.NotFound, ReasonSystemPrincipalNotFound, "system principal was not found")
		case errors.Is(err, port.ErrSystemPrincipalUnavailable):
			return nil, transportStatus(codes.Unavailable, ReasonSystemPrincipalUnavailable, "system principal is unavailable")
		default:
			return nil, transportStatus(codes.Internal, ReasonInternal, "internal failure")
		}
	}
	return &systemprincipalv1.ResolveSystemPrincipalResponse{AuthId: principal.AuthID(), Purpose: purpose}, nil
}

func systemPurposeFromProto(value systemprincipalv1.SystemPrincipalPurpose) (systemprincipalv1.SystemPrincipalPurpose, string) {
	if value == systemprincipalv1.SystemPrincipalPurpose_SYSTEM_PRINCIPAL_PURPOSE_APP_CENTER_REVIEW_AUTO_REJECTION {
		return value, string(domain.PurposeAppCenterReviewAutoRejection)
	}
	return systemprincipalv1.SystemPrincipalPurpose_SYSTEM_PRINCIPAL_PURPOSE_UNSPECIFIED, ""
}

var _ systemprincipalv1.SystemPrincipalDirectoryServer = (*SystemPrincipalService)(nil)
