package transport

import (
	"context"
	"errors"

	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	developerport "iwut-auth-center/internal/developer/port"
	developerusecase "iwut-auth-center/internal/developer/usecase"
	"iwut-auth-center/internal/scope/port"
)

const (
	ReasonScopeCatalogUnavailable      = "ERROR_REASON_SCOPE_CATALOG_UNAVAILABLE"
	ReasonInvalidDeveloperStatusQuery  = "ERROR_REASON_INVALID_DEVELOPER_STATUS_QUERY"
	ReasonDeveloperStatusNotFound      = "ERROR_REASON_DEVELOPER_STATUS_NOT_FOUND"
	ReasonDeveloperStatusUnavailable   = "ERROR_REASON_DEVELOPER_STATUS_UNAVAILABLE"
	ReasonServiceIdentityRequired      = "ERROR_REASON_SERVICE_IDENTITY_REQUIRED"
	ReasonInvalidServiceIdentity       = "ERROR_REASON_INVALID_SERVICE_IDENTITY"
	ReasonScopeCatalogReadForbidden    = "ERROR_REASON_SCOPE_CATALOG_READ_FORBIDDEN"
	ReasonDeveloperStatusReadForbidden = "ERROR_REASON_DEVELOPER_STATUS_READ_FORBIDDEN"
	ReasonSystemPrincipalReadForbidden = "ERROR_REASON_SYSTEM_PRINCIPAL_READ_FORBIDDEN"
	ReasonServicePermissionDenied      = "ERROR_REASON_SERVICE_PERMISSION_DENIED"
	ReasonInternal                     = "ERROR_REASON_INTERNAL"
)

func toTransportError(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, context.Canceled):
		return status.Error(codes.Canceled, "request canceled")
	case errors.Is(err, context.DeadlineExceeded):
		return status.Error(codes.DeadlineExceeded, "request deadline exceeded")
	case errors.Is(err, port.ErrScopeCatalogUnavailable):
		return transportStatus(codes.Unavailable, ReasonScopeCatalogUnavailable, "scope catalog is unavailable")
	case errors.Is(err, developerusecase.ErrInvalidDeveloperStatusQuery):
		return transportStatus(codes.InvalidArgument, ReasonInvalidDeveloperStatusQuery, "developer status query is invalid")
	case errors.Is(err, developerusecase.ErrDeveloperStatusNotFound):
		return transportStatus(codes.NotFound, ReasonDeveloperStatusNotFound, "developer status was not found")
	case errors.Is(err, developerport.ErrDeveloperStatusUnavailable):
		return transportStatus(codes.Unavailable, ReasonDeveloperStatusUnavailable, "developer status is unavailable")
	default:
		return transportStatus(codes.Internal, ReasonInternal, "internal failure")
	}
}

func transportStatus(code codes.Code, reason, message string) error {
	current := status.New(code, message)
	withDetails, err := current.WithDetails(&errdetails.ErrorInfo{Reason: reason})
	if err != nil {
		return current.Err()
	}
	return withDetails.Err()
}
