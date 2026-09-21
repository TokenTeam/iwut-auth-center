package transport

import (
	"context"
	"errors"

	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"iwut-auth-center/internal/scope/port"
)

const (
	ReasonScopeCatalogUnavailable = "ERROR_REASON_SCOPE_CATALOG_UNAVAILABLE"
	ReasonInternal                = "ERROR_REASON_INTERNAL"
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
