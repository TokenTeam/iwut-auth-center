package transport

import (
	"context"
	"errors"
	identityv1 "iwut-auth-center/api/gen/go/auth_center/v1/user_identity"
	"strings"

	"github.com/go-kratos/kratos/v2/middleware"
	kratostransport "github.com/go-kratos/kratos/v2/transport"
	"google.golang.org/grpc/codes"

	developerstatusv1 "iwut-auth-center/api/gen/go/auth_center/v1/developer_status"
	scopecatalogv1 "iwut-auth-center/api/gen/go/auth_center/v1/scope_catalog"
	systemprincipalv1 "iwut-auth-center/api/gen/go/auth_center/v1/system_principal"
)

type serviceIdentityContextKey struct{}

func serviceIdentityFromContext(ctx context.Context) (ServiceIdentity, bool) {
	identity, ok := ctx.Value(serviceIdentityContextKey{}).(ServiceIdentity)
	return identity, ok
}

func serviceIdentityMiddleware(verifier *ServiceIdentityVerifier) middleware.Middleware {
	return func(handler middleware.Handler) middleware.Handler {
		return func(ctx context.Context, request any) (any, error) {
			transporter, ok := kratostransport.FromServerContext(ctx)
			if !ok {
				return nil, serviceIdentityError(errServiceIdentityRequired, "")
			}
			operation := transporter.Operation()
			if strings.HasPrefix(operation, "/grpc.health.v1.Health/") || strings.HasPrefix(operation, "/grpc.reflection.") {
				return handler(ctx, request)
			}
			requiredPermission, protected := permissionForOperation(operation)
			if !protected {
				return nil, transportStatus(codes.PermissionDenied, ReasonServicePermissionDenied, "service operation is forbidden")
			}
			values := transporter.RequestHeader().Values(ServiceAuthorizationHeader)
			if len(values) == 0 || (len(values) == 1 && strings.TrimSpace(values[0]) == "") {
				return nil, serviceIdentityError(errServiceIdentityRequired, operation)
			}
			if len(values) != 1 || !strings.HasPrefix(values[0], "Bearer ") {
				return nil, serviceIdentityError(errServiceIdentityInvalid, operation)
			}
			token := strings.TrimPrefix(values[0], "Bearer ")
			if token == "" || strings.TrimSpace(token) != token {
				return nil, serviceIdentityError(errServiceIdentityInvalid, operation)
			}
			identity, err := verifier.Verify(token)
			if err != nil {
				return nil, serviceIdentityError(err, operation)
			}
			if !identity.HasPermission(requiredPermission) {
				return nil, serviceIdentityError(errServicePermissionDenied, operation)
			}
			return handler(context.WithValue(ctx, serviceIdentityContextKey{}, identity), request)
		}
	}
}

func permissionForOperation(operation string) (string, bool) {
	switch operation {
	case identityv1.UserIdentityService_IssueUserIdentityFromSession_FullMethodName:
		return PermissionIdentityIssue, true
	case scopecatalogv1.ScopeCatalog_GetScopeCatalogSnapshot_FullMethodName:
		return PermissionScopeCatalogRead, true
	case developerstatusv1.DeveloperStatusDirectory_BatchGetDeveloperStatuses_FullMethodName:
		return PermissionDeveloperStatusRead, true
	case systemprincipalv1.SystemPrincipalDirectory_ResolveSystemPrincipal_FullMethodName:
		return PermissionSystemPrincipalResolve, true
	default:
		return "", false
	}
}

func serviceIdentityError(err error, operation string) error {
	if errors.Is(err, errServiceIdentityRequired) {
		return transportStatus(codes.Unauthenticated, ReasonServiceIdentityRequired, "service identity is required")
	}
	if errors.Is(err, errServicePermissionDenied) {
		reason := ReasonServicePermissionDenied
		switch operation {
		case identityv1.UserIdentityService_IssueUserIdentityFromSession_FullMethodName:
			reason = ReasonIdentityIssuanceForbidden
		case scopecatalogv1.ScopeCatalog_GetScopeCatalogSnapshot_FullMethodName:
			reason = ReasonScopeCatalogReadForbidden
		case developerstatusv1.DeveloperStatusDirectory_BatchGetDeveloperStatuses_FullMethodName:
			reason = ReasonDeveloperStatusReadForbidden
		case systemprincipalv1.SystemPrincipalDirectory_ResolveSystemPrincipal_FullMethodName:
			reason = ReasonSystemPrincipalReadForbidden
		}
		return transportStatus(codes.PermissionDenied, reason, "service is not allowed to call this operation")
	}
	return transportStatus(codes.Unauthenticated, ReasonInvalidServiceIdentity, "service identity is invalid")
}
