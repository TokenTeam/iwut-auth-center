package transport

import (
	"context"

	"github.com/go-kratos/kratos/v2/middleware"
	kratostransport "github.com/go-kratos/kratos/v2/transport"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/proto"

	authv1 "github.com/TokenTeam/iwut-api-proto/gen/go/auth_center/v1/authentication"
	reviewerpb "github.com/TokenTeam/iwut-api-proto/gen/go/auth_center/v1/reviewer_permission"
)

// A nil user middleware fails closed. It never falls back to service identity
// or treats a whole namespace as anonymous.
func userEndpointAuthenticationMiddleware(service *ServiceIdentityVerifier, profile, session middleware.Middleware, enabled bool, maximumBytes ...int) middleware.Middleware {
	limit := 16 * 1024
	if len(maximumBytes) > 0 && maximumBytes[0] > 0 {
		limit = maximumBytes[0]
	}
	return func(handler middleware.Handler) middleware.Handler {
		internal := serviceIdentityMiddleware(service)(handler)
		return func(ctx context.Context, request any) (any, error) {
			if tr, ok := kratostransport.FromServerContext(ctx); ok && (emailMethod(tr.Operation()) || emailLoginMethod(tr.Operation())) {
				return handler(ctx, request)
			}
			if !enabled {
				return internal(ctx, request)
			}
			tr, ok := kratostransport.FromServerContext(ctx)
			if !ok {
				return nil, transportStatus(codes.Unauthenticated, "AUTHENTICATION_FAILED", "authentication context is required")
			}
			if developerApplicationMethod(tr.Operation()) {
				return handler(ctx, request)
			}
			switch tr.Operation() {
			case authv1.AuthenticationService_BeginUserRegistration_FullMethodName,
				authv1.AuthenticationService_CompleteUserRegistration_FullMethodName,
				authv1.AuthenticationService_BeginDeviceLogin_FullMethodName,
				authv1.AuthenticationService_CompleteDeviceLogin_FullMethodName,
				authv1.AuthenticationService_RevokeCurrentSession_FullMethodName:
				if err := checkAuthenticationMessageSize(request, limit); err != nil {
					return nil, err
				}
				return handler(ctx, request)
			case authv1.AuthenticationService_RevokeOwnCredential_FullMethodName:
				if err := checkAuthenticationMessageSize(request, limit); err != nil {
					return nil, err
				}
				if session == nil {
					return nil, transportStatus(codes.Unauthenticated, "SESSION_INVALID", "session is invalid")
				}
				return session(handler)(ctx, request)
			case "/auth_center.v1.user_profile.UserProfileService/EditOwnProfile",
				"/auth_center.v1.user_profile.UserProfileService/GetOwnProfile",
				"/auth_center.v1.user_profile.UserProfileService/GetProfileEditingSchema",
				reviewerpb.ReviewerPermissionService_ManageReviewerPermission_FullMethodName,
				reviewerpb.ReviewerPermissionService_GetReviewerPermission_FullMethodName,
				reviewerpb.ReviewerPermissionService_ManageApplicationReviewPermission_FullMethodName,
				reviewerpb.ReviewerPermissionService_GetApplicationReviewPermissions_FullMethodName:
				if profile == nil {
					return nil, transportStatus(codes.Unauthenticated, "USER_IDENTITY_REQUIRED", "user identity is required")
				}
				return profile(handler)(ctx, request)
			default:
				return internal(ctx, request)
			}
		}
	}
}

func checkAuthenticationMessageSize(request any, limit int) error {
	message, ok := request.(proto.Message)
	if !ok || message == nil {
		return transportStatus(codes.InvalidArgument, "INVALID_LOGIN_INPUT", "invalid authentication request")
	}
	if proto.Size(message) > limit {
		return transportStatus(codes.ResourceExhausted, "AUTHENTICATION_INPUT_TOO_LARGE", "authentication request is too large")
	}
	return nil
}
