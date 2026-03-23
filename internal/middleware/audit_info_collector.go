package middleware

import (
	"context"
	"iwut-auth-center/internal/util"

	"github.com/go-kratos/kratos/v2/middleware"
)

func GetAuditInfoCollectorMiddleware() middleware.Middleware {
	return func(handler middleware.Handler) middleware.Handler {
		return func(ctx context.Context, req interface{}) (interface{}, error) {
			ctx = util.WithRequestAudit(ctx)
			return handler(ctx, req)
		}
	}
}
