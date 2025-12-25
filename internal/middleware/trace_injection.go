package middleware

import (
	"context"
	"iwut-auth-center/internal/util"

	"github.com/go-kratos/kratos/v2/middleware"
)

func GetTraceInjectionMiddleware() middleware.Middleware {
	return func(handler middleware.Handler) middleware.Handler {
		return func(ctx context.Context, req interface{}) (reply interface{}, err error) {
			ctx = util.WithRequestID(ctx, util.GenerateRequestID())
			return handler(ctx, req)
		}
	}
}
