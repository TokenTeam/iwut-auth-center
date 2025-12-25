package middleware

import (
	"context"
	"iwut-auth-center/internal/biz"
	"iwut-auth-center/internal/util"
	"strings"

	"github.com/go-kratos/kratos/v2/errors"
	"github.com/go-kratos/kratos/v2/middleware"
	"github.com/go-kratos/kratos/v2/transport"
)

type JwtCheckMiddleware struct {
	authUsecase *biz.AuthUsecase
	jwtUtil     *util.JwtUtil
}

func NewJwtCheckMiddleware(uc *biz.AuthUsecase, jwtUtil *util.JwtUtil) *JwtCheckMiddleware {
	return &JwtCheckMiddleware{
		authUsecase: uc,
		jwtUtil:     jwtUtil,
	}
}

// tokenKey is an unexported context key type to avoid collisions

//	func (e *JwtError) Error() string {
//		return fmt.Sprintf("%d: %s", e.Code, e.Message)
//	}

func (c *JwtCheckMiddleware) GetCheckJwtMiddleware() middleware.Middleware {
	return func(handler middleware.Handler) middleware.Handler {
		return func(ctx context.Context, req any) (any, error) {
			tr, ok := transport.FromServerContext(ctx)
			if !ok {
				return nil, errors.New(500, "", "transport not found")
			}
			if strings.HasPrefix(tr.Operation(), "/auth_center.v1.auth.Auth/") {
				return handler(ctx, req)
			}
			header := tr.RequestHeader()
			token := ""
			// Try Authorization header first
			h := header.Get("Authorization")
			if h == "" {
				h = header.Get("authorization")
			}
			if h != "" {
				// Accept formats like: "Bearer <token>" (case-insensitive) or raw token
				parts := strings.Fields(h)
				if len(parts) == 2 && strings.ToLower(parts[0]) == "bearer" {
					token = parts[1]
				} else {
					token = h
				}
			} else {
				h := header.Get("Cookie")
				if h == "" {
					h = header.Get("cookie")
				}
				parts := strings.Split(h, ";")
				for _, part := range parts {
					part = strings.TrimSpace(part)
					if strings.HasPrefix(part, "access_token=") {
						token = strings.TrimPrefix(part, "access_token=")
						break
					}
				}
			}

			// If no token present, return 401 Error immediately
			if strings.TrimSpace(token) == "" {
				return nil, errors.New(401, "", "Unauthorized")
			}

			// Verify and parse token
			result, err := c.jwtUtil.DecodeJWTWithRS256(token)
			if err != nil {
				return nil, errors.New(401, "", err.Error())
			}
			ctx = c.jwtUtil.WithTokenValue(ctx, &util.TokenValue{
				Token:  token,
				Claims: result,
			})

			return handler(ctx, req)
		}
	}
}
