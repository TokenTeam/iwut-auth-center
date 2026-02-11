package middleware

import (
	"context"
	"iwut-auth-center/internal/util"
	"strings"

	"github.com/go-kratos/kratos/v2/errors"
	"github.com/go-kratos/kratos/v2/middleware"
	"github.com/go-kratos/kratos/v2/transport"
)

type JwtCheckMiddleware struct {
	jwtUtil *util.JwtUtil
}

func NewJwtInfoMiddleware(jwtUtil *util.JwtUtil) *JwtCheckMiddleware {
	return &JwtCheckMiddleware{
		jwtUtil: jwtUtil,
	}
}

func GetJwtTypeFromHeader(header transport.Header) util.JwtType {
	jwtType := header.Get("X-Auth-Jwt-Type")
	switch strings.ToLower(jwtType) {
	case "official":
		return util.OfficialJwt
	case "oauth":
		return util.OAuthJwt
	default:
		return util.UnknownJwt
	}
}

func (c *JwtCheckMiddleware) GetJwtInfoMiddleware() middleware.Middleware {
	return func(handler middleware.Handler) middleware.Handler {
		return func(ctx context.Context, req any) (any, error) {
			tr, ok := transport.FromServerContext(ctx)
			if !ok {
				return nil, errors.New(500, "", "transport not found")
			}
			if strings.HasPrefix(tr.Operation(), "/auth_center.v1.auth.Auth/") ||
				strings.HasPrefix(tr.Operation(), "/auth_center.v1.oauth2.OAuth2/getToken") {
				return handler(ctx, req)
			}
			header := tr.RequestHeader()

			switch GetJwtTypeFromHeader(header) {
			case util.UnknownJwt:
				return nil, errors.Unauthorized("", "Invalid or missing X-Auth-Jwt-Type header")
			case util.OfficialJwt:
				baseClaims, err := util.BaseAuthClaimsFromJSON(header.Get("X-Auth-Base-Claim"))
				if err != nil {
					return nil, errors.Unauthorized("", err.Error())
				}
				if baseClaims.Type != "access" {
					return nil, errors.Unauthorized("", "Invalid token type")
				}
				ctx = c.jwtUtil.WithTokenValue(ctx, &util.TokenValue{
					BaseAuthClaims: baseClaims,
				})
			case util.OAuthJwt:
				oauthClaims, err := util.OAuthClaimsFromJSON(header.Get("X-Auth-Oauth-Claim"))
				if err != nil {
					return nil, errors.Unauthorized("", err.Error())
				}
				if oauthClaims.Type != "access" {
					return nil, errors.Unauthorized("", "Invalid token type")
				}
				ctx = c.jwtUtil.WithTokenValue(ctx, &util.TokenValue{
					OAuthClaims: oauthClaims,
				})
			}
			return handler(ctx, req)
		}
	}
}
