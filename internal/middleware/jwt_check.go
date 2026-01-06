package middleware

import (
	"context"
	"iwut-auth-center/internal/biz"
	"iwut-auth-center/internal/util"
	"strings"
	"time"

	"github.com/go-kratos/kratos/v2/errors"
	"github.com/go-kratos/kratos/v2/middleware"
	"github.com/go-kratos/kratos/v2/transport"
)

type JwtCheckMiddleware struct {
	authUsecase   *biz.AuthUsecase
	oauth2Usecase *biz.Oauth2Usecase
	jwtUtil       *util.JwtUtil
}

func NewJwtCheckMiddleware(uc *biz.AuthUsecase, oauth2Usecase *biz.Oauth2Usecase, jwtUtil *util.JwtUtil) *JwtCheckMiddleware {
	return &JwtCheckMiddleware{
		authUsecase:   uc,
		oauth2Usecase: oauth2Usecase,
		jwtUtil:       jwtUtil,
	}
}

func (c *JwtCheckMiddleware) GetCheckJwtMiddleware() middleware.Middleware {
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
				return nil, errors.Unauthorized("", "Unauthorized")
			}

			// Verify and parse token 检查 签名 过期时间(exp iat) 和 iss
			result, err := c.jwtUtil.DecodeJWTWithRS256(token)
			if err != nil {
				return nil, errors.Unauthorized("", err.Error())
			}

			// 判断Token类型 一方还是Oauth
			switch c.jwtUtil.GetJwtTypeFromClaims(result) {
			case util.OfficialJwt:
				baseClaims, err := c.jwtUtil.ToBaseAuthClaims(result)
				if err != nil {
					return nil, errors.Unauthorized("", err.Error())
				}
				if baseClaims.Type != "access" {
					return nil, errors.Unauthorized("", "Invalid token type")
				}
				version, err := c.authUsecase.Repo.GetUserVersion(ctx,
					baseClaims.Uid,
					time.Duration(baseClaims.Exp-time.Now().Unix())*time.Second)
				if err != nil {
					return nil, errors.Unauthorized("", err.Error())
				}
				if baseClaims.Version != version {
					return nil, errors.Unauthorized("", "Token has been revoked")
				}
				ctx = c.jwtUtil.WithTokenValue(ctx, &util.TokenValue{
					Token:          token,
					BaseAuthClaims: baseClaims,
				})
			case util.OAuthJwt:
				oauthClaims, err := c.jwtUtil.ToOAuthClaims(result)
				if err != nil {
					return nil, errors.Unauthorized("", err.Error())
				}
				if oauthClaims.Type != "access" {
					return nil, errors.Unauthorized("", "Invalid token type")
				}
				// whitelist check: token must be allowed
				allowed, err := c.oauth2Usecase.Repo.CheckJTIAllowed(ctx, oauthClaims.Uid, oauthClaims.Azp, oauthClaims.Jti)
				if err != nil {
					return nil, errors.Unauthorized("", err.Error())
				}
				if !allowed {
					return nil, errors.Unauthorized("", "Token has been revoked")
				}
				ctx = c.jwtUtil.WithTokenValue(ctx, &util.TokenValue{
					Token:       token,
					OAuthClaims: oauthClaims,
				})
			}
			return handler(ctx, req)
		}
	}
}
