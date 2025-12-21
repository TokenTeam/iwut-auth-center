package auth

import (
	"context"
	"iwut-auth-center/api/auth_center/v1/auth"
	"iwut-auth-center/internal/biz"
	"iwut-auth-center/internal/conf"
	"iwut-auth-center/internal/util"
	"time"
)

type AuthService struct {
	auth.UnimplementedAuthServer
	uc                   *biz.AuthUsecase
	jwtUtil              *util.JwtUtil
	accessTokenLifeSpan  time.Duration
	refreshTokenLifeSpan time.Duration
}

func NewAuthService(uc *biz.AuthUsecase, jwtUtil *util.JwtUtil, c *conf.Jwt) *AuthService {

	return &AuthService{uc: uc, jwtUtil: jwtUtil,
		accessTokenLifeSpan:  time.Duration(c.GetAccessTokenLifeSpan()) * time.Second,
		refreshTokenLifeSpan: time.Duration(c.GetRefreshTokenLifeSpan()) * time.Second,
	}
}

func (s *AuthService) PasswordLogin(ctx context.Context, in *auth.LoginRequest) (*auth.LoginReply, error) {
	userId, err := s.uc.Repo.CheckPasswordAndGetUserBaseInfo(ctx, in.Email, in.Password)

	if err != nil {
		return nil, err
	}

	accessToken, err := (*s.jwtUtil).EncodeJWTWithRS256(map[string]interface{}{
		"uid": userId,
	}, s.accessTokenLifeSpan)
	refreshToken, err := (*s.jwtUtil).EncodeJWTWithRS256(map[string]interface{}{
		"uid": userId,
	}, s.refreshTokenLifeSpan)

	return &auth.LoginReply{
		Code:    200,
		Message: "登录成功",
		Data: &auth.LoginReply_LoginReplyData{
			AccessToken:  accessToken,
			RefreshToken: refreshToken,
		}}, nil
}
