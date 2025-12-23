package auth

import (
	"context"
	"iwut-auth-center/api/auth_center/v1/auth"
	"iwut-auth-center/internal/biz"
	"iwut-auth-center/internal/biz/mail"
	"iwut-auth-center/internal/conf"
	"iwut-auth-center/internal/util"
	"time"
)

type AuthService struct {
	auth.UnimplementedAuthServer
	authUsecase          *biz.AuthUsecase
	mailUsecase          *mail.Usecase
	jwtUtil              *util.JwtUtil
	accessTokenLifeSpan  time.Duration
	refreshTokenLifeSpan time.Duration
}

func NewAuthService(uc *biz.AuthUsecase, mailUsecase *mail.Usecase, jwtUtil *util.JwtUtil, c *conf.Jwt) *AuthService {

	return &AuthService{authUsecase: uc, mailUsecase: mailUsecase, jwtUtil: jwtUtil,
		accessTokenLifeSpan:  time.Duration(c.GetAccessTokenLifeSpan()) * time.Second,
		refreshTokenLifeSpan: time.Duration(c.GetRefreshTokenLifeSpan()) * time.Second,
	}
}

func (s *AuthService) PasswordLogin(ctx context.Context, in *auth.LoginRequest) (*auth.LoginReply, error) {
	userId, err := s.authUsecase.Repo.CheckPasswordAndGetUserBaseInfo(ctx, in.Email, in.Password)

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

func (s *AuthService) GetRegisterMail(ctx context.Context, in *auth.GetVerifyCodeRequest) (*auth.GetVerifyCodeReply, error) {

	return &auth.GetVerifyCodeReply{
		Code:    200,
		Message: "获取验证码成功",
	}, nil
}

func (s *AuthService) Register(ctx context.Context, in *auth.RegisterRequest) (*auth.RegisterReply, error) {

	err := s.mailUsecase.SendVerifyCodeMail(10, "984965", []string{"li_chx@qq.com"})

	if err != nil {
		return &auth.RegisterReply{
			Code:    500,
			Message: "注册失败，发送邮件失败",
		}, nil
	}
	return &auth.RegisterReply{
		Code:    200,
		Message: "注册成功",
	}, nil
}
