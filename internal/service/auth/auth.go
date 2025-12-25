package auth

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"iwut-auth-center/api/auth_center/v1/auth"
	"iwut-auth-center/internal/biz"
	"iwut-auth-center/internal/biz/mail"
	"iwut-auth-center/internal/conf"
	"iwut-auth-center/internal/util"
	"math/big"
	"time"
)

type Service struct {
	auth.UnimplementedAuthServer
	authUsecase          *biz.AuthUsecase
	mailUsecase          *mail.Usecase
	jwtUtil              *util.JwtUtil
	accessTokenLifeSpan  time.Duration
	refreshTokenLifeSpan time.Duration
}

func NewAuthService(authUsecase *biz.AuthUsecase, mailUsecase *mail.Usecase, jwtUtil *util.JwtUtil, c *conf.Jwt) *Service {

	return &Service{authUsecase: authUsecase, mailUsecase: mailUsecase, jwtUtil: jwtUtil,
		accessTokenLifeSpan:  time.Duration(c.GetAccessTokenLifeSpan()) * time.Second,
		refreshTokenLifeSpan: time.Duration(c.GetRefreshTokenLifeSpan()) * time.Second,
	}
}

func (s *Service) PasswordLogin(ctx context.Context, in *auth.LoginRequest) (*auth.LoginReply, error) {
	userId, version, err := s.authUsecase.Repo.CheckPasswordWithEmailAndGetUserIdAndVersion(ctx, in.Email, in.Password)

	if err != nil {
		var re *biz.ReturnableError
		if errors.As(err, &re) {
			return &auth.LoginReply{
				Code:    re.Code,
				Message: re.Message,
			}, nil
		}
		traceId := util.RequestIDFrom(ctx)
		return &auth.LoginReply{
			Code:    500,
			Message: err.Error(),
			TraceId: &traceId,
		}, nil
	}
	err = s.authUsecase.Repo.AddOrUpdateUserVersion(ctx, userId, version, s.refreshTokenLifeSpan)
	if err != nil {
		traceId := util.RequestIDFrom(ctx)
		return &auth.LoginReply{
			Code:    500,
			Message: err.Error(),
			TraceId: &traceId,
		}, nil
	}
	accessToken, err := (*s.jwtUtil).EncodeJWTWithRS256(map[string]interface{}{
		"uid":     userId,
		"version": version,
	}, s.accessTokenLifeSpan)
	refreshToken, err := (*s.jwtUtil).EncodeJWTWithRS256(map[string]interface{}{
		"uid":     userId,
		"version": version,
	}, s.refreshTokenLifeSpan)

	return &auth.LoginReply{
		Code:    200,
		Message: "登录成功",
		Data: &auth.LoginReply_LoginReplyData{
			AccessToken:  accessToken,
			RefreshToken: refreshToken,
		}}, nil
}

func GenerateSecure6DigitCode() (string, error) {
	randNumber := big.NewInt(1000000) // 上限为 1_000_000（不包含）
	n, err := rand.Int(rand.Reader, randNumber)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%06d", n.Int64()), nil
}

func (s *Service) GetRegisterMail(ctx context.Context, in *auth.GetVerifyCodeRequest) (*auth.GetVerifyCodeReply, error) {
	captcha, err := GenerateSecure6DigitCode()
	if err != nil {
		traceId := util.RequestIDFrom(ctx)
		return &auth.GetVerifyCodeReply{
			Code:    500,
			Message: "生成验证码失败",
			TraceId: &traceId,
		}, nil
	}
	err = s.authUsecase.Repo.TryInsertRegisterCaptcha(ctx, in.Email, captcha, 10*time.Minute)
	if err != nil {
		var re *biz.ReturnableError
		if errors.As(err, &re) {
			return &auth.GetVerifyCodeReply{
				Code:    re.Code,
				Message: re.Message,
			}, nil
		}
		traceId := util.RequestIDFrom(ctx)
		return &auth.GetVerifyCodeReply{
			Code:    500,
			Message: "写入验证码失败",
			TraceId: &traceId,
		}, nil
	}
	err = s.mailUsecase.SendVerifyCodeMail(ctx, 10, captcha, []string{in.GetEmail()})
	if err != nil {
		traceId := util.RequestIDFrom(ctx)
		return &auth.GetVerifyCodeReply{
			Code:    500,
			Message: "发送邮件失败",
			TraceId: &traceId,
		}, nil
	}

	return &auth.GetVerifyCodeReply{
		Code:    200,
		Message: "获取验证码成功",
	}, nil
}

func (s *Service) Register(ctx context.Context, in *auth.RegisterRequest) (*auth.RegisterReply, error) {
	err := s.authUsecase.Repo.CheckCaptchaUsable(ctx, in.GetEmail(), in.GetVerifyCode(), 10*time.Minute)
	if err != nil {
		var re *biz.ReturnableError
		if errors.As(err, &re) {
			return &auth.RegisterReply{
				Code:    re.Code,
				Message: re.Message,
			}, nil
		}
		traceId := util.RequestIDFrom(ctx)
		return &auth.RegisterReply{
			Code:    500,
			Message: "验证验证码失败",
			TraceId: &traceId,
		}, nil
	}
	id, err := s.authUsecase.Repo.RegisterUser(ctx, in.GetEmail(), in.GetPassword())
	if err != nil {
		var re *biz.ReturnableError
		if errors.As(err, &re) {
			return &auth.RegisterReply{
				Code:    re.Code,
				Message: re.Message,
			}, nil
		}
		traceId := util.RequestIDFrom(ctx)
		return &auth.RegisterReply{
			Code:    500,
			Message: "注册用户失败",
			TraceId: &traceId,
		}, nil
	}

	return &auth.RegisterReply{
		Code:    200,
		Message: "注册成功",
		Data: &auth.RegisterReply_RegisterReplyData{
			UserId: id,
		},
	}, nil
}
