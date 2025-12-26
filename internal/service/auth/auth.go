package auth

import (
	"context"
	"crypto/rand"
	"fmt"
	"iwut-auth-center/api/auth_center/v1/auth"
	"iwut-auth-center/internal/biz"
	"iwut-auth-center/internal/biz/mail"
	"iwut-auth-center/internal/conf"
	"iwut-auth-center/internal/util"
	"math/big"
	"strings"
	"time"

	"github.com/go-kratos/kratos/v2/errors"
	"github.com/go-kratos/kratos/v2/transport"
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
	reqId := util.RequestIDFrom(ctx)
	userId, version, err := s.authUsecase.Repo.CheckPasswordWithEmailAndGetUserIdAndVersion(ctx, in.Email, in.Password)

	if err != nil {
		if _, ok := interface{}(err).(interface {
			GetMetadata() map[string]string
		}); ok {
			return nil, err
		}
		err := errors.InternalServer("", err.Error())
		err.Metadata["traceId"] = reqId
		return nil, err
	}
	err = s.authUsecase.Repo.AddOrUpdateUserVersion(ctx, userId, version, s.refreshTokenLifeSpan)
	if err != nil {
		err := errors.InternalServer("", err.Error())
		err.Metadata["traceId"] = reqId
		return nil, err
	}
	accessToken, err := (*s.jwtUtil).EncodeJWTWithRS256(map[string]interface{}{
		"uid":     userId,
		"type":    "access",
		"version": version,
	}, s.accessTokenLifeSpan)
	if err != nil {
		err := errors.InternalServer("", err.Error())
		err.Metadata["traceId"] = reqId
		return nil, err
	}
	refreshToken, err := (*s.jwtUtil).EncodeJWTWithRS256(map[string]interface{}{
		"uid":     userId,
		"type":    "refresh",
		"version": version,
	}, s.refreshTokenLifeSpan)
	if err != nil {
		err := errors.InternalServer("", err.Error())
		err.Metadata["traceId"] = reqId
		return nil, err
	}
	return &auth.LoginReply{
		Code:    200,
		Message: "Login successful",
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
	reqId := util.RequestIDFrom(ctx)
	captcha, err := GenerateSecure6DigitCode()
	if err != nil {
		traceId := util.RequestIDFrom(ctx)
		return &auth.GetVerifyCodeReply{
			Code:    500,
			Message: "failed to generate verify code",
			TraceId: &traceId,
		}, nil
	}
	err = s.authUsecase.Repo.TryInsertRegisterCaptcha(ctx, in.Email, captcha, 10*time.Minute)
	if err != nil {
		if _, ok := interface{}(err).(interface {
			GetMetadata() map[string]string
		}); ok {
			return nil, err
		}
		err := errors.InternalServer("", "failed to insert register captcha: "+err.Error())
		err.Metadata["traceId"] = reqId
		return nil, err
	}
	err = s.mailUsecase.SendVerifyCodeMail(ctx, 10, captcha, []string{in.GetEmail()})
	if err != nil {
		err := errors.InternalServer("", "failed to send verify code mail: "+err.Error())
		err.Metadata["traceId"] = reqId
		return nil, err
	}

	return &auth.GetVerifyCodeReply{
		Code:    200,
		Message: "send verify code mail successful",
	}, nil
}

func (s *Service) Register(ctx context.Context, in *auth.RegisterRequest) (*auth.RegisterReply, error) {
	reqId := util.RequestIDFrom(ctx)
	err := s.authUsecase.Repo.CheckCaptchaUsable(ctx, in.GetEmail(), in.GetVerifyCode(), 10*time.Minute)
	if err != nil {
		if _, ok := interface{}(err).(interface {
			GetMetadata() map[string]string
		}); ok {
			return nil, err
		}
		err := errors.InternalServer("", "verify code is not usable: "+err.Error())
		err.Metadata["traceId"] = reqId
		return nil, err
	}
	id, err := s.authUsecase.Repo.RegisterUser(ctx, in.GetEmail(), in.GetPassword())

	if err != nil {
		if _, ok := interface{}(err).(interface {
			GetMetadata() map[string]string
		}); ok {
			return nil, err
		}
		err := errors.InternalServer("", "failed to register user: "+err.Error())
		err.Metadata["traceId"] = reqId
		return nil, err
	}

	return &auth.RegisterReply{
		Code:    200,
		Message: "Register successful",
		Data: &auth.RegisterReply_RegisterReplyData{
			UserId: id,
		},
	}, nil
}

func (s *Service) RefreshToken(ctx context.Context, in *auth.RefreshTokenRequest) (*auth.RefreshTokenReply, error) {
	reqId := util.RequestIDFrom(ctx)
	token := ""
	if token = in.GetRefreshToken(); strings.TrimSpace(token) == "" {

		tr, ok := transport.FromServerContext(ctx)
		if !ok {
			err := errors.InternalServer("", "transport not found, cannot get refresh token")
			err.Metadata["traceId"] = reqId
			return nil, err
		}

		header := tr.RequestHeader()
		// Try Authorization header first

		h := header.Get("Cookie")
		if h == "" {
			h = header.Get("cookie")
		}
		parts := strings.Split(h, ";")
		for _, part := range parts {
			part = strings.TrimSpace(part)
			if strings.HasPrefix(part, "refresh_token=") {
				token = strings.TrimPrefix(part, "refresh_token=")
				break
			}
		}
	}
	if strings.TrimSpace(token) == "" {
		return nil, errors.BadRequest("", "Refresh token is required")
	}

	result, err := s.jwtUtil.DecodeJWTWithRS256(token)
	if err != nil {
		return nil, errors.BadRequest("", err.Error())
	}
	if s.jwtUtil.GetJwtTypeFromClaims(result) != util.OfficialJwt {
		return nil, errors.BadRequest("", "Only official tokens are supported by this endpoint")
	}
	baseClaims, err := s.jwtUtil.ToBaseAuthClaims(result)
	if err != nil {
		return nil, errors.BadRequest("", err.Error())
	}
	if baseClaims.Type != "refresh" {
		return nil, errors.BadRequest("", "Invalid token type")
	}
	version, err := s.authUsecase.Repo.GetUserVersion(ctx,
		baseClaims.Uid,
		time.Duration(baseClaims.Exp-time.Now().Unix())*time.Second)
	if err != nil {
		return nil, errors.BadRequest("", err.Error())
	}
	if baseClaims.Version != version {
		return nil, errors.BadRequest("", "Token has been revoked")
	}
	accessToken, err := s.jwtUtil.EncodeJWTWithRS256(map[string]interface{}{
		"uid":     baseClaims.Uid,
		"type":    "access",
		"version": version,
	}, s.accessTokenLifeSpan)
	if err != nil {
		err := errors.InternalServer("", err.Error())
		err.Metadata["traceId"] = reqId
		return nil, err
	}
	refreshToken, err := s.jwtUtil.EncodeJWTWithRS256(map[string]interface{}{
		"uid":     baseClaims.Uid,
		"type":    "refresh",
		"version": version,
	}, s.refreshTokenLifeSpan)
	if err != nil {
		err := errors.InternalServer("", err.Error())
		err.Metadata["traceId"] = reqId
		return nil, err
	}
	return &auth.RefreshTokenReply{
		Code:    200,
		Message: "Refresh token successful",
		Data: &auth.RefreshTokenReply_RefreshTokenReplyData{
			AccessToken:  accessToken,
			RefreshToken: refreshToken,
		},
	}, nil
}
