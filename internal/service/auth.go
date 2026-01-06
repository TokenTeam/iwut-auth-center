package service

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

type AuthService struct {
	auth.UnimplementedAuthServer
	authUsecase          *biz.AuthUsecase
	mailUsecase          *mail.Usecase
	auditUsecase         *biz.AuditUsecase
	jwtUtil              *util.JwtUtil
	accessTokenLifeSpan  time.Duration
	refreshTokenLifeSpan time.Duration
}

func NewAuthService(authUsecase *biz.AuthUsecase, mailUsecase *mail.Usecase, auditUsecase *biz.AuditUsecase, jwtUtil *util.JwtUtil, c *conf.Jwt) *AuthService {

	return &AuthService{authUsecase: authUsecase, mailUsecase: mailUsecase, auditUsecase: auditUsecase, jwtUtil: jwtUtil,
		accessTokenLifeSpan:  time.Duration(c.GetAccessTokenLifeSpan()) * time.Second,
		refreshTokenLifeSpan: time.Duration(c.GetRefreshTokenLifeSpan()) * time.Second,
	}
}

func (s *AuthService) PasswordLogin(ctx context.Context, in *auth.LoginRequest) (*auth.LoginReply, error) {

	successProcess, errorProcess := util.GetProcesses[*auth.LoginReply]("PasswordLogin", GetAuditInsertFunc(*s.auditUsecase))
	userId, version, err := s.authUsecase.Repo.CheckPasswordWithEmailAndGetUserIdAndVersion(ctx, in.Email, in.Password)

	if err != nil {
		return nil, errorProcess(ctx, err, util.Audit{UserID: &userId})
	}
	err = s.authUsecase.Repo.AddOrUpdateUserVersion(ctx, userId, version, s.refreshTokenLifeSpan)
	if err != nil {
		return nil, errorProcess(ctx, err, util.Audit{UserID: &userId})
	}
	accessToken, err := (*s.jwtUtil).EncodeJWTWithRS256(map[string]interface{}{
		"uid":     userId,
		"type":    "access",
		"version": version,
	}, s.accessTokenLifeSpan)
	if err != nil {
		return nil, errorProcess(ctx, err, util.Audit{UserID: &userId})
	}
	refreshToken, err := (*s.jwtUtil).EncodeJWTWithRS256(map[string]interface{}{
		"uid":     userId,
		"type":    "refresh",
		"version": version,
	}, s.refreshTokenLifeSpan)
	if err != nil {
		return nil, errorProcess(ctx, err, util.Audit{UserID: &userId})
	}

	return successProcess(ctx, func(reqId string) *auth.LoginReply {
		return &auth.LoginReply{
			Code:    200,
			Message: "Login successful",
			Data: &auth.LoginReply_LoginReplyData{
				AccessToken:  accessToken,
				RefreshToken: refreshToken,
			},
			TraceId: reqId,
		}
	}, util.Audit{UserID: &userId}), nil
}

func GenerateSecure6DigitCode() (string, error) {
	randNumber := big.NewInt(1000000) // 上限为 1_000_000（不包含）
	n, err := rand.Int(rand.Reader, randNumber)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%06d", n.Int64()), nil
}

func (s *AuthService) GetRegisterMail(ctx context.Context, in *auth.GetVerifyCodeRequest) (*auth.GetVerifyCodeReply, error) {
	successProcess, errorProcess := util.GetProcesses[*auth.GetVerifyCodeReply]("GetRegisterMail", GetAuditInsertFunc(*s.auditUsecase))
	captcha, err := GenerateSecure6DigitCode()
	if err != nil {
		return nil, errorProcess(ctx, errors.InternalServer("500", "failed to generate verify code"))
	}
	err = s.authUsecase.Repo.TryInsertRegisterCaptcha(ctx, in.Email, captcha, 10*time.Minute)
	if err != nil {
		return nil, errorProcess(ctx, err)
	}
	err = s.mailUsecase.SendVerifyCodeMail(ctx, 10, captcha, []string{in.GetEmail()})
	if err != nil {
		return nil, errorProcess(ctx, err)
	}

	return successProcess(ctx, func(reqId string) *auth.GetVerifyCodeReply {
		return &auth.GetVerifyCodeReply{
			Code:    200,
			Message: "send verify code mail successful",
			TraceId: reqId,
		}
	}, util.Audit{Message: stringPtr(in.GetEmail())}), nil
}

func (s *AuthService) Register(ctx context.Context, in *auth.RegisterRequest) (*auth.RegisterReply, error) {
	successProcess, errorProcess := util.GetProcesses[*auth.RegisterReply]("Register", GetAuditInsertFunc(*s.auditUsecase))
	err := s.authUsecase.Repo.CheckCaptchaUsable(ctx, in.GetEmail(), in.GetVerifyCode(), 10*time.Minute)
	if err != nil {
		return nil, errorProcess(ctx, err)
	}
	id, err := s.authUsecase.Repo.RegisterUser(ctx, in.GetEmail(), in.GetPassword())

	if err != nil {
		return nil, errorProcess(ctx, err)
	}

	return successProcess(ctx, func(reqId string) *auth.RegisterReply {
		return &auth.RegisterReply{
			Code:    200,
			Message: "Register successful",
			Data: &auth.RegisterReply_RegisterReplyData{
				UserId: id,
			},
			TraceId: reqId,
		}
	}, util.Audit{UserID: &id}), nil
}

func (s *AuthService) RefreshToken(ctx context.Context, in *auth.RefreshTokenRequest) (*auth.RefreshTokenReply, error) {
	// Specify the concrete type parameter so the generic helper returns the correct function type
	successProcess, errorProcess := util.GetProcesses[*auth.RefreshTokenReply]("RefreshToken", GetAuditInsertFunc(*s.auditUsecase))
	token := ""
	if token = in.GetRefreshToken(); strings.TrimSpace(token) == "" {

		tr, ok := transport.FromServerContext(ctx)
		if !ok {
			return nil, errorProcess(ctx, errors.InternalServer("", "transport not found, cannot get refresh token"))
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
		return nil, errorProcess(ctx, errors.BadRequest("400", "Refresh token is required"))
	}

	result, err := s.jwtUtil.DecodeJWTWithRS256(token)
	if err != nil {
		return nil, errorProcess(ctx, errors.BadRequest("400", err.Error()))
	}
	if s.jwtUtil.GetJwtTypeFromClaims(result) != util.OfficialJwt {
		return nil, errorProcess(ctx, errors.BadRequest("400", "Only official tokens are supported by this endpoint"))
	}
	baseClaims, err := s.jwtUtil.ToBaseAuthClaims(result)
	if err != nil {
		return nil, errorProcess(ctx, errors.BadRequest("400", err.Error()))
	}
	if baseClaims.Type != "refresh" {
		return nil, errorProcess(ctx, errors.BadRequest("400", "Invalid token type"))
	}
	version, err := s.authUsecase.Repo.GetUserVersion(ctx,
		baseClaims.Uid,
		time.Duration(baseClaims.Exp-time.Now().Unix())*time.Second)
	if err != nil {
		return nil, errorProcess(ctx, errors.BadRequest("400", err.Error()))
	}
	if baseClaims.Version != version {
		return nil, errorProcess(ctx, errors.BadRequest("400", "Token has been revoked"))
	}
	accessToken, err := s.jwtUtil.EncodeJWTWithRS256(map[string]interface{}{
		"uid":     baseClaims.Uid,
		"type":    "access",
		"version": version,
	}, s.accessTokenLifeSpan)
	if err != nil {
		return nil, errorProcess(ctx, err)
	}
	refreshToken, err := s.jwtUtil.EncodeJWTWithRS256(map[string]interface{}{
		"uid":     baseClaims.Uid,
		"type":    "refresh",
		"version": version,
	}, s.refreshTokenLifeSpan)
	if err != nil {
		return nil, errorProcess(ctx, err)
	}
	return successProcess(ctx, func(reqId string) *auth.RefreshTokenReply {
		return &auth.RefreshTokenReply{
			Code:    200,
			Message: "Refresh token successful",
			Data: &auth.RefreshTokenReply_RefreshTokenReplyData{
				AccessToken:  accessToken,
				RefreshToken: refreshToken,
			},
			TraceId: reqId,
		}
	}, util.Audit{UserID: &baseClaims.Uid}), nil
}
