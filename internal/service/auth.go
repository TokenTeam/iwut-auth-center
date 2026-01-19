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
	frontendUrl          string
}

// NewAuthService constructs an AuthService.
// It wires usecases, mail sender, audit usecase and JWT util and configures token lifetimes.
func NewAuthService(authUsecase *biz.AuthUsecase, mailUsecase *mail.Usecase, auditUsecase *biz.AuditUsecase, jwtUtil *util.JwtUtil, c *conf.Jwt, sc *conf.Server) *AuthService {
	return &AuthService{authUsecase: authUsecase, mailUsecase: mailUsecase, auditUsecase: auditUsecase, jwtUtil: jwtUtil,
		accessTokenLifeSpan:  time.Duration(c.GetAccessTokenLifeSpan()) * time.Second,
		refreshTokenLifeSpan: time.Duration(c.GetRefreshTokenLifeSpan()) * time.Second,
		frontendUrl:          strings.TrimSuffix(sc.GetFrontendUrl(), "/"),
	}
}

// PasswordLogin handles a password-based login request.
// - Verifies credentials via the auth usecase, issues access and refresh JWTs on success,
// - Updates cached user version used to validate refresh tokens,
// - Records audit information via the audit helper provided by util.GetProcesses.
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

// GenerateSecure6DigitCode returns a cryptographically secure 6-digit numeric code as string.
// Used for generating email verification codes.
func GenerateSecure6DigitCode() (string, error) {
	randNumber := big.NewInt(1000000) // 上限为 1_000_000（不包含）
	n, err := rand.Int(rand.Reader, randNumber)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%06d", n.Int64()), nil
}

// GetRegisterMail generates a verification code, stores rate-limited captcha via auth usecase
// and sends the code via mail usecase. It returns RPC-level success/failure with auditing.
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

// GetResetUrlMail handles password reset URL generation and emailing.
// - Generates a secure reset URL with a verification code,
// - Stores the code via auth usecase for later validation,
// - Sends the reset URL via mail usecase,
// - Returns RPC-level success/failure with auditing.
func (s *AuthService) GetResetUrlMail(ctx context.Context, in *auth.GetResetUrlRequest) (*auth.GetResetUrlReply, error) {
	successProcess, errorProcess := util.GetProcesses[*auth.GetResetUrlReply]("GetResetUrlMail", GetAuditInsertFunc(*s.auditUsecase))
	captcha, err := GenerateSecure6DigitCode()
	if err != nil {
		return nil, errorProcess(ctx, errors.InternalServer("500", "failed to generate verify code"))
	}
	err = s.authUsecase.Repo.TryInsertResetPasswordCaptcha(ctx, in.Email, captcha, 10*time.Minute)
	if err != nil {
		return nil, errorProcess(ctx, err)
	}
	// resetUrl := fmt.Sprintf("%s/reset-password?email=%s&code=%s", i??(), in.GetEmail(), captcha)
	resetUrl, err := util.BuildRedirectURL(s.frontendUrl+"/reset-password", map[string]string{
		"email": in.GetEmail(),
		"code":  captcha,
	})
	err = s.mailUsecase.SendResetPasswordMail(ctx, 10, resetUrl, []string{in.GetEmail()})
	if err != nil {
		return nil, errorProcess(ctx, err)
	}

	return successProcess(ctx, func(reqId string) *auth.GetResetUrlReply {
		return &auth.GetResetUrlReply{
			Code:    200,
			Message: "send reset url mail successful",
			TraceId: reqId,
		}
	}, util.Audit{Message: stringPtr(in.GetEmail())}), nil
}

// Register handles user registration:
// - Validates the provided verification code via auth usecase,
// - Creates a new user record via auth usecase,
// - Returns created user id on success and records audit.
func (s *AuthService) Register(ctx context.Context, in *auth.RegisterRequest) (*auth.RegisterReply, error) {
	successProcess, errorProcess := util.GetProcesses[*auth.RegisterReply]("Register", GetAuditInsertFunc(*s.auditUsecase))
	err := s.authUsecase.Repo.CheckRegisterCaptchaUsable(ctx, in.GetEmail(), in.GetVerifyCode(), 10*time.Minute)
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

// ResetPassword handles password reset requests:
// - Validates the provided verification code via auth usecase,
// - Updates the user's password via auth usecase,
// - Returns RPC-level success/failure with auditing.
func (s *AuthService) ResetPassword(ctx context.Context, in *auth.ResetPasswordRequest) (*auth.ResetPasswordReply, error) {
	successProcess, errorProcess := util.GetProcesses[*auth.ResetPasswordReply]("ResetPassword", GetAuditInsertFunc(*s.auditUsecase))
	err := s.authUsecase.Repo.CheckResetPasswordCaptchaUsable(ctx, in.GetEmail(), in.GetVerifyCode(), 10*time.Minute)
	if err != nil {
		return nil, errorProcess(ctx, err)
	}
	err = s.authUsecase.Repo.ResetPassword(ctx, in.GetEmail(), in.GetPassword())
	if err != nil {
		return nil, errorProcess(ctx, err)
	}

	return successProcess(ctx, func(reqId string) *auth.ResetPasswordReply {
		return &auth.ResetPasswordReply{
			Code:    200,
			Message: "Reset password successful",
			TraceId: reqId,
		}
	}, util.Audit{Message: stringPtr(in.GetEmail())}), nil

}

// RefreshToken handles a refresh token exchange:
// - Accepts a refresh token from request body or cookie, decodes and validates the JWT,
// - Verifies token type and version against cached user version via auth usecase,
// - Issues new access and refresh tokens when valid.
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
