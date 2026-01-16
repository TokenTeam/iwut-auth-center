package service

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"iwut-auth-center/api/auth_center/v1/oauth2"
	"iwut-auth-center/internal/biz"
	"iwut-auth-center/internal/conf"
	"iwut-auth-center/internal/util"
	"time"

	"github.com/go-kratos/kratos/v2/errors"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/structpb"
)

type Oauth2Service struct {
	oauth2.UnimplementedOAuth2Server
	oauth2Usecase        *biz.Oauth2Usecase
	auditUsecase         *biz.AuditUsecase
	appUsecase           *biz.AppUsecase
	jwtUtil              *util.JwtUtil
	accessTokenLifeSpan  time.Duration
	refreshTokenLifeSpan time.Duration
}

// NewOauth2Service constructs an Oauth2Service wiring usecases and JWT util.
func NewOauth2Service(oauth2Usecase *biz.Oauth2Usecase, auditUsecase *biz.AuditUsecase, appUsecase *biz.AppUsecase, jwtUtil *util.JwtUtil, c *conf.Jwt) *Oauth2Service {
	return &Oauth2Service{
		oauth2Usecase:        oauth2Usecase,
		auditUsecase:         auditUsecase,
		appUsecase:           appUsecase,
		jwtUtil:              jwtUtil,
		accessTokenLifeSpan:  time.Duration(c.GetAccessTokenLifeSpan()) * time.Second,
		refreshTokenLifeSpan: time.Duration(c.GetRefreshTokenLifeSpan()) * time.Second,
	}
}

// Authorize performs OAuth2 authorization request validation and issues an authorization code.
// - Validates incoming parameters (scope/response_type/PKCE arguments) and user permission via oauth2 usecase,
// - Generates an authorization code, caches its associated metadata, and returns a redirect URI containing the code.
func (s *Oauth2Service) Authorize(ctx context.Context, in *oauth2.AuthorizeRequest) (*oauth2.AuthorizeReply, error) {
	successProcess, errorProcess := util.GetProcesses[*oauth2.AuthorizeReply]("Authorize", GetAuditInsertFunc(*s.auditUsecase))

	claim, err := s.jwtUtil.GetBaseAuthClaims(ctx)
	if err != nil {
		return nil, errorProcess(ctx, err)
	}
	nonce := ""
	codeChallenge := ""
	codeChallengeMethod := ""
	if in.Nonce != nil {
		nonce = *in.Nonce
	}
	if in.CodeChallenge != nil {
		codeChallenge = *in.CodeChallenge
	}
	if in.CodeChallengeMethod != nil {
		if *in.CodeChallengeMethod != "S256" {
			return nil, errors.BadRequest("400", "unsupported code_challenge_method, only S256 is supported")
		}
		if codeChallenge == "" {
			return nil, errors.BadRequest("400", "code_challenge_method is provided, code_challenge must be provided too")
		}
		codeChallengeMethod = *in.CodeChallengeMethod
	}
	codeInfo := &biz.CodeInfo{
		UserId:              claim.Uid,
		ClientId:            in.ClientId,
		ResponseType:        in.ResponseType,
		Scope:               in.Scope,
		RedirectUri:         in.RedirectUri,
		Nonce:               nonce,
		CodeChallenge:       codeChallenge,
		CodeChallengeMethod: codeChallengeMethod,
		CreatedAt:           time.Now().Unix(),
	}

	if ok, err := s.oauth2Usecase.Repo.CheckGetCodeRequest(ctx, codeInfo); !ok {
		if err != nil {
			return nil, errorProcess(ctx, err)
		}
		return nil, errors.InternalServer("500", "check get token request failed with unknown reason")
	}
	code, err := util.GenerateString(32)
	if err != nil {
		return nil, errorProcess(ctx, err)
	}
	if err = s.oauth2Usecase.Repo.SetCodeInfo(ctx, code, codeInfo); err != nil {
		return nil, errorProcess(ctx, err)
	}
	url, err := util.BuildRedirectURL(in.RedirectUri, map[string]string{
		"code":  code,
		"state": in.State,
	})
	if err != nil {
		return nil, errorProcess(ctx, err)
	}

	return successProcess(ctx, func(reqId string) *oauth2.AuthorizeReply {
		return &oauth2.AuthorizeReply{
			Code:    200,
			Message: "check success",
			Data: &oauth2.AuthorizeReply_AuthorizeReplyData{
				RedirectUri: url,
			},
			TraceId: &reqId,
		}
	}), nil
}

func stringPtr(s string) *string {
	return &s
}

// GetToken exchanges an authorization code for access and refresh tokens.
// - Validates grant_type, client authentication and PKCE when applicable,
// - Generates JTI, issues tokens (access/refresh), records the JTI in user consents and invalidates the used code.
// - Returns OAuth2-compliant error structures when validation fails.
func (s *Oauth2Service) GetToken(ctx context.Context, in *oauth2.GetTokenRequest) (*oauth2.GetTokenReply, error) {
	if in.GetGrantType() != "authorization_code" {
		return &oauth2.GetTokenReply{
			Error:            stringPtr("invalid_request"),
			ErrorDescription: stringPtr("unsupported grant_type, only authorization_code is supported"),
		}, nil
	}

	codeInfo, err := s.oauth2Usecase.Repo.GetCodeInfo(ctx, in.GetCode())
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	if codeInfo == nil {
		return &oauth2.GetTokenReply{
			Error:            stringPtr("invalid_grant"),
			ErrorDescription: stringPtr("authorization code not found"),
		}, nil
	}
	if codeInfo.ClientId != in.GetClientId() {
		return &oauth2.GetTokenReply{
			Error:            stringPtr("invalid_grant"),
			ErrorDescription: stringPtr("authorization code client_id mismatch"),
		}, nil
	}

	clientInfo, err := s.appUsecase.Repo.GetClientInfo(ctx, codeInfo.ClientId)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	if clientInfo == nil || clientInfo.ClientSecret != in.GetClientSecret() {
		return &oauth2.GetTokenReply{
			Error:            stringPtr("invalid_client"),
			ErrorDescription: stringPtr("client authentication failed"),
		}, nil
	}

	// PKCE S256 verification
	if codeInfo.CodeChallengeMethod == "S256" {
		codeVerifier := in.GetCodeVerifier()
		if codeVerifier == "" {
			return &oauth2.GetTokenReply{
				Error:            stringPtr("invalid_request"),
				ErrorDescription: stringPtr("code_verifier is required when code_challenge_method is S256"),
			}, nil
		}

		h := sha256.Sum256([]byte(codeVerifier))
		expectedChallenge := base64.RawURLEncoding.EncodeToString(h[:])
		if expectedChallenge != codeInfo.CodeChallenge {
			return &oauth2.GetTokenReply{
				Error:            stringPtr("invalid_grant"),
				ErrorDescription: stringPtr("PKCE verification failed: code_verifier does not match code_challenge"),
			}, nil
		}
	}
	jti, err := util.GenerateString(32)
	if err != nil {
		return &oauth2.GetTokenReply{
			Error:            stringPtr("internal_error"),
			ErrorDescription: stringPtr("failed to generate jti"),
		}, nil
	}
	tokenLifeSpan := []time.Duration{s.accessTokenLifeSpan, s.refreshTokenLifeSpan}
	token := make([]string, 2)
	for i, tokenType := range []string{"access", "refresh"} {
		claims := map[string]interface{}{
			"jti":   jti,
			"uid":   codeInfo.UserId,
			"scope": codeInfo.Scope,
			"azp":   codeInfo.ClientId,
			"aud":   []string{codeInfo.ClientId},
			"type":  tokenType,
		}
		// 只有在 nonce 不为空时才写入 JWT
		if codeInfo.Nonce != "" {
			claims["nonce"] = codeInfo.Nonce
		}

		generatedToken, err := s.jwtUtil.EncodeJWTWithRS256(claims, tokenLifeSpan[i])
		if err != nil {
			return &oauth2.GetTokenReply{
				Error:            stringPtr("internal_error"),
				ErrorDescription: stringPtr(fmt.Sprintf("failed to generate %s token", tokenType)),
			}, nil
		}
		token[i] = generatedToken
	}
	err = s.oauth2Usecase.Repo.EraseCodeInfo(ctx, in.GetCode())
	if err != nil {
		return &oauth2.GetTokenReply{
			Error:            stringPtr("internal_error"),
			ErrorDescription: stringPtr("failed to erase used authorization code"),
		}, nil
	}
	err = s.oauth2Usecase.Repo.InsertJTIToUserConsents(ctx, codeInfo.UserId, clientInfo.ClientId, jti)
	if err != nil {
		return &oauth2.GetTokenReply{
			Error:            stringPtr("internal_error"),
			ErrorDescription: stringPtr("failed to record token jti in user consents"),
		}, nil
	}
	expiresIn := int32(s.accessTokenLifeSpan.Seconds())
	return &oauth2.GetTokenReply{
		AccessToken:  stringPtr(token[0]),
		IdToken:      stringPtr(token[0]),
		RefreshToken: stringPtr(token[1]),
		TokenType:    stringPtr("Bearer"),
		ExpiresIn:    &expiresIn,
		Scope:        stringPtr(codeInfo.Scope),
	}, nil
}

// RevokeAuthorization revokes the authenticated user's consent for a client.
// - Validates caller via JWT and delegates the revoke operation to oauth2 usecase repo.
// - Returns RPC-level success or propagated errors and records audit.
func (s *Oauth2Service) RevokeAuthorization(ctx context.Context, in *oauth2.RevokeAuthorizationRequest) (*oauth2.RevokeAuthorizationReply, error) {
	successProcess, errorProcess := util.GetProcesses[*oauth2.RevokeAuthorizationReply]("RevokeAuthorization", GetAuditInsertFunc(*s.auditUsecase))
	claim, err := s.jwtUtil.GetBaseAuthClaims(ctx)
	if err != nil {
		return nil, errorProcess(ctx, err)
	}

	err = s.oauth2Usecase.Repo.RevokeUserConsent(ctx, claim.Uid, in.GetClientId())
	if err != nil {
		return nil, errorProcess(ctx, err)
	}
	return successProcess(ctx, func(reqId string) *oauth2.RevokeAuthorizationReply {
		return &oauth2.RevokeAuthorizationReply{
			Code:    200,
			Message: "revoke success",
			TraceId: &reqId,
		}
	}), nil
}

// GetUserProfile returns the profile visible to the requesting OAuth client (azp from JWT).
// - Extracts OAuth claims, delegates profile assembly to oauth2 usecase repo, converts maps to structpb and returns them.
func (s *Oauth2Service) GetUserProfile(ctx context.Context, in *oauth2.GetUserProfileRequest) (*oauth2.GetUserProfileReply, error) {
	successProcess, errorProcess := util.GetProcesses[*oauth2.GetUserProfileReply]("GetUserProfile", GetAuditInsertFunc(*s.auditUsecase))
	claim, err := s.jwtUtil.GetOAuthClaims(ctx)
	if err != nil {
		return nil, errorProcess(ctx, err)
	}
	userProfile, err := s.oauth2Usecase.Repo.GetUserProfile(ctx, claim.Uid, claim.Azp, in.GetScopeKeys(), in.GetStorageKeys())
	if err != nil {
		return nil, errorProcess(ctx, err)
	}
	officialAttrs, err := structpb.NewStruct(userProfile.OfficialAttrs)
	if err != nil {
		return nil, errorProcess(ctx, err)
	}
	storage, err := util.StringMapToStructpbValueMap(userProfile.StorageKeyValue)
	if err != nil {
		return nil, errorProcess(ctx, err)
	}

	return successProcess(ctx, func(reqId string) *oauth2.GetUserProfileReply {
		return &oauth2.GetUserProfileReply{
			Code:    200,
			Message: "get user profile success",
			Data: &oauth2.GetUserProfileReply_UserProfileData{
				Scope:   officialAttrs,
				Storage: storage,
			},
			TraceId: &reqId,
		}
	}), nil
}

// SetUserStorage updates namespaced storage keys for the authenticated OAuth client (azp).
// - Parses incoming structpb to map[string]string and delegates persistence to oauth2 usecase repo.
func (s *Oauth2Service) SetUserStorage(ctx context.Context, in *structpb.Struct) (*oauth2.SetUserStorageReply, error) {
	successProcess, errorProcess := util.GetProcesses[*oauth2.SetUserStorageReply]("SetUserStorage", GetAuditInsertFunc(*s.auditUsecase))
	claim, err := s.jwtUtil.GetOAuthClaims(ctx)
	if err != nil {
		return nil, errorProcess(ctx, err)
	}
	inParsed, err := util.StructToStringMap(in)
	if err != nil {
		return nil, errorProcess(ctx, err)
	}
	err = s.oauth2Usecase.Repo.SetUserProfile(ctx, claim.Uid, claim.Azp, inParsed)
	if err != nil {
		return nil, errorProcess(ctx, err)
	}
	return successProcess(ctx, func(reqId string) *oauth2.SetUserStorageReply {
		return &oauth2.SetUserStorageReply{
			Code:    200,
			Message: "set user storage success",
			TraceId: &reqId,
		}
	}), nil
}
