package biz

import (
	"context"
)

type Oauth2Repo interface {
	SetCodeInfo(ctx context.Context, code string, codeInfo *CodeInfo) error
	GetCodeInfo(ctx context.Context, code string) (*CodeInfo, error)
	CheckGetCodeRequest(ctx context.Context, codeInfo *CodeInfo) (bool, error)
	EraseCodeInfo(ctx context.Context, code string) error
	InsertJTIToUserConsents(ctx context.Context, userId string, clientId string, jti string) error
	RevokeUserConsent(ctx context.Context, userId string, clientId string) error
	GetUserOfficialProfile(ctx context.Context, userId string, clientId string, internalVersion int32, scopes []string) (map[string]any, error)
	GetUserProfile(ctx context.Context, userId string, clientId string, storageKeys []string) (map[string]*string, error)
	SetUserProfile(ctx context.Context, userId string, clientId string, storageKeyValues map[string]string) error
}

type Oauth2Usecase struct {
	Repo Oauth2Repo
}

func NewOauth2Usecase(repo Oauth2Repo) *Oauth2Usecase {
	return &Oauth2Usecase{Repo: repo}
}

type CodeInfo struct {
	UserId              string `json:"user_id"`
	ClientId            string `json:"client_id"`
	ResponseType        string `json:"response_type"`
	InternalVersion     int32  `json:"internal_version"`
	Scope               string `json:"scope"`
	RedirectUri         string `json:"redirect_uri"`
	Nonce               string `json:"nonce"`
	CodeChallenge       string `json:"code_challenge"`
	CodeChallengeMethod string `json:"code_challenge_method"`
	CreatedAt           int64  `json:"created_at"`
}

type Oauth2UserProfile struct {
	OfficialAttrs   map[string]any     `json:"official_attrs"`
	StorageKeyValue map[string]*string `json:"storage_key_value"`
}
