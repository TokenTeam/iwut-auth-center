package biz

import (
	"context"
)

type Oauth2Repo interface {
	SetCodeInfo(ctx context.Context, code string, codeInfo *CodeInfo) error
	GetCodeInfo(ctx context.Context, code string) (*CodeInfo, error)
	GetClientInfo(ctx context.Context, clientId string) (*ClientInfo, error)
	CheckGetCodeRequest(ctx context.Context, codeInfo *CodeInfo) (bool, error)
	EraseCodeInfo(ctx context.Context, code string) error
	InsertJTIToUserConsents(ctx context.Context, userId string, clientId string, jti string) error
	CheckJTIAllowed(ctx context.Context, userId string, clientId string, jti string) (bool, error)
	RevokeUserConsent(ctx context.Context, userId string, clientId string) error
	GetUserProfile(ctx context.Context, userId string, clientId string, scopes []string, storageKeys []string) (*Oauth2UserProfile, error)
	SetUserProfile(ctx context.Context, userId string, clientId string, storageKeyValues map[string]string) error
}

type Oauth2Usecase struct {
	Repo Oauth2Repo
}

func NewOauth2Usecase(repo Oauth2Repo) *Oauth2Usecase {
	return &Oauth2Usecase{Repo: repo}
}

type ClientInfo struct {
	ClientId      string   `json:"client_id"`
	ClientSecret  string   `json:"client_secret"`
	Version       string   `json:"version"`      // 应用版本
	RedirectUri   []string `json:"redirect_uri"` // 跳转地址
	BasicScope    []string `json:"basic_scope"`  // 必须权限
	ExtraScope    []string `json:"extra_scope"`  // 可选权限
	StorageKeys   []string `json:"storage_keys"` // 额外存储键
	DisplayName   string   `json:"display_name"` // 显示名称
	Name          string   `json:"name"`         // 仅允许字母、数字、下划线、中划线
	Describe      string   `json:"describe"`     // 应用描述
	Url           string   `json:"url"`          // 首次访问 url
	Icon          string   `json:"icon"`         // icon url
	Show          bool     `json:"show"`
	Admin         string   `json:"admin"`         // 拥有人
	Collaborators []string `json:"collaborators"` // 协作者
}

type CodeInfo struct {
	UserId              string `json:"user_id"`
	ClientId            string `json:"client_id"`
	ResponseType        string `json:"response_type"`
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
