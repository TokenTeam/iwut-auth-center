package biz

import "context"

type AppRepo interface {
	GetClientInfo(ctx context.Context, clientId string) (*ClientInfo, error)
}

type AppUsecase struct {
	Repo AppRepo
}

type ClientInfo struct {
	ClientId      string   `json:"client_id"`
	ClientSecret  string   `json:"client_secret"`
	Version       string   `json:"version"`        // 应用版本
	RedirectUri   []string `json:"redirect_uri"`   // 跳转地址
	BasicScope    []string `json:"basic_scope"`    // 必须权限
	OptionalScope []string `json:"optional_scope"` // 可选权限
	StorageKeys   []string `json:"storage_keys"`   // 额外存储键
	DisplayName   string   `json:"display_name"`   // 显示名称
	Name          string   `json:"name"`           // 仅允许字母、数字、下划线、中划线
	Describe      string   `json:"describe"`       // 应用描述
	Url           string   `json:"url"`            // 首次访问 url
	Icon          string   `json:"icon"`           // icon url
	Show          bool     `json:"show"`
	Admin         string   `json:"admin"`         // 拥有人
	Collaborators []string `json:"collaborators"` // 协作者
}

func NewAppUsecase(repo AppRepo) *AppUsecase {
	return &AppUsecase{Repo: repo}
}
