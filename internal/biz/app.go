package biz

import "context"

type AppRepo interface {
	GetApplicationInfo(ctx context.Context, clientId string) (*ApplicationInfo, error)
	GetApplicationVersionInfo(ctx context.Context, clientId string, internalVersion int32) (*ApplicationVersionInfo, error)
	// GetUserApplicationVersionInfo GetUserApplicationVersionInfoList 传递userId 的版本 应该进行用户可访问性检查
	GetUserApplicationVersionInfo(ctx context.Context, clientId string, userId string, internalVersion int32) (*ApplicationVersionInfo, error)
	GetUserApplicationVersionInfoList(ctx context.Context, clientId string, userId string) (*ApplicationVersionInfoList, error)
}

type AppUsecase struct {
	Repo AppRepo
}

//	type ApplicationInfo struct {
//		ClientId      string   `json:"client_id"`
//		ClientSecret  string   `json:"client_secret"`
//		Version       string   `json:"version"`        // 应用版本
//		RedirectUri   []string `json:"redirect_uri"`   // 跳转地址
//		BasicScope    []string `json:"basic_scope"`    // 必须权限
//		OptionalScope []string `json:"optional_scope"` // 可选权限
//		StorageKeys   []string `json:"storage_keys"`   // 额外存储键
//		DisplayName   string   `json:"display_name"`   // 显示名称
//		Name          string   `json:"name"`           // 仅允许字母、数字、下划线、中划线
//		Describe      string   `json:"describe"`       // 应用描述
//		Url           string   `json:"url"`            // 首次访问 url
//		Icon          string   `json:"icon"`           // icon url
//		Show          bool     `json:"show"`
//		Admin         string   `json:"admin"`         // 拥有人
//		Collaborators []string `json:"collaborators"` // 协作者
//	}
type ApplicationInfo struct {
	ClientId       string   `json:"client_id"`
	ClientSecret   string   `json:"client_secret"`
	StableVersion  int32    `json:"stable_version"`  // 稳定版本
	GrayVersion    int32    `json:"gray_version"`    // 灰度版本
	BetaVersion    int32    `json:"beta_version"`    // 测试版本
	GrayPercentage float32  `json:"gray_percentage"` // 灰度版本用户占比，0-1
	Name           string   `json:"name"`            // 仅允许字母、数字、下划线、中划线
	Status         string   `json:"status"`          // DEVELOPING AUDITING PUBLISHED BANNED（由官方下架） HIDDEN（由用户下架） ...
	Admin          string   `json:"admin"`           // 拥有人
	Collaborators  []string `json:"collaborators"`   // 协作者
	Id             string   `json:"id"`              // 计算属性！ 应用ID，格式为 admin.name
}

type ApplicationVersionInfo struct {
	ClientId        string   `json:"client_id"`
	InternalVersion int32    `json:"internal_version"` // 内部版本号，递增
	BasicScope      []string `json:"basic_scope"`
	OptionalScope   []string `json:"optional_scope"`
	//StorageKeys []string `json:"storage_keys"`
	Version     string   `json:"version"` // 开发者自定义版本号
	RedirectUri []string `json:"redirect_uri"`
	DisplayName string   `json:"display_name"`
	Url         string   `json:"url"`  // 首次访问 url
	Icon        string   `json:"icon"` // icon url
	Rule        string   `json:"rule"` // 用户筛选显示规则
	Type        string   `json:"type"` // 计算属性！ STANDARD GRAY TEST
	Id          string   `json:"id"`   // 计算属性！ 版本ID，格式为 admin.name
}

type ApplicationVersionInfoList struct {
	StandardVersionInfo *ApplicationVersionInfo
	GrayVersionInfo     *ApplicationVersionInfo
	TestVersionInfo     *ApplicationVersionInfo
}

func NewAppUsecase(repo AppRepo) *AppUsecase {
	return &AppUsecase{Repo: repo}
}
