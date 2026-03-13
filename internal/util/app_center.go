package util

import (
	"context"
	"encoding/json"
	"fmt"
	"iwut-auth-center/api/gen/go/app_center/v1/app"
	"iwut-auth-center/api/gen/go/app_center/v1/app_version"
	"iwut-auth-center/internal/conf"
	"time"

	"github.com/go-kratos/kratos/v2/log"
	"go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
)

type ApplicationInfo struct {
	ClientId        string   `json:"client_id"`
	ClientSecret    string   `json:"client_secret"`
	StableVersion   int32    `json:"stable_version"`   // 稳定版本
	GreyVersion     int32    `json:"grey_version"`     // 灰度版本
	BetaVersion     int32    `json:"beta_version"`     // 测试版本
	GreyShuffleCode int32    `json:"grey_shuffleCode"` // 灰度版本随机码，整数，0-10000，配合 GreyPercentage 做灰度控制
	GreyPercentage  float64  `json:"grey_percentage"`  // 灰度版本用户占比，0-1
	RedirectUri     []string `json:"redirect_uri"`     // 跳转地址
	Name            string   `json:"name"`             // 仅允许字母、数字、下划线、中划线
	Status          string   `json:"status"`           // DEVELOPING AUDITING PUBLISHED BANNED（由官方下架） HIDDEN（由用户下架） ...
	Admin           string   `json:"admin"`            // 拥有人
	Collaborators   []string `json:"collaborators"`    // 协作者
	NextVersion     int32    `json:"next_version"`     // 下一个版本号，等于 max(StableVersion, GreyVersion, BetaVersion) + 1
	Id              string   `json:"id"`               // 计算属性！ 应用ID，格式为 uid.clientId
}

type ApplicationVersionInfo struct {
	ClientId        string     `json:"client_id"`
	InternalVersion int32      `json:"internal_version"` // 内部版本号，递增
	BasicScope      []string   `json:"basic_scope"`
	OptionalScope   []string   `json:"optional_scope"`
	Version         string     `json:"version"` // 开发者自定义版本号
	DisplayName     string     `json:"display_name"`
	Description     string     `json:"description"`
	Url             string     `json:"url"`    // 首次访问 url
	Icon            string     `json:"icon"`   // icon url
	Status          string     `json:"status"` //DEACTIVATE STABLE GREY TEST
	CreatedAt       time.Time  `json:"created_at"`
	DeletedAt       *time.Time `json:"deleted_at"`
}

type ApplicationVersionInfoList struct {
	StableVersionInfo *ApplicationVersionInfo
	GrayVersionInfo   *ApplicationVersionInfo
	TestVersionInfo   *ApplicationVersionInfo
}

type AppCenterUtil struct {
	log              *log.Helper
	grpcConn         *grpc.ClientConn
	appClient        app.AppClient
	appVersionClient app_version.AppVersionClient
}

// NewAppCenterUtil creates an AppCenterUtil and establishes a gRPC connection to AppCenter.
// Returns the repo, a cleanup func to close the connection, and an error.
func NewAppCenterUtil(c *conf.Service, logger log.Logger) (*AppCenterUtil, func(), error) {
	l := log.NewHelper(logger)
	addr := ""
	if c.GetApp() != nil {
		addr = c.GetApp().GetUri()
	}
	if addr == "" {
		return nil, nil, fmt.Errorf("app center uri is empty in config")
	}

	conn, err := grpc.NewClient(addr,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithConnectParams(grpc.ConnectParams{MinConnectTimeout: 5 * time.Second}),
		grpc.WithStatsHandler(otelgrpc.NewClientHandler()),
	)
	if err != nil {
		l.Errorf("failed to create app center client %s: %v", addr, err)
		return nil, nil, err
	}

	util := &AppCenterUtil{
		log:              log.NewHelper(logger),
		grpcConn:         conn,
		appClient:        app.NewAppClient(conn),
		appVersionClient: app_version.NewAppVersionClient(conn),
	}
	cleanup := func() {
		_ = conn.Close()
	}
	return util, cleanup, nil
}

// GetApplicationInfo retrieves client information for the given clientId.
// Behavior:
//   - It first attempts to load the client information from Redis cache.
//   - If the cache misses, it falls back to fetching the information from the App Center
//     via getApplicationInfoFromAppCenter and then caches the result via cacheClientInfo.
//
// Parameters:
// - ctx: context for cancellation and deadlines.
// - clientId: the identifier of the client application to look up.
// Returns:
// - *util.ApplicationInfo: the client information when found, or nil if not found.
// - error: non-nil if an error occurred while accessing cache or App Center.
// Notes:
// - Cache had been disabled
func (u *AppCenterUtil) GetApplicationInfo(ctx context.Context, clientId string) (*ApplicationInfo, error) {
	l := log.NewHelper(log.WithContext(ctx, u.log.Logger()))

	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	l.Debugf("GetApplicationInfo clientId: %s", clientId)
	clientInfo, err := u.getApplicationInfoFromAppCenter(ctx, clientId)
	if err != nil {
		l.Errorf("GetClientInfo from AppCenter error: %v", err)
		return nil, err
	}
	if clientInfo == nil {
		l.Infof("GetClientInfo from AppCenter returned nil for clientId: %s", clientId)
		return nil, nil
	}

	return clientInfo, nil
}

func (u *AppCenterUtil) GetApplicationVersionInfo(ctx context.Context, clientId string, internalVersion int32) (*ApplicationVersionInfo, error) {
	l := log.NewHelper(log.WithContext(ctx, u.log.Logger()))

	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	l.Debugf("GetApplicationVersionInfo clientId: %s, internalVersion: %d", clientId, internalVersion)

	clientVersionInfo, err := u.getApplicationVersionInfoFromAppCenter(ctx, clientId, internalVersion)
	if err != nil {
		l.Errorf("GetApplicationVersionInfo from AppCenter error: %v", err)
		return nil, err
	}
	if clientVersionInfo == nil {
		l.Infof("GetApplicationVersionInfo from AppCenter returned nil for clientId: %s, internalVersion: %d", clientId, internalVersion)
		return nil, nil
	}
	return clientVersionInfo, nil
}

func (u *AppCenterUtil) GetApplicationVersionInfoWithUserCheck(ctx context.Context, clientId string, userId string, internalVersion int32) (bool, *ApplicationVersionInfo, error) {
	l := log.NewHelper(log.WithContext(ctx, u.log.Logger()))
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	l.Debugf("GetApplicationVersionInfoWithUserCheck clientId: %s, userId: %s, internalVersion: %d", clientId, userId, internalVersion)

	// 目前先直接调用 getApplicationVersionInfoFromAppCenter 获取，后续可以根据用户和版本号的不同进行灰度等逻辑处理
	allowed, clientVersionInfo, err := u.getApplicationVersionInfoWithUserCheckFromAppCenter(ctx, clientId, userId, internalVersion)
	if err != nil {
		l.Errorf("GetApplicationVersionInfoWithUserCheck from AppCenter error: %v", err)
		return false, nil, err
	}
	if clientVersionInfo == nil {
		l.Infof("GetApplicationVersionInfoWithUserCheck from AppCenter returned nil for clientId: %s, userId: %s, internalVersion: %d", clientId, userId, internalVersion)
		return false, nil, fmt.Errorf("GetApplicationVersionInfoWithUserCheck from AppCenter returned nil")
	}
	return allowed, clientVersionInfo, nil
}

type ServiceClaim struct {
	ServiceName string `json:"ServiceName"`
	FuncName    string `json:"FuncName"`
}

func (u *AppCenterUtil) getApplicationInfoFromAppCenter(ctx context.Context, clientId string) (*ApplicationInfo, error) {
	if u.appClient == nil {
		return nil, fmt.Errorf("app center client is not initialized")
	}
	// Append our custom metadata instead of replacing existing outgoing metadata
	ctx = metadata.AppendToOutgoingContext(ctx, "X-Auth-Jwt-Type", "service")
	serviceClaim, err := json.Marshal(ServiceClaim{
		ServiceName: "auth-center",
		FuncName:    "getApplicationInfoFromAppCenter",
	})
	if err != nil {
		return nil, fmt.Errorf("failed to marshal service claim: %v", err)
	}
	ctx = metadata.AppendToOutgoingContext(ctx, "X-Auth-Service-Claim", string(serviceClaim))

	req := &app.GetApplicationInfoRequest{ClientId: clientId}

	resp, err := u.appClient.GetApplicationInfo(ctx, req)
	ad, err := tailProcess(resp, err)
	if err != nil {
		return nil, err
	}
	if ad == nil {
		return nil, fmt.Errorf("get application info from app center returned nil data for clientId: %s", clientId)
	}
	ai := &ApplicationInfo{
		ClientId:        ad.GetClientId(),
		ClientSecret:    ad.GetClientSecret(),
		StableVersion:   ad.GetStableVersion(),
		GreyVersion:     ad.GetGreyVersion(),
		BetaVersion:     ad.GetBetaVersion(),
		GreyShuffleCode: ad.GetGreyShuffleCode(),
		GreyPercentage:  ad.GetGreyPercentage(),
		RedirectUri:     ad.GetRedirectUri(),
		Name:            ad.GetName(),
		Status:          ad.GetStatus(),
		Admin:           ad.GetAdmin(),
		Collaborators:   ad.GetCollaborators(),
		NextVersion:     ad.GetNextVersion(),
		Id:              ad.GetId(),
	}
	return ai, nil
}

func (u *AppCenterUtil) getApplicationVersionInfoFromAppCenter(ctx context.Context, clientId string, internalVersion int32) (*ApplicationVersionInfo, error) {
	if u.appVersionClient == nil {
		return nil, fmt.Errorf("app center client is not initialized")
	}
	ctx = metadata.AppendToOutgoingContext(ctx, "X-Auth-Jwt-Type", "service")
	serviceClaim, err := json.Marshal(ServiceClaim{
		ServiceName: "auth-center",
		FuncName:    "getApplicationVersionInfoFromAppCenter",
	})
	if err != nil {
		return nil, fmt.Errorf("failed to marshal service claim: %v", err)
	}
	ctx = metadata.AppendToOutgoingContext(ctx, "X-Auth-Service-Claim", string(serviceClaim))

	req := &app_version.GetAppVersionInfoRequest{
		ClientId: clientId,
		Version:  internalVersion,
	}
	resp, err := u.appVersionClient.GetAppVersionInfo(ctx, req)
	ad, err := tailProcess(resp, err)
	if err != nil {
		return nil, err
	}
	if ad == nil {
		return nil, fmt.Errorf("get app version info from app center returned nil data for clientId=%s, internalVersion=%d", clientId, internalVersion)
	}
	avi := convertToApplicationVersionInfo(ad)
	return avi, nil
}

func (u *AppCenterUtil) getApplicationVersionInfoWithUserCheckFromAppCenter(ctx context.Context, clientId string, userId string, internalVersion int32) (bool, *ApplicationVersionInfo, error) {
	if u.appVersionClient == nil {
		return false, nil, fmt.Errorf("app center client is not initialized")
	}
	ctx = metadata.AppendToOutgoingContext(ctx, "X-Auth-Jwt-Type", "service")
	serviceClaim, err := json.Marshal(ServiceClaim{
		ServiceName: "auth-center",
		FuncName:    "getApplicationVersionInfoWithUserCheckFromAppCenter",
	})
	if err != nil {
		return false, nil, fmt.Errorf("failed to marshal service claim: %v", err)
	}
	ctx = metadata.AppendToOutgoingContext(ctx, "X-Auth-Service-Claim", string(serviceClaim))

	req := &app_version.GetAppVersionInfoWithUserCheckRequest{
		ClientId: clientId,
		Version:  internalVersion,
		UserId:   userId,
	}
	resp, err := u.appVersionClient.GetAppVersionInfoWithUserCheck(ctx, req)
	ad, err := tailProcess(resp, err)
	if err != nil {
		return false, nil, err
	}
	if ad == nil || ad.GetAppVersion() == nil {
		return false, nil, fmt.Errorf("get app version info with user check from app center returned nil data for clientId=%s, userId=%s, internalVersion=%d", clientId, userId, internalVersion)
	}
	return ad.GetAllowed(), convertToApplicationVersionInfo(ad.GetAppVersion()), nil
}
func convertToApplicationVersionInfo(appVersion *app_version.ApplicationVersion) *ApplicationVersionInfo {

	return &ApplicationVersionInfo{
		ClientId:        appVersion.GetClientId(),
		InternalVersion: appVersion.GetInternalVersion(),
		BasicScope:      appVersion.GetBasicScope(),
		OptionalScope:   appVersion.GetOptionalScope(),
		Version:         appVersion.GetVersion(),
		DisplayName:     appVersion.GetDisplayName(),
		Description:     appVersion.GetDescription(),
		Url:             appVersion.GetUrl(),
		Icon:            appVersion.GetIcon(),
		Status:          appVersion.GetStatus(),
		CreatedAt:       appVersion.GetCreatedAt().AsTime(),
		DeletedAt: func() *time.Time {
			if appVersion.GetDeletedAt() != nil {
				t := appVersion.GetDeletedAt().AsTime()
				return &t
			}
			return nil
		}(),
	}
}

type appCenterReply[N any] interface {
	*app.GetApplicationInfoReply |
		*app_version.GetAppVersionInfoReply |
		*app_version.GetAppVersionInfoWithUserCheckReply

	GetCode() int32
	GetMessage() string
	GetData() *N
}

func tailProcess[N any, T appCenterReply[N]](resp T, err error) (*N, error) {
	if err != nil {
		return nil, err
	}
	if resp == nil {
		return nil, fmt.Errorf("response is nil")
	}
	if resp.GetCode()/100 != 2 {
		return nil, fmt.Errorf("app center returned code=%d message=%s", resp.GetCode(), resp.GetMessage())
	}
	return resp.GetData(), nil
}
