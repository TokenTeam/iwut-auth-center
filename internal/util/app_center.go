package util

import (
	"context"
	"encoding/json"
	"fmt"
	"iwut-auth-center/api/gen/go/app_center/v1/app"
	"iwut-auth-center/internal/conf"
	"time"

	"github.com/go-kratos/kratos/v2/log"
	"go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
)

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
	Id              string   `json:"id"`               // 计算属性！ 应用ID，格式为 admin.name
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
	log       *log.Helper
	grpcConn  *grpc.ClientConn
	appClient app.AppClient
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

	client := app.NewAppClient(conn)
	util := &AppCenterUtil{
		log:       log.NewHelper(logger),
		grpcConn:  conn,
		appClient: client,
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
	//
	//// 先尝试从缓存获取
	//cachedClient, err := u.getClientInfoFromCache(ctx, clientId)
	//if err != nil {
	//	l.Errorf("GetApplicationInfo cache error: %v", err)
	//	return nil, err
	//}
	//if cachedClient != nil {
	//	l.Debugf("GetApplicationInfo cache hit for clientId: %s", clientId)
	//	return cachedClient, nil
	//}
	//// 缓存未命中，从 AppCenter 获取
	clientInfo, err := u.getApplicationInfoFromAppCenter(ctx, clientId)
	if err != nil {
		l.Errorf("GetClientInfo from AppCenter error: %v", err)
		return nil, err
	}
	if clientInfo == nil {
		l.Infof("GetClientInfo from AppCenter returned nil for clientId: %s", clientId)
		return nil, nil
	}
	// 将获取到的信息缓存起来
	//err = u.cacheClientInfo(ctx, clientInfo)
	//if err != nil {
	//	l.Errorf("cacheClientInfo error: %v", err)
	//	// 缓存失败不影响正常返回
	//}
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

//func (u *AppCenterUtil) GetApplicationVersionInfoWithUserCheck(ctx context.Context, clientId string, userId string, internalVersion int32) (bool, *ApplicationVersionInfo, error) {
//	l := log.NewHelper(log.WithContext(ctx, u.log.Logger()))
//
//	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
//	defer cancel()
//	l.Debugf("GetApplicationVersionInfoWithUserCheck clientId: %s, userId: %s, internalVersion: %d", clientId, userId, internalVersion)
//
//	clientVersionInfo, err := u.getApplicationVersionInfoWithUserCheckFromAppCenter(ctx, clientId, userId, internalVersion)
//	if err != nil {
//		l.Errorf("GetApplicationVersionInfoWithUserCheck from AppCenter error: %v", err)
//		return false, nil, err
//	}
//}

//func (u *AppCenterUtil) GetUserApplicationVersionInfoList(ctx context.Context, clientId string, userId string) (*ApplicationVersionInfoList, error) {
//	l := log.NewHelper(log.WithContext(ctx, u.log.Logger()))
//	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
//	defer cancel()
//	l.Debugf("GetUserApplicationVersionInfoList clientId: %s, userId: %s", clientId, userId)
//
//	userApplicationVersionInfo, err := u.getUserApplicationVersionInfoFromAppCenter(ctx, clientId, userId)
//	if err != nil {
//		l.Error("GetUserApplicationVersionInfoList from AppCenter error: %v", err)
//		return nil, err
//	}
//	if userApplicationVersionInfo == nil {
//		l.Infof("GetUserApplicationVersionInfoList from AppCenter returned nil for clientId: %s, userId: %s", clientId, userId)
//		return nil, nil
//	}
//	return userApplicationVersionInfo, nil
//}

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

//const clientInfoTTL = 30 * time.Minute

// cacheClientInfo serializes the provided ApplicationInfo into JSON and stores it in Redis
// with a TTL defined by clientInfoTTL. It returns an error if serialization or
// Redis SET fails.
// Parameters:
// - ctx: context for cancellation and deadlines.
// - client: pointer to util.ApplicationInfo to be cached.
// Returns:
// - error: non-nil when JSON marshaling or Redis operations fail.
//func (r *AppCenterUtil) cacheClientInfo(ctx context.Context, client *util.ApplicationInfo) error {
//	key := GetRedisKey("client_info", client.ClientId)
//
//	// 序列化为 JSON
//	b, err := json.Marshal(client)
//	if err != nil {
//		return err
//	}
//
//	// 写入 Redis（设置 TTL）
//	return r.data.redis.Set(ctx, key, b, clientInfoTTL).Err()
//}

type ServiceClaim struct {
	ServiceName string `json:"ServiceName"`
	FuncName    string `json:"FuncName"`
}

// getClientInfoFromCache attempts to read a client info JSON blob from Redis and
// unmarshal it into a util.ApplicationInfo struct.
// Behavior:
// - If the key is missing in Redis, it returns (nil, nil) to indicate a cache miss.
// - If the value exists but JSON unmarshalling fails, it returns an error.
// Parameters:
// - ctx: context for cancellation and deadlines.
// - clientID: the client identifier used to build the Redis key.
// Returns:
// - *util.ApplicationInfo: the unmarshaled client info when present.
// - error: non-nil if a Redis or unmarshalling error occurs.
//
//	func (r *AppCenterUtil) getClientInfoFromCache(ctx context.Context, clientID string) (*util.ApplicationInfo, error) {
//		key := GetRedisKey("client_info", clientID)
//
//		val, err := r.data.redis.Get(ctx, key).Result()
//		if err != nil {
//			if errors.Is(err, redis.Nil) {
//				// 未命中缓存，按你的逻辑可以返回 nil,nil 或去 AppCenter 拉取后再 Cache
//				return nil, nil
//			}
//			return nil, err
//		}
//
//		var client util.ApplicationInfo
//		if err := json.Unmarshal([]byte(val), &client); err != nil {
//			return nil, err
//		}
//		return &client, nil
//	}
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
	if err != nil {
		return nil, err
	}
	// check business code
	if resp == nil {
		return nil, nil
	}
	if resp.GetCode()/100 != 2 {
		return nil, fmt.Errorf("app center returned code=%d message=%s", resp.GetCode(), resp.GetMessage())
	}
	ad := resp.GetData()
	if ad == nil {
		return nil, nil
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
	if u.appClient == nil {
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

	req := &app.GetAppVersionInfoRequest{
		ClientId: clientId,
		Version:  internalVersion,
	}
	resp, err := u.appClient.GetAppVersionInfo(ctx, req)
	if err != nil {
		return nil, err
	}
	if resp == nil {
		return nil, nil
	}
	if resp.GetCode()/100 != 2 {
		return nil, fmt.Errorf("app center returned code=%d message=%s", resp.GetCode(), resp.GetMessage())
	}
	ad := resp.GetData()
	if ad == nil {
		return nil, nil
	}
	avi := convertToApplicationVersionInfo(ad)
	return avi, nil
}

func (u *AppCenterUtil) getApplicationVersionInfoWithUserCheckFromAppCenter(ctx context.Context, clientId string, userId string, internalVersion int32) (bool, *ApplicationVersionInfo, error) {
	if u.appClient == nil {
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

	req := &app.GetAppVersionInfoWithUserCheckRequest{
		ClientId: clientId,
		Version:  internalVersion,
		UserId:   userId,
	}
	resp, err := u.appClient.GetAppVersionInfoWithUserCheck(ctx, req)
	if err != nil {
		return false, nil, err
	}
	if resp == nil {
		return false, nil, nil
	}
	if resp.GetCode()/100 != 2 {
		return false, nil, fmt.Errorf("app center returned code=%d message=%s", resp.GetCode(), resp.GetMessage())
	}
	ad := resp.GetData()
	if ad == nil || ad.GetAppVersion() == nil {
		return false, nil, fmt.Errorf("get app version info with user check from app center returned nil data for clientId=%s, userId=%s, internalVersion=%d", clientId, userId, internalVersion)
	}
	return ad.GetAllowed(), convertToApplicationVersionInfo(ad.GetAppVersion()), nil
}
func convertToApplicationVersionInfo(appVersion *app.ApplicationVersion) *ApplicationVersionInfo {

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

//	func (u *AppCenterUtil) getUserApplicationVersionInfoFromAppCenter(ctx context.Context, clientId string, userId string) (*ApplicationVersionInfoList, error) {
//		// userId 参数目前未使用；标记为已使用以避免编译/静态检查警告
//		_ = userId
//		a, _ := u.getApplicationVersionInfoFromAppCenter(ctx, clientId, 1)
//		b, _ := u.getApplicationVersionInfoFromAppCenter(ctx, clientId, 2)
//		c, _ := u.getApplicationVersionInfoFromAppCenter(ctx, clientId, 3)
//		return &ApplicationVersionInfoList{
//			StableVersionInfo: a,
//			GrayVersionInfo:     b,
//			TestVersionInfo:     c,
//		}, nil
//	}
//func (u *AppCenterUtil) getClientVersionInfoWithInternalVersionFromAppCenter(ctx context.Context, clientId string, userId string, internalVersion int32) (*ApplicationVersionInfo, error) {
//	// userId 参数目前未使用；标记为已使用以避免编译/静态检查警告
//	_ = userId
//	// userId 参数目前未使用，应当发送到AppCenter 进行校验
//	return u.getApplicationVersionInfoFromAppCenter(ctx, clientId, internalVersion)
//}
