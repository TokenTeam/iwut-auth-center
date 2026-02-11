package data

import (
	"context"
	"iwut-auth-center/internal/biz"
	"time"

	"github.com/go-kratos/kratos/v2/log"
)

type appRepo struct {
	data *Data
	log  *log.Helper
}

func NewAppRepo(data *Data, logger log.Logger) biz.AppRepo {
	return &appRepo{
		data: data,
		log:  log.NewHelper(logger),
	}
}

// GetClientInfo retrieves client information for the given clientId.
// Behavior:
//   - It first attempts to load the client information from Redis cache.
//   - If the cache misses, it falls back to fetching the information from the App Center
//     via getClientInfoFromAppCenter and then caches the result via cacheClientInfo.
//
// Parameters:
// - ctx: context for cancellation and deadlines.
// - clientId: the identifier of the client application to look up.
// Returns:
// - *biz.ApplicationInfo: the client information when found, or nil if not found.
// - error: non-nil if an error occurred while accessing cache or App Center.
// Notes:
// - Cache had been disabled
func (r *appRepo) GetApplicationInfo(ctx context.Context, clientId string) (*biz.ApplicationInfo, error) {
	l := log.NewHelper(log.WithContext(ctx, r.log.Logger()))

	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	l.Debugf("GetApplicationInfo clientId: %s", clientId)
	//
	//// 先尝试从缓存获取
	//cachedClient, err := r.getClientInfoFromCache(ctx, clientId)
	//if err != nil {
	//	l.Errorf("GetApplicationInfo cache error: %v", err)
	//	return nil, err
	//}
	//if cachedClient != nil {
	//	l.Debugf("GetApplicationInfo cache hit for clientId: %s", clientId)
	//	return cachedClient, nil
	//}
	//// 缓存未命中，从 AppCenter 获取
	clientInfo, err := r.getClientInfoFromAppCenter(ctx, clientId)
	if err != nil {
		l.Errorf("GetApplicationInfo from AppCenter error: %v", err)
		return nil, err
	}
	if clientInfo == nil {
		l.Infof("GetApplicationInfo from AppCenter returned nil for clientId: %s", clientId)
		return nil, nil
	}
	// 将获取到的信息缓存起来
	//err = r.cacheClientInfo(ctx, clientInfo)
	//if err != nil {
	//	l.Errorf("cacheClientInfo error: %v", err)
	//	// 缓存失败不影响正常返回
	//}
	return clientInfo, nil
}

func (r *appRepo) GetApplicationVersionInfo(ctx context.Context, clientId string, internalVersion int32) (*biz.ApplicationVersionInfo, error) {
	l := log.NewHelper(log.WithContext(ctx, r.log.Logger()))

	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	l.Debugf("GetApplicationVersionInfo clientId: %s, internalVersion: %d", clientId, internalVersion)

	clientVersionInfo, err := r.getClientVersionInfoFromAppCenter(ctx, clientId, internalVersion)
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

func (r *appRepo) GetUserApplicationVersionInfoList(ctx context.Context, clientId string, userId string) (*biz.ApplicationVersionInfoList, error) {
	l := log.NewHelper(log.WithContext(ctx, r.log.Logger()))
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	l.Debugf("GetUserApplicationVersionInfoList clientId: %s, userId: %s", clientId, userId)

	userApplicationVersionInfo, err := r.getUserApplicationVersionInfoFromAppCenter(ctx, clientId, userId)
	if err != nil {
		l.Error("GetUserApplicationVersionInfoList from AppCenter error: %v", err)
		return nil, err
	}
	if userApplicationVersionInfo == nil {
		l.Infof("GetUserApplicationVersionInfoList from AppCenter returned nil for clientId: %s, userId: %s", clientId, userId)
		return nil, nil
	}
	return userApplicationVersionInfo, nil
}

func (r *appRepo) GetUserApplicationVersionInfo(ctx context.Context, clientId string, userId string, internalVersion int32) (*biz.ApplicationVersionInfo, error) {
	l := log.NewHelper(log.WithContext(ctx, r.log.Logger()))
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	l.Debugf("GetUserApplicationVersionInfo clientId: %s, userId: %s, internalVersion: %d", clientId, userId, internalVersion)

	// 目前先直接调用 getClientVersionInfoFromAppCenter 获取，后续可以根据用户和版本号的不同进行灰度等逻辑处理
	clientVersionInfo, err := r.getClientVersionInfoWithInternalVersionFromAppCenter(ctx, clientId, userId, internalVersion)
	if err != nil {
		l.Errorf("GetUserApplicationVersionInfo from AppCenter error: %v", err)
		return nil, err
	}
	if clientVersionInfo == nil {
		l.Infof("GetUserApplicationVersionInfo from AppCenter returned nil for clientId: %s, userId: %s, internalVersion: %d", clientId, userId, internalVersion)
		return nil, nil
	}
	return clientVersionInfo, nil
}

//const clientInfoTTL = 30 * time.Minute

// cacheClientInfo serializes the provided ApplicationInfo into JSON and stores it in Redis
// with a TTL defined by clientInfoTTL. It returns an error if serialization or
// Redis SET fails.
// Parameters:
// - ctx: context for cancellation and deadlines.
// - client: pointer to biz.ApplicationInfo to be cached.
// Returns:
// - error: non-nil when JSON marshaling or Redis operations fail.
//func (r *appRepo) cacheClientInfo(ctx context.Context, client *biz.ApplicationInfo) error {
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

// getClientInfoFromCache attempts to read a client info JSON blob from Redis and
// unmarshal it into a biz.ApplicationInfo struct.
// Behavior:
// - If the key is missing in Redis, it returns (nil, nil) to indicate a cache miss.
// - If the value exists but JSON unmarshalling fails, it returns an error.
// Parameters:
// - ctx: context for cancellation and deadlines.
// - clientID: the client identifier used to build the Redis key.
// Returns:
// - *biz.ApplicationInfo: the unmarshaled client info when present.
// - error: non-nil if a Redis or unmarshalling error occurs.
//func (r *appRepo) getClientInfoFromCache(ctx context.Context, clientID string) (*biz.ApplicationInfo, error) {
//	key := GetRedisKey("client_info", clientID)
//
//	val, err := r.data.redis.Get(ctx, key).Result()
//	if err != nil {
//		if errors.Is(err, redis.Nil) {
//			// 未命中缓存，按你的逻辑可以返回 nil,nil 或去 AppCenter 拉取后再 Cache
//			return nil, nil
//		}
//		return nil, err
//	}
//
//	var client biz.ApplicationInfo
//	if err := json.Unmarshal([]byte(val), &client); err != nil {
//		return nil, err
//	}
//	return &client, nil
//}

// getClientInfoFromAppCenter is a placeholder function that should query the
// external App Center service to retrieve client metadata when the cache misses.
// Current implementation returns a stubbed example client and nil error.
// Parameters:
// - ctx: context for cancellation and deadlines.
// - clientId: the identifier of the client application to fetch.
// Returns:
// - *biz.ApplicationInfo: the client info obtained from App Center or nil if not found.
// - error: non-nil if the external call fails.
func (r *appRepo) getClientInfoFromAppCenter(_ context.Context, clientId string) (*biz.ApplicationInfo, error) {
	// TODO: implement the logic after app center is ready
	return &biz.ApplicationInfo{
		ClientId:       clientId,
		ClientSecret:   "123456789abcdef",
		StableVersion:  1,
		GrayVersion:    2,
		BetaVersion:    3,
		GrayPercentage: 0.1,
		Name:           "Test_App",
		Status:         "PUBLISHED",
		Admin:          "official",
		Collaborators:  []string{},
		Id:             "official.Test_App",
	}, nil
}
func (r *appRepo) getClientVersionInfoFromAppCenter(_ context.Context, clientId string, internalVersion int32) (*biz.ApplicationVersionInfo, error) {
	// TODO: implement the logic after app center is ready
	return &biz.ApplicationVersionInfo{
		ClientId:        clientId,
		InternalVersion: internalVersion,
		BasicScope:      []string{"read___id", "read__nick"},
		OptionalScope:   []string{"read__email"},
		Version:         "1.0.0",
		RedirectUri:     []string{"http://localhost:8080/callback"},
		DisplayName:     "Test Application",
		Url:             "http://localhost:8080",
		Icon:            "",
		Rule:            "",
		Type:            "STANDARD",
		Id:              "official.Test_App",
	}, nil
}
func (r *appRepo) getUserApplicationVersionInfoFromAppCenter(ctx context.Context, clientId string, userId string) (*biz.ApplicationVersionInfoList, error) {
	a, _ := r.getClientVersionInfoFromAppCenter(ctx, clientId, 1)
	b, _ := r.getClientVersionInfoFromAppCenter(ctx, clientId, 2)
	c, _ := r.getClientVersionInfoFromAppCenter(ctx, clientId, 3)
	return &biz.ApplicationVersionInfoList{
		StandardVersionInfo: a,
		GrayVersionInfo:     b,
		TestVersionInfo:     c,
	}, nil
}
func (r *appRepo) getClientVersionInfoWithInternalVersionFromAppCenter(ctx context.Context, clientId string, userId string, internalVersion int32) (*biz.ApplicationVersionInfo, error) {
	// userId 参数目前未使用，应当发送到AppCenter 进行校验
	return r.getClientVersionInfoFromAppCenter(ctx, clientId, internalVersion)
}
