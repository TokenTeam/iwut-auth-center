package data

import (
	"context"
	"encoding/json"
	"errors"
	"iwut-auth-center/internal/biz"
	"time"

	"github.com/go-kratos/kratos/v2/log"
	"github.com/go-redis/redis/v8"
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
// - *biz.ClientInfo: the client information when found, or nil if not found.
// - error: non-nil if an error occurred while accessing cache or App Center.
func (r *appRepo) GetClientInfo(ctx context.Context, clientId string) (*biz.ClientInfo, error) {
	l := log.NewHelper(log.WithContext(ctx, r.log.Logger()))

	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	l.Debugf("GetClientInfo clientId: %s", clientId)

	// 先尝试从缓存获取
	cachedClient, err := r.getClientInfoFromCache(ctx, clientId)
	if err != nil {
		l.Errorf("GetClientInfo cache error: %v", err)
		return nil, err
	}
	if cachedClient != nil {
		l.Debugf("GetClientInfo cache hit for clientId: %s", clientId)
		return cachedClient, nil
	}
	// 缓存未命中，从 AppCenter 获取
	clientInfo, err := r.getClientInfoFromAppCenter(ctx, clientId)
	if err != nil {
		l.Errorf("GetClientInfo from AppCenter error: %v", err)
		return nil, err
	}
	if clientInfo == nil {
		l.Infof("GetClientInfo from AppCenter returned nil for clientId: %s", clientId)
		return nil, nil
	}
	// 将获取到的信息缓存起来
	err = r.cacheClientInfo(ctx, clientInfo)
	if err != nil {
		l.Errorf("cacheClientInfo error: %v", err)
		// 缓存失败不影响正常返回
	}
	return clientInfo, nil
}

const clientInfoTTL = 30 * time.Minute

// cacheClientInfo serializes the provided ClientInfo into JSON and stores it in Redis
// with a TTL defined by clientInfoTTL. It returns an error if serialization or
// Redis SET fails.
// Parameters:
// - ctx: context for cancellation and deadlines.
// - client: pointer to biz.ClientInfo to be cached.
// Returns:
// - error: non-nil when JSON marshaling or Redis operations fail.
func (r *appRepo) cacheClientInfo(ctx context.Context, client *biz.ClientInfo) error {
	key := GetRedisKey("client_info", client.ClientId)

	// 序列化为 JSON
	b, err := json.Marshal(client)
	if err != nil {
		return err
	}

	// 写入 Redis（设置 TTL）
	return r.data.redis.Set(ctx, key, b, clientInfoTTL).Err()
}

// getClientInfoFromCache attempts to read a client info JSON blob from Redis and
// unmarshal it into a biz.ClientInfo struct.
// Behavior:
// - If the key is missing in Redis, it returns (nil, nil) to indicate a cache miss.
// - If the value exists but JSON unmarshalling fails, it returns an error.
// Parameters:
// - ctx: context for cancellation and deadlines.
// - clientID: the client identifier used to build the Redis key.
// Returns:
// - *biz.ClientInfo: the unmarshaled client info when present.
// - error: non-nil if a Redis or unmarshalling error occurs.
func (r *appRepo) getClientInfoFromCache(ctx context.Context, clientID string) (*biz.ClientInfo, error) {
	key := GetRedisKey("client_info", clientID)

	val, err := r.data.redis.Get(ctx, key).Result()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			// 未命中缓存，按你的逻辑可以返回 nil,nil 或去 AppCenter 拉取后再 Cache
			return nil, nil
		}
		return nil, err
	}

	var client biz.ClientInfo
	if err := json.Unmarshal([]byte(val), &client); err != nil {
		return nil, err
	}
	return &client, nil
}

// getClientInfoFromAppCenter is a placeholder function that should query the
// external App Center service to retrieve client metadata when the cache misses.
// Current implementation returns a stubbed example client and nil error.
// Parameters:
// - ctx: context for cancellation and deadlines.
// - clientId: the identifier of the client application to fetch.
// Returns:
// - *biz.ClientInfo: the client info obtained from App Center or nil if not found.
// - error: non-nil if the external call fails.
func (r *appRepo) getClientInfoFromAppCenter(ctx context.Context, clientId string) (*biz.ClientInfo, error) {
	// TODO: implement the logic after app center is ready
	return &biz.ClientInfo{
		ClientId:      clientId,
		ClientSecret:  "123456789abcdef",
		Version:       "1.0.0",
		RedirectUri:   []string{"http://localhost:8080/callback"},
		BasicScope:    []string{"read___id", "read__nick"},
		OptionalScope: []string{"read__email"},
		StorageKeys:   []string{"test"},
		DisplayName:   "Test Application",
		Name:          "Test App",
		Describe:      "This is a test application for demonstration purposes.",
		Url:           "http://localhost:8080",
		Icon:          "",
		Show:          false,
		Admin:         "official",
		Collaborators: []string{},
	}, nil
}
