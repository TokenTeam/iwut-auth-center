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
	clientInfo, err := r.getClientInfoFromAppCenter(clientId)
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
		return clientInfo, err
	}
	return clientInfo, nil
}

const clientInfoTTL = 30 * time.Minute

// cacheClientInfo 将结构体序列化为 JSON 并写入 Redis
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

// GetClientInfoCache 从 Redis 读取 JSON 并反序列化为结构体
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

func (r *appRepo) getClientInfoFromAppCenter(clientId string) (*biz.ClientInfo, error) {
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
