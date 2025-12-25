package data

import (
	"context"
	"fmt"
	"iwut-auth-center/internal/conf"
	"strings"
	"sync"
	"time"

	"github.com/go-kratos/kratos/v2/log"
	"github.com/go-redis/redis/v8"
	"github.com/google/wire"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

// ProviderSet is data providers.
var ProviderSet = wire.NewSet(NewData, NewAuthRepo, NewUserRepo)

var (
	RedisPrefixKey string
)

type Data struct {
	mongo *mongo.Client
	redis *redis.Client
}

// NewData .
func NewData(c *conf.Data) (*Data, func(), error) {
	mongoClient, err := initMongo(c)
	if err != nil {
		return nil, nil, err
	}
	redisClient, err := initRedis(c)
	if err != nil {
		return nil, nil, err
	}
	cleanup := func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		var wg sync.WaitGroup
		errCh := make(chan error, 2)

		// 并发关闭 mongodb
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := mongoClient.Disconnect(ctx); err != nil {
				errCh <- fmt.Errorf("failed to disconnect mongodb: %w", err)
			}
		}()

		// 并发关闭 redis
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := redisClient.Close(); err != nil {
				errCh <- fmt.Errorf("failed to close redis client: %w", err)
			}
		}()

		wg.Wait()
		close(errCh)

		for err := range errCh {
			if err != nil {
				log.Error(err.Error())
			}
		}

		log.Info("closing the data resources")
	}
	return &Data{mongo: mongoClient, redis: redisClient}, cleanup, nil
}

func initMongo(c *conf.Data) (*mongo.Client, error) {
	uri := c.GetMongodb().GetUri()
	if uri == "" {
		return nil, fmt.Errorf("mongodb uri is empty")
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()

	clientOpts := options.Client().ApplyURI(uri)

	if c.Mongodb.GetUsername() != "" && c.Mongodb.GetPassword() != "" {
		cred := options.Credential{
			Username:   c.Mongodb.GetUsername(),
			Password:   c.Mongodb.GetPassword(),
			AuthSource: c.Mongodb.GetAuthSource(),
		}
		clientOpts.SetAuth(cred)
	}

	client, err := mongo.Connect(ctx, clientOpts)
	if err != nil {
		return nil, err
	}

	if err := client.Ping(ctx, nil); err != nil {
		_ = client.Disconnect(context.Background())
		return nil, err
	}
	return client, nil
}

func initRedis(c *conf.Data) (*redis.Client, error) {
	addr := c.GetRedis().GetAddr()
	if addr == "" {
		return nil, fmt.Errorf("redis addr is empty")
	}

	password := c.GetRedis().GetPassword()
	if password == "" {
		log.Warn("redis password is empty")
	}

	RedisPrefixKey = c.GetRedis().GetPrefixKey()
	if RedisPrefixKey == "" {
		log.Warn("redis prefix key is empty, using default 'AuthCenter:'")
		RedisPrefixKey = "AuthCenter:"
	} else {
		if strings.HasSuffix(RedisPrefixKey, ":") == false {
			RedisPrefixKey += ":"
		}
	}

	db := int(c.GetRedis().GetDb())

	// 这里使用默认超时，若配置对象提供了超时字段可进一步从 c.GetRedis() 取值并解析
	rdb := redis.NewClient(&redis.Options{
		Addr:     addr,
		Password: password,
		DB:       db,
		// 可按需设置其他选项，例如 Password、DB、DialTimeout 等
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := rdb.Ping(ctx).Err(); err != nil {
		_ = rdb.Close()
		return nil, fmt.Errorf("redis ping failed: %w", err)
	}

	return rdb, nil
}

func GetRedisKey(keys ...string) string {
	for i, key := range keys {
		keys[i] = strings.Trim(key, ":")
	}
	return RedisPrefixKey + strings.Join(keys, ":")
}
