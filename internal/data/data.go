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
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
)

// ProviderSet is data providers.
var ProviderSet = wire.NewSet(NewAppRepo, NewAuditRepo, NewAuthRepo, NewUserRepo, NewOauth2Repo, NewData)

var (
	RedisPrefixKey string
)

type Data struct {
	mongo *mongo.Client
	redis *redis.Client
	db    *gorm.DB
}

// NewData .
func NewData(c *conf.Data, logger log.Logger) (*Data, func(), error) {
	mongoClient, err := initMongo(c)
	if err != nil {
		return nil, nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := ensureUserEmailUniqueIndex(ctx, mongoClient.Database(c.GetMongodb().GetDatabase()).Collection("user")); err != nil {
		(log.NewHelper(logger)).Warnf("ensure email unique index failed: %v", err)
	}
	redisClient, err := initRedis(c)
	if err != nil {
		// close mongo if redis init failed
		_ = mongoClient.Disconnect(context.Background())
		return nil, nil, err
	}
	mysqlClient, err := initMySQL(c)
	if err != nil {
		// close mongo and redis if mysql init failed
		_ = mongoClient.Disconnect(context.Background())
		_ = redisClient.Close()
		return nil, nil, err
	}
	cleanup := func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		var wg sync.WaitGroup
		errCh := make(chan error, 3)

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

		// 并发关闭 mysql (通过 GORM 获取底层 *sql.DB 并 Close)
		wg.Add(1)
		go func() {
			defer wg.Done()
			if mysqlClient != nil {
				sqlDB, err := mysqlClient.DB()
				if err != nil {
					errCh <- fmt.Errorf("failed to get underlying sql.DB from gorm: %w", err)
					return
				}
				if err := sqlDB.Close(); err != nil {
					errCh <- fmt.Errorf("failed to close mysql client: %w", err)
				}
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
	return &Data{
		mongo: mongoClient,
		redis: redisClient,
		db:    mysqlClient,
	}, cleanup, nil
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

func ensureUserEmailUniqueIndex(ctx context.Context, col *mongo.Collection) error {
	// Create an ascending index on `email` and mark it unique.
	// create indexes as part of a controlled migration step if needed.
	idxOpts := options.Index()
	idxOpts.SetUnique(true)
	// optional: give the index a stable name
	idxOpts.SetName("idx_user_email_unique")

	idx := mongo.IndexModel{
		Keys:    bson.D{{Key: "email", Value: 1}},
		Options: idxOpts,
	}
	_, err := col.Indexes().CreateOne(ctx, idx)
	return err
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

func initMySQL(c *conf.Data) (*gorm.DB, error) {
	driver := c.GetDatabase().GetDriver()
	source := c.GetDatabase().GetSource()
	if driver == "" || source == "" {
		return nil, fmt.Errorf("mysql driver or source is empty")
	}

	// currently we only support mysql driver here
	if driver != "mysql" {
		return nil, fmt.Errorf("unsupported database driver: %s", driver)
	}

	// open gorm DB using mysql driver
	gdb, err := gorm.Open(mysql.Open(source), &gorm.Config{})
	if err != nil {
		return nil, fmt.Errorf("failed to open gorm mysql: %w", err)
	}

	// configure underlying sql.DB connection pool and ping
	sqlDB, err := gdb.DB()
	if err != nil {
		return nil, fmt.Errorf("failed to get underlying sql.DB from gorm: %w", err)
	}
	sqlDB.SetMaxOpenConns(25)
	sqlDB.SetMaxIdleConns(25)
	sqlDB.SetConnMaxLifetime(time.Hour)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := sqlDB.PingContext(ctx); err != nil {
		_ = sqlDB.Close()
		return nil, fmt.Errorf("mysql ping failed: %w", err)
	}
	return gdb, nil
}

func GetRedisKey(keys ...string) string {
	for i, key := range keys {
		keys[i] = strings.Trim(key, ":")
	}
	return RedisPrefixKey + strings.Join(keys, ":")
}
