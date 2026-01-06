package data

import (
	"context"
	"errors"
	"fmt"
	"iwut-auth-center/internal/biz"
	"iwut-auth-center/internal/conf"
	"iwut-auth-center/internal/util"
	"strconv"
	"time"

	"github.com/go-kratos/kratos/v2/log"
	"github.com/go-redis/redis/v8"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
)

type authRepo struct {
	data           *Data
	log            *log.Helper
	userCollection *mongo.Collection
	sha256Util     *util.Sha256Util
}

func NewAuthRepo(data *Data, c *conf.Data, logger log.Logger, sha256Util *util.Sha256Util) biz.AuthRepo {
	dbName := c.GetMongodb().GetDatabase()
	usersCollection := data.mongo.Database(dbName).Collection("user")
	return &authRepo{
		data:           data,
		log:            log.NewHelper(logger),
		userCollection: usersCollection,
		sha256Util:     sha256Util,
	}
}

func (r *authRepo) CheckPasswordWithEmailAndGetUserIdAndVersion(ctx context.Context, email string, password string) (string, int, error) {
	l := log.NewHelper(log.WithContext(ctx, r.log.Logger()))

	password = r.sha256Util.HashPassword(password)
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	l.Debugf("CheckPasswordAndGetUserBaseInfo called with email: %s", email)

	collection := r.userCollection
	filter := bson.M{"email": email, "password": password}

	var result struct {
		UserId    primitive.ObjectID `bson:"_id"`
		Version   int                `bson:"Version"`
		DeletedAt *time.Time         `bson:"deleted_at"`
	}
	err := collection.FindOne(ctx, filter).Decode(&result)

	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return "", -1, biz.UserNotFoundError
		}
		l.Errorf("failed to find user: %v", err)
		return "", -1, fmt.Errorf("failed to find user: %w", err)
	} else if result.DeletedAt != nil {
		// 30 天内可以恢复
		if time.Since(*result.DeletedAt) < 30*24*time.Hour {
			update := bson.M{
				"$set": bson.M{
					"deleted_at": nil,
					"updated_at": time.Now(),
				},
			}
			_, err = collection.UpdateOne(ctx, filter, update)
			if err != nil {
				l.Errorf("failed to restore deleted user: %v", err)
				return "", -1, fmt.Errorf("failed to restore deleted user: %w", err)
			}
		} else {
			return "", -1, biz.UserHasBeenDeletedError
		}
	}

	return result.UserId.Hex(), result.Version, nil
}

func (r *authRepo) TryInsertRegisterCaptcha(ctx context.Context, email string, captcha string, ttl time.Duration) error {
	l := log.NewHelper(log.WithContext(ctx, r.log.Logger()))
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	l.Debugf("TryInsertCaptcha called with email: %s", email)

	collection := r.userCollection
	filter := bson.M{"email": email}

	count, err := collection.CountDocuments(ctx, filter)
	if err != nil {
		l.Errorf("CountDocuments error: %v", err)
		return fmt.Errorf("failed to count documents: %w", err)
	}
	if count > 0 {
		return biz.UserAlreadyExistsError
	}

	key := GetRedisKey("register_captcha", email)
	now := time.Now().Unix()

	// 取最近一条记录做限流
	zs, err := r.data.redis.ZRevRangeWithScores(ctx, key, 0, 0).Result()
	if err != nil && !errors.Is(err, redis.Nil) {
		l.Errorf("ZRevrangeWithScores error: %v", err)
		return fmt.Errorf("redis zrevrange error: %w", err)
	}
	if len(zs) > 0 {
		lastTs := int64(zs[0].Score)
		if time.Unix(now, 0).Sub(time.Unix(lastTs, 0)) < time.Minute {
			return biz.AskingCaptchaTooFrequentlyError
		}
	}

	// 插入新 captcha（score = now）
	if err := r.data.redis.ZAdd(ctx, key, &redis.Z{
		Score:  float64(now),
		Member: captcha,
	}).Err(); err != nil {
		l.Errorf("ZAdd error: %v", err)
		return fmt.Errorf("failed to zadd captcha: %w", err)
	}

	// 清理早于有效期的旧条目（假设 expireAt 是该 captcha 类型的最终有效截止）
	cutoff := strconv.FormatInt(time.Now().Add(-ttl).Unix(), 10)
	if err := r.data.redis.ZRemRangeByScore(ctx, key, "-inf", cutoff).Err(); err != nil {
		// 记录但不阻塞正常流程
		l.Errorf("ZRemRangeByScore error: %v", err)
	}

	if err := r.data.redis.Expire(ctx, key, ttl).Err(); err != nil {
		l.Errorf("Expire error: %v", err)
	}
	return nil
}

func (r *authRepo) CheckCaptchaUsable(ctx context.Context, email string, code string, ttl time.Duration) error {
	l := log.NewHelper(log.WithContext(ctx, r.log.Logger()))
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	key := GetRedisKey("register_captcha", email)

	// 清理早于有效期的旧条目（假设 expireAt 是该 captcha 类型的最终有效截止）
	cutoff := strconv.FormatInt(time.Now().Add(-ttl).Unix(), 10)
	if err := r.data.redis.ZRemRangeByScore(ctx, key, "-inf", cutoff).Err(); err != nil {
		// 记录但不阻塞正常流程
		l.Errorf("ZRemRangeByScore error: %v", err)
	}

	_, err := r.data.redis.ZRank(ctx, key, code).Result()
	if errors.Is(err, redis.Nil) {
		return biz.CaptchaNotUsableError
	} else if err != nil {
		l.Errorf("ZRank error: %v", err)
		return fmt.Errorf("redis zrank error: %w", err)
	}
	return nil
}

func (r *authRepo) RegisterUser(ctx context.Context, email string, password string) (string, error) {
	l := log.NewHelper(log.WithContext(ctx, r.log.Logger()))
	password = r.sha256Util.HashPassword(password)
	filter := bson.M{"email": email}

	count, err := r.userCollection.CountDocuments(ctx, filter)
	if err != nil {
		l.Errorf("CountDocuments error: %v", err)
		return "", fmt.Errorf("failed to count documents: %w", err)
	}
	if count > 0 {
		return "", biz.UserAlreadyExistsError
	}
	result, err := r.userCollection.InsertOne(ctx, bson.M{
		"email":      email,
		"password":   password,
		"created_at": time.Now(),
		"updated_at": time.Now(),
		"Version":    0,
	})
	if err != nil {
		l.Errorf("InsertOne error: %v", err)
		return "", fmt.Errorf("failed to insert user: %w", err)
	}

	var idStr string
	switch id := result.InsertedID.(type) {
	case primitive.ObjectID:
		idStr = id.Hex()
	case string:
		idStr = id
	default:
		idStr = fmt.Sprintf("%v", id)
	}
	return idStr, nil
}

func (r *authRepo) AddOrUpdateUserVersion(ctx context.Context, userId string, version int, ttl time.Duration) error {
	l := log.NewHelper(log.WithContext(ctx, r.log.Logger()))
	key := GetRedisKey("user_version", userId)
	err := r.data.redis.Set(ctx, key, version, ttl).Err()
	if err != nil {
		l.Errorf("Set user Version error: %v", err)
		return fmt.Errorf("failed to set user Version: %w", err)
	}
	return nil
}

// GetUserVersion ttl 的作用是 当缓存不存在时 使用ttl修复缓存
func (r *authRepo) GetUserVersion(ctx context.Context, userId string, ttl time.Duration) (int, error) {
	l := log.NewHelper(log.WithContext(ctx, r.log.Logger()))
	key := GetRedisKey("user_version", userId)
	val, err := r.data.redis.Get(ctx, key).Result()
	if errors.Is(err, redis.Nil) {
		// 该情况可能是服务器重启后缓存丢失导致的，理论上不应该发生
		l.Errorf("Get user Version not found, which shouldn't be possible.")

		collection := r.userCollection
		filter := bson.M{"_id": userId}

		var result struct {
			Version   int        `bson:"version"`
			DeletedAt *time.Time `bson:"deleted_at"`
		}
		err := collection.FindOne(ctx, filter).Decode(&result)
		if err != nil {
			if errors.Is(err, mongo.ErrNoDocuments) {
				return 1<<31 - 1, biz.UserNotFoundError
			}
			l.Errorf("failed to find user: %v", err)
			return 1<<31 - 1, fmt.Errorf("failed to find user: %w", err)
		} else if result.DeletedAt != nil {
			return 1<<31 - 1, biz.UserHasBeenDeletedError
		}
		err = r.AddOrUpdateUserVersion(ctx, userId, result.Version, ttl)
		if err != nil {
			l.Errorf("AddOrUpdateUserVersion error: %v", err)
		}
		return result.Version, nil
	} else if err != nil {
		l.Errorf("Get user Version error: %v", err)
		return 0, fmt.Errorf("failed to get user Version: %w", err)
	}
	version, err := strconv.Atoi(val)
	if err != nil {
		l.Errorf("Atoi user Version error: %v", err)
		return 0, fmt.Errorf("failed to parse user Version: %w", err)
	}
	return version, nil
}
