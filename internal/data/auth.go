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
	"go.mongodb.org/mongo-driver/mongo/options"
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

// CheckPasswordWithEmailAndGetUserIdAndVersion verifies the provided password for
// the user with the given email, and returns the user's ID and version on success.
// Behavior:
//   - The provided plain password is hashed with the repo's sha256 util before
//     querying the MongoDB `user` collection for a document matching {email, password}.
//   - If no document is found, it returns biz.UserNotFoundError.
//   - If a matching user has a deleted_at timestamp, attempt to restore the user
//     when the deletion is within a 30-day recovery window by clearing deleted_at
//     and updating updated_at; if restore fails return an error. If the deletion is
//     older than 30 days, return biz.UserHasBeenDeletedError.
//
// Parameters:
// - ctx: context for cancellation and timeouts.
// - email: user email to look up.
// - password: plain-text password to verify.
// Returns:
// - userId (hex string): the MongoDB object id as hex when validation succeeds.
// - version: integer version stored on the user document.
// - error: non-nil for validation failures, not-found, DB errors, or restore failures.
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

// TryInsertRegisterCaptcha attempts to record a registration captcha for an email
// in Redis sorted set and enforces rate limiting.
// Behavior:
//   - Checks MongoDB user collection to ensure the email is not already registered;
//     if registered returns biz.UserAlreadyExistsError.
//   - Uses a Redis sorted set (key: register_captcha:<email>) where members are
//     captcha codes and score is the Unix timestamp when inserted.
//   - Retrieves the most recent score to enforce a minimum interval (1 minute)
//     between captcha requests for the same email; if too frequent returns
//     biz.AskingCaptchaTooFrequentlyError.
//   - Adds the new captcha as a member with current timestamp score, trims old
//     entries older than ttl via ZRemRangeByScore, and sets the key's TTL.
//
// Parameters:
// - ctx: context for cancellation.
// - email: email the captcha is for.
// - captcha: the captcha code to store as the member string.
// - ttl: time-to-live for captcha entries (used for trimming and key expiry).
// Returns:
//   - error: non-nil if DB or Redis operations fail or rate limit / existence rules
//     are violated.
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
		return fmt.Errorf("failed to add captcha: %w", err)
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

// CheckCaptchaUsable verifies whether the provided captcha code for an email is
// currently usable (exists and within TTL).
// Behavior:
//   - Trims old entries older than ttl from the Redis sorted set to keep the set clean.
//   - Uses ZRank to check presence of the code; if Redis returns Nil it indicates
//     the code is not present and biz.CaptchaNotUsableError is returned.
//   - Other Redis errors are wrapped and returned.
//
// Parameters:
// - ctx: context for cancellation.
// - email: the email the captcha was issued for.
// - code: the captcha code to validate.
// - ttl: time-to-live used to determine which entries should be trimmed prior to check.
// Returns:
// - error: non-nil when captcha is not usable or on Redis errors.
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

// RegisterUser creates a new user document in MongoDB with the given email and
// hashed password. It returns the inserted document ID as a string on success.
// Behavior:
//   - Hashes the provided password using the repo's sha256 util before storing.
//   - Checks for existing users with the same email and returns
//     biz.UserAlreadyExistsError if present.
//   - Inserts a new document with created_at, updated_at and Version = 0.
//   - Converts the MongoDB InsertedID into a string (hex when ObjectID).
//
// Notes and edge cases:
//   - Concurrent registrations for the same email may still result in duplicates
//     if no unique index is enforced at the DB level; the application should ensure
//     a unique index on `email` to prevent races.
//
// Parameters:
// - ctx: context for cancellation.
// - email: user email to register.
// - password: plain-text password to hash and store.
// Returns:
// - id string: inserted document id formatted as a string.
// - error: non-nil on validation, DB errors, or other failures.
func (r *authRepo) RegisterUser(ctx context.Context, email string, password string) (string, error) {
	l := log.NewHelper(log.WithContext(ctx, r.log.Logger()))
	password = r.sha256Util.HashPassword(password)
	filter := bson.M{"email": email}
	update := bson.M{
		"$setOnInsert": bson.M{
			"email":      email,
			"password":   password,
			"created_at": time.Now(),
			"updated_at": time.Now(),
			"Version":    0,
		},
	}
	opt := options.Update().SetUpsert(true)
	res, err := r.userCollection.UpdateOne(ctx, filter, update, opt)
	if err != nil {
		// 仍然可能因并发插入产生 duplicate-key（极端 race），需要检查 err 的 11000
		var we mongo.WriteException
		if errors.As(err, &we) {
			for _, e := range we.WriteErrors {
				if e.Code == 11000 {
					return "", biz.UserAlreadyExistsError
				}
			}
		}
		l.Errorf("failed to upsert user: %v", err)
		return "", fmt.Errorf("failed to upsert user: %w", err)
	}

	// UpsertedID == nil：表示已经存在并被匹配（没有插入新文档）
	if res.UpsertedID == nil {
		return "", biz.UserAlreadyExistsError
	}

	var idStr string
	switch id := res.UpsertedID.(type) {
	case primitive.ObjectID:
		idStr = id.Hex()
	case string:
		idStr = id
	default:
		idStr = fmt.Sprintf("%v", id)
	}
	return idStr, nil
}

// AddOrUpdateUserVersion stores the user's version in Redis with a TTL.
// Behavior:
//   - Writes the provided integer `version` into Redis key user_version:<userId>
//     with the provided TTL to keep a cached version that can be used for
//     optimistic concurrency checks elsewhere in the application.
//
// Parameters:
// - ctx: context for cancellation.
// - userId: user identifier used to build the redis key.
// - version: integer version to cache.
// - ttl: TTL to set for the redis key.
// Returns:
// - error: non-nil if the Redis SET operation fails.
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

// GetUserVersion returns the cached version for a user. If the Redis cache is
// missing (redis.Nil), it queries MongoDB for the user's version, repopulates
// the cache with the provided ttl, and returns that value.
// Behavior:
// - Attempts to GET user_version:<userId> from Redis.
// - If the key is missing (redis.Nil):
//   - Query the MongoDB `user` collection for the document with _id == userId.
//   - If the user is not found, return biz.UserNotFoundError and a sentinel int.
//   - If the user has a deleted_at timestamp, return biz.UserHasBeenDeletedError.
//   - Otherwise, update the Redis cache with the found version using AddOrUpdateUserVersion.
//
// - If Redis returns another error, wrap and return it.
// - Converts the cached string value to int and returns it.
// Edge cases & notes:
//   - The function returns (1<<31 - 1) as the int value in combination with a
//     not-found or deleted error to provide a distinguishable sentinel; callers
//     should check the error first.
//   - The MongoDB query expects the `_id` to match `userId` as stored; if your
//     application stores ObjectIDs, you must ensure consistent typing or adapt
//     the lookup accordingly.
//
// Parameters:
// - ctx: context for cancellation.
// - userId: identifier of the user to look up.
// - ttl: ttl to use when repopulating the redis cache on a cache miss.
// Returns:
// - int: the cached or DB-derived version on success.
// - error: non-nil on redis/mongo errors or when user is not found / deleted.
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
		return 1<<31 - 1, fmt.Errorf("failed to get user Version: %w", err)
	}
	version, err := strconv.Atoi(val)
	if err != nil {
		l.Errorf("parse user Version error: %v", err)
		return 1<<31 - 1, fmt.Errorf("failed to parse user Version: %w", err)
	}
	return version, nil
}
