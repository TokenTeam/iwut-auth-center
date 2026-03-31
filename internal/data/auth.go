package data

import (
	"context"
	"fmt"
	v1 "iwut-auth-center/api/gen/go/auth_center/v1/error_reason"
	"iwut-auth-center/internal/biz"
	"iwut-auth-center/internal/conf"
	"iwut-auth-center/internal/util"
	"strconv"
	"time"

	"github.com/go-kratos/kratos/v2/errors"
	"github.com/go-kratos/kratos/v2/log"
	"github.com/go-redis/redis/v8"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
)

type authRepo struct {
	data                *Data
	log                 *log.Helper
	userCollection      *mongo.Collection
	sha256Util          *util.Sha256Util
	accessTokenLifeSpan time.Duration
}

func NewAuthRepo(data *Data, c *conf.Data, cj *conf.Jwt, logger log.Logger, sha256Util *util.Sha256Util) biz.AuthRepo {
	dbName := c.GetMongodb().GetDatabase()
	usersCollection := data.mongo.Database(dbName).Collection("user")
	return &authRepo{
		data:                data,
		log:                 log.NewHelper(logger),
		userCollection:      usersCollection,
		sha256Util:          sha256Util,
		accessTokenLifeSpan: time.Duration(cj.GetAccessTokenLifeSpan()) * time.Second,
	}
}

// CheckPasswordWithEmailAndGetUserIdAndVersion verifies the provided password for
// the user with the given email, and returns the user's ID and version on success.
// Behavior:
//   - The provided plain password is hashed with the repo's sha256 util before
//     querying the MongoDB `user` collection for a document matching {email, password}.
//   - If no document is found, it returns v1.ErrorReason_USER_NOT_FOUND.
//   - If a matching user has a deleted_at timestamp, attempt to restore the user
//     when the deletion is within a 30-day recovery window by clearing deleted_at
//     and updating updated_at; if restore fails return an error. If the deletion is
//     older than 30 days, return v1.ErrorReason_USER_DELETED.
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
		UserId    string     `bson:"uid"`
		Version   int        `bson:"version"`
		DeletedAt *time.Time `bson:"deleted_at"`
	}
	err := collection.FindOne(ctx, filter).Decode(&result)

	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return "", -1, errors.NotFound(v1.ErrorReason_USER_NOT_FOUND.String(), "user not found")
		}
		l.Errorf("failed to find user: %v", err)
		return "", -1, fmt.Errorf("failed to find user: %w", err)
	}
	if result.DeletedAt != nil {
		if success, err := r.TryRestoreDeletedUser(ctx, result.UserId, result.DeletedAt); err != nil || !success {
			if err != nil {
				l.Error("failed to restore deleted user: %v", err)
				return "", -1, fmt.Errorf("failed to restore deleted user: %w", err)
			}
			return "", -1, errors.New(410, v1.ErrorReason_USER_DELETED.String(), "user has been deleted")
		}
	}

	return result.UserId, result.Version, nil
}

func (r *authRepo) GetDeveloperIdByUserId(ctx context.Context, uid string) (*string, error) {
	l := log.NewHelper(log.WithContext(ctx, r.log.Logger()))

	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	l.Debugf("GetDeveloperIdByUserId called with userId: %s", uid)
	collection := r.userCollection
	filter := bson.M{"uid": uid}

	// Decode into a nested struct so we can read claim.developer_id correctly.
	var result struct {
		Claim struct {
			DeveloperId *string `bson:"developer_id"`
		} `bson:"claim"`
		DeletedAt *time.Time `bson:"deleted_at"`
	}
	if err := collection.FindOne(ctx, filter).Decode(&result); err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return nil, errors.NotFound(v1.ErrorReason_USER_NOT_FOUND.String(), "user not found")
		}
		l.Errorf("failed to find user: %v", err)
		return nil, fmt.Errorf("failed to find user: %w", err)
	}
	if result.DeletedAt != nil {
		if success, err := r.TryRestoreDeletedUser(ctx, uid, result.DeletedAt); err != nil || !success {
			if err != nil {
				l.Error("failed to restore deleted user: %v", err)
				return nil, fmt.Errorf("failed to restore deleted user: %w", err)
			}
			return nil, errors.New(410, v1.ErrorReason_USER_DELETED.String(), "user has been deleted")
		}
	}
	return result.Claim.DeveloperId, nil
}

func (r *authRepo) TryRestoreDeletedUser(ctx context.Context, uid string, deletedAt *time.Time) (bool, error) {
	l := log.NewHelper(log.WithContext(ctx, r.log.Logger()))
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	l.Debugf("TryRestoreDeletedUser called with userId: %s", uid)
	if deletedAt == nil {
		return false, fmt.Errorf("deletedAt is nil")
	}
	// 30 天内可以恢复
	if time.Since(*deletedAt) < 30*24*time.Hour {
		filter := bson.M{"uid": uid}
		update := bson.M{
			"$set": bson.M{
				"deleted_at": nil,
				"updated_at": time.Now(),
			},
		}
		_, err := r.userCollection.UpdateOne(ctx, filter, update)
		if err != nil {
			l.Errorf("failed to restore deleted user: %v", err)
			return false, fmt.Errorf("failed to restore deleted user: %w", err)
		}
	} else {
		return false, errors.New(410, v1.ErrorReason_USER_DELETED.String(), "user has been deleted")
	}
	return true, nil
}

// TryInsertRegisterCaptcha attempts to record a registration captcha for an email
// in Redis sorted set and enforces rate limiting.
// Behavior:
//   - Checks MongoDB user collection to ensure the email is not already registered;
//     if registered returns v1.ErrorReason_USER_ALREADY_EXISTS.
//   - Uses a Redis sorted set (key: register_captcha:<email>) where members are
//     captcha codes and score is the Unix timestamp when inserted.
//   - Retrieves the most recent score to enforce a minimum interval (1 minute)
//     between captcha requests for the same email; if too frequent returns
//     v1.ErrorReason_CAPTCHA_REQUEST_TOO_FREQUENTLY.
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
		return errors.Conflict(v1.ErrorReason_USER_ALREADY_EXISTS.String(), "user already exists")
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
			return errors.New(429, v1.ErrorReason_CAPTCHA_REQUEST_TOO_FREQUENTLY.String(), "asking captcha too frequently")
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

// TryInsertResetPasswordCaptcha attempts to record a password reset captcha for an email
// in Redis sorted set and enforces rate limiting.
// Behavior:
//   - Checks MongoDB user collection to ensure the email exists; if not, returns v1.ErrorReason_USER_NOT_FOUND.
//   - Uses a Redis sorted set (key: reset_password_captcha:<email>) where members are
//     captcha codes and score is the Unix timestamp when inserted.
//   - Retrieves the most recent score to enforce a minimum interval (1 minute)
//     between captcha requests for the same email; if too frequent returns
//     v1.ErrorReason_CAPTCHA_REQUEST_TOO_FREQUENTLY.
//   - Adds the new captcha as a member with current timestamp score, trims old
//     entries older than ttl via ZRemRangeByScore, and sets the key's TTL.
//
// Parameters:
// - ctx: context for cancellation.
// - email: email the captcha is for.
// - captcha: the captcha code to store as the member string.
// - ttl: time-to-live for captcha entries (used for trimming and key expiry).
// Returns:
//   - error: non-nil if Redis operations fail or rate limit / existence rules are violated.
func (r *authRepo) TryInsertResetPasswordCaptcha(ctx context.Context, email string, captcha string, ttl time.Duration) error {
	l := log.NewHelper(log.WithContext(ctx, r.log.Logger()))
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	l.Debugf("TryInsertResetPasswordCaptcha called with email: %s", email)

	// 首先检查 MongoDB 中是否存在该 email 对应的账号
	collection := r.userCollection
	filter := bson.M{"email": email}

	count, err := collection.CountDocuments(ctx, filter)
	if err != nil {
		l.Errorf("CountDocuments error: %v", err)
		return fmt.Errorf("failed to count documents: %w", err)
	}
	if count == 0 {
		return errors.NotFound(v1.ErrorReason_USER_NOT_FOUND.String(), "user not found")
	}

	key := GetRedisKey("reset_password_captcha", email)
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
			return errors.New(429, v1.ErrorReason_CAPTCHA_REQUEST_TOO_FREQUENTLY.String(), "asking captcha too frequently")
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

// CheckRegisterCaptchaUsable verifies whether the provided captcha code for an email is
// currently usable (exists and within TTL).
// Behavior:
//   - Trims old entries older than ttl from the Redis sorted set to keep the set clean.
//   - Uses ZRank to check presence of the code; if Redis returns Nil it indicates
//     the code is not present and INVALID_CAPTCHA is returned.
//   - Other Redis errors are wrapped and returned.
//
// Parameters:
// - ctx: context for cancellation.
// - email: the email the captcha was issued for.
// - code: the captcha code to validate.
// - ttl: time-to-live used to determine which entries should be trimmed prior to check.
// Returns:
// - error: non-nil when captcha is not usable or on Redis errors.
func (r *authRepo) CheckRegisterCaptchaUsable(ctx context.Context, email string, code string, ttl time.Duration) error {
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
		return errors.BadRequest(v1.ErrorReason_INVALID_CAPTCHA.String(), "captcha not usable")
	} else if err != nil {
		l.Errorf("ZRank error: %v", err)
		return fmt.Errorf("redis zrank error: %w", err)
	}

	// 校验成功：删除该 key，使其它未使用的验证码均失效
	if err := r.data.redis.Del(ctx, key).Err(); err != nil {
		l.Errorf("Del captcha key error: %v", err)
		// 不阻塞正常流程，仍认为验证码可用
	}

	return nil
}

// CheckResetPasswordCaptchaUsable verifies whether the provided reset password captcha code
// for an email is currently usable (exists and within TTL).
// Behavior:
//   - Trims old entries older than ttl from the Redis sorted set to keep the set clean.
//   - Uses ZRank to check presence of the code; if Redis returns Nil it indicates
//     the code is not present and INVALID_CAPTCHA is returned.
//   - Other Redis errors are wrapped and returned.
//
// Parameters:
// - ctx: context for cancellation.
// - email: the email the captcha was issued for.
// - code: the captcha code to validate.
// - ttl: time-to-live used to determine which entries should be trimmed prior to check.
// Returns:
// - error: non-nil when captcha is not usable or on Redis errors.
func (r *authRepo) CheckResetPasswordCaptchaUsable(ctx context.Context, email string, code string, ttl time.Duration) error {
	l := log.NewHelper(log.WithContext(ctx, r.log.Logger()))
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	key := GetRedisKey("reset_password_captcha", email)

	// 清理早于有效期的旧条目（假设 expireAt 是该 captcha 类型的最终有效截止）
	cutoff := strconv.FormatInt(time.Now().Add(-ttl).Unix(), 10)
	if err := r.data.redis.ZRemRangeByScore(ctx, key, "-inf", cutoff).Err(); err != nil {
		// 记录但不阻塞正常流程
		l.Errorf("ZRemRangeByScore error: %v", err)
	}

	_, err := r.data.redis.ZRank(ctx, key, code).Result()
	if errors.Is(err, redis.Nil) {
		return errors.BadRequest(v1.ErrorReason_INVALID_CAPTCHA.String(), "captcha not usable")
	} else if err != nil {
		l.Errorf("ZRank error: %v", err)
		return fmt.Errorf("redis zrank error: %w", err)
	}

	// 校验成功：删除该 key，使其它未使用的验证码均失效
	if err := r.data.redis.Del(ctx, key).Err(); err != nil {
		l.Errorf("Del reset-password captcha key error: %v", err)
		// 不阻塞正常流程，仍认为验证码可用
	}
	return nil
}

// RegisterUser creates a new user document in MongoDB with the given email and
// hashed password. It returns the inserted document ID as a string on success.
// Behavior:
//   - Hashes the provided password using the repo's sha256 util before storing.
//   - Checks for existing users with the same email and returns
//     v1.ErrorReason_USER_ALREADY_EXISTS if present.
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
	uid := util.MustUUIDv7String()
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	l.Debugf("RegisterUser called with email: %s", email)

	// Build the document to insert. We use InsertOne so we only return the uid
	// when an actual insert happened. Rely on DB unique constraint to prevent
	// duplicates; catch duplicate-key error and return a friendly error.

	doc := bson.M{
		"uid":        uid,
		"email":      email,
		"password":   password,
		"created_at": time.Now(),
		"updated_at": time.Now(),
		"version":    0,
	}

	_, err := r.userCollection.InsertOne(ctx, doc)
	if err != nil {
		// If duplicate key error (11000) occurs, map to UserAlreadyExistsError.
		var we mongo.WriteException
		if errors.As(err, &we) {
			for _, e := range we.WriteErrors {
				if e.Code == 11000 {
					return "", errors.Conflict(v1.ErrorReason_USER_ALREADY_EXISTS.String(), "user already exists")
				}
			}
		}
		l.Errorf("failed to insert user: %v", err)
		return "", fmt.Errorf("failed to insert user: %w", err)
	}

	// Optionally, verify inserted id if needed. We return the generated uid.
	return uid, nil
}

func (r *authRepo) ResetPassword(ctx context.Context, email string, newPassword string) error {
	l := log.NewHelper(log.WithContext(ctx, r.log.Logger()))
	newPassword = r.sha256Util.HashPassword(newPassword)
	filter := bson.M{"email": email}
	var result struct {
		UserId  string `bson:"uid"`
		Version int    `bson:"version"`
	}
	err := r.userCollection.FindOne(ctx, filter).Decode(&result)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return errors.NotFound(v1.ErrorReason_USER_NOT_FOUND.String(), "user not found")
		}
		l.Errorf("failed to find user: %v", err)
		return fmt.Errorf("failed to find user: %w", err)
	}
	result.Version = util.NextJWTVersion(result.Version)
	update := bson.M{
		"$set": bson.M{
			"password":   newPassword,
			"version":    result.Version,
			"updated_at": time.Now(),
		},
	}
	res, err := r.userCollection.UpdateOne(ctx, filter, update)
	if err != nil {
		l.Errorf("failed to update user password: %v", err)
		return fmt.Errorf("failed to update user password: %w", err)
	}
	if res.MatchedCount == 0 {
		return errors.NotFound(v1.ErrorReason_USER_NOT_FOUND.String(), "user not found")
	}
	err = r.AddOrUpdateUserVersion(ctx, result.UserId, result.Version, r.accessTokenLifeSpan)
	if err != nil {
		l.Errorf("AddOrUpdateUserVersion error: %v", err)
		return fmt.Errorf("failed to update user version in redis: %w", err)
	}
	return nil
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
//   - If the user is not found, return v1.ErrorReason_USER_NOT_FOUND and a sentinel int.
//   - If the user has a deleted_at timestamp, return v1.ErrorReason_USER_DELETED.
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
func (r *authRepo) GetUserVersion(ctx context.Context, uid string, ttl time.Duration) (int, error) {
	l := log.NewHelper(log.WithContext(ctx, r.log.Logger()))
	key := GetRedisKey("user_version", uid)
	val, err := r.data.redis.Get(ctx, key).Result()
	if errors.Is(err, redis.Nil) {
		// 该情况可能是服务器重启后缓存丢失导致的，理论上不应该发生
		l.Errorf("Get user Version not found, which shouldn't be possible.")

		collection := r.userCollection
		filter := bson.M{"uid": uid}

		var result struct {
			Version   int        `bson:"version"`
			DeletedAt *time.Time `bson:"deleted_at"`
		}
		err = collection.FindOne(ctx, filter).Decode(&result)
		if err != nil {
			if errors.Is(err, mongo.ErrNoDocuments) {
				return 1<<31 - 1, errors.NotFound(v1.ErrorReason_USER_NOT_FOUND.String(), "user not found")
			}
			l.Errorf("failed to find user: %v", err)
			return 1<<31 - 1, fmt.Errorf("failed to find user: %w", err)
		} else if result.DeletedAt != nil {
			return 1<<31 - 1, errors.New(410, v1.ErrorReason_USER_DELETED.String(), "user has been deleted")
		}
		err = r.AddOrUpdateUserVersion(ctx, uid, result.Version, ttl)
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
