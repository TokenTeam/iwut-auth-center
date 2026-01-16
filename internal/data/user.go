package data

import (
	"context"
	"errors"
	"fmt"
	"iwut-auth-center/internal/biz"
	"iwut-auth-center/internal/conf"
	"iwut-auth-center/internal/util"
	"time"

	kratosErrors "github.com/go-kratos/kratos/v2/errors"
	"github.com/go-kratos/kratos/v2/log"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type userRepo struct {
	data                         *Data
	log                          *log.Helper
	appUsecase                   *biz.AppUsecase
	userCollection               *mongo.Collection
	userConsentsCollection       *mongo.Collection
	sha256Util                   *util.Sha256Util
	officialInfoMemoryLimitation int64
}

func NewUserRepo(data *Data, c *conf.Data, logger log.Logger, appUsecase *biz.AppUsecase, sha256Util *util.Sha256Util) biz.UserRepo {
	dbName := c.GetMongodb().GetDatabase()
	usersCollection := data.mongo.Database(dbName).Collection("user")
	userConsentsCollection := data.mongo.Database(dbName).Collection("user_consents")
	return &userRepo{
		data:                         data,
		log:                          log.NewHelper(logger),
		appUsecase:                   appUsecase,
		userCollection:               usersCollection,
		userConsentsCollection:       userConsentsCollection,
		sha256Util:                   sha256Util,
		officialInfoMemoryLimitation: c.GetMongodb().GetLimitations().GetUser().GetOfficialMemLimit(),
	}
}

// UpdateUserPassword verifies the provided oldPassword and updates it to newPassword.
// Behavior:
//   - Converts userId from hex to ObjectID; returns an error if invalid.
//   - Hashes oldPassword/newPassword using sha256Util before DB operations.
//   - Finds a document matching {_id: uid, password: oldHashed} and checks deleted_at.
//   - If found, updates the password, updated_at and bumps the `Version` using
//     util.NextJWTVersion to invalidate previous tokens/caches.
//   - Uses a short (5s) context timeout for DB calls.
//
// Parameters:
// - ctx: context for cancellation/timeouts.
// - userId: hex string representation of MongoDB ObjectID.
// - oldPassword/newPassword: plain-text passwords.
// Returns:
//   - error: biz.UserNotFoundError when credentials don't match; biz.UserHasBeenDeletedError
//     when the user is soft-deleted; wrapped errors for other failures.
//
// Edge cases:
//   - If the userId is not a valid hex ObjectID, returns a formatted error.
//   - The update is optimistic: it matches the old hashed password to prevent
//     blind overwrites.
func (r *userRepo) UpdateUserPassword(ctx context.Context, userId string, oldPassword string, newPassword string) error {
	l := log.NewHelper(log.WithContext(ctx, r.log.Logger()))

	uid, err := primitive.ObjectIDFromHex(userId)
	if err != nil {
		l.Errorf("invalid userId format: %s", userId)
		return fmt.Errorf("invalid userId format: %s", userId)
	}
	oldPassword = r.sha256Util.HashPassword(oldPassword)
	newPassword = r.sha256Util.HashPassword(newPassword)
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	l.Debugf("UpdateUserPassword called with UserId: %s", userId)

	collection := r.userCollection
	filter := bson.M{"_id": uid, "password": oldPassword}

	var result struct {
		Version   int        `bson:"Version"`
		DeletedAt *time.Time `bson:"deleted_at"`
	}
	err = collection.FindOne(ctx, filter).Decode(&result)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return biz.UserNotFoundError
		}
		l.Errorf("failed to find user: %v", err)
		return fmt.Errorf("failed to find user: %w", err)
	} else if result.DeletedAt != nil {
		return biz.UserHasBeenDeletedError
	}
	update := bson.M{
		"$set": bson.M{
			"password":   newPassword,
			"updated_at": time.Now(),
			"Version":    util.NextJWTVersion(result.Version),
		},
	}
	_, err = collection.UpdateOne(ctx, filter, update)
	if err != nil {
		l.Errorf("failed to update user password: %v", err)
		return fmt.Errorf("failed to update user password: %w", err)
	}
	return nil
}

// DeleteUserAccount marks the user document as deleted (soft delete).
// Behavior:
// - Converts userId to ObjectID; returns an error for invalid format.
// - Fetches the existing document and checks if it's already deleted.
// - Sets `deleted_at` and `updated_at` to now and bumps `Version` to invalidate tokens.
// - Uses a 5s timeout for DB operations.
// Parameters:
// - ctx: context for cancellation/timeouts.
// - userId: hex string of the user's ObjectID.
// Returns:
//   - error: biz.UserNotFoundError if user doesn't exist; biz.UserHasBeenDeletedError
//     if already deleted; wrapped errors on DB failures.
func (r *userRepo) DeleteUserAccount(ctx context.Context, userId string) error {
	l := log.NewHelper(log.WithContext(ctx, r.log.Logger()))

	uid, err := primitive.ObjectIDFromHex(userId)
	if err != nil {
		l.Errorf("invalid userId format: %s", userId)
		return fmt.Errorf("invalid userId format: %s", userId)
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	l.Debugf("DeleteUserAccount called with UserId: %s", userId)

	collection := r.userCollection
	filter := bson.M{"_id": uid}

	var result struct {
		DeletedAt *time.Time `bson:"deleted_at"`
		Version   int        `bson:"Version"`
	}
	err = collection.FindOne(ctx, filter).Decode(&result)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return biz.UserNotFoundError
		}
		l.Errorf("failed to find user: %v", err)
		return fmt.Errorf("failed to find user: %w", err)
	} else if result.DeletedAt != nil {
		return biz.UserHasBeenDeletedError
	}

	now := time.Now()
	update := bson.M{
		"$set": bson.M{
			"deleted_at": now,
			"updated_at": now,
			"Version":    util.NextJWTVersion(result.Version),
		},
	}
	_, err = collection.UpdateOne(ctx, filter, update)
	if err != nil {
		l.Errorf("failed to delete user account: %v", err)
		return fmt.Errorf("failed to delete user account: %w", err)
	}
	return nil
}

// GetUserProfileById returns a UserProfile assembled from the `user` document.
// Behavior:
//   - Converts userId to ObjectID and aggregates the document to construct an `official`
//     map by picking fields that start with "official__" and stripping the prefix.
//   - Returns email, created_at, updated_at and the official attributes as a map.
//   - Handles Mongo types (primitive.ObjectID, primitive.DateTime) and validates types
//     before conversion; returns errors if unexpected types are encountered.
//   - Uses a 5s DB timeout for the aggregation.
//
// Parameters:
// - ctx: context for cancellation/timeouts.
// - userId: hex string of the user's ObjectID.
// Returns:
// - *biz.UserProfile: populated profile when the user exists (OfficialAttrs may be empty).
// - error: biz.UserNotFoundError if not found; wrapped errors for DB/decoding issues.
func (r *userRepo) GetUserProfileById(ctx context.Context, userId string) (*biz.UserProfile, error) {
	l := log.NewHelper(log.WithContext(ctx, r.log.Logger()))

	uid, err := primitive.ObjectIDFromHex(userId)
	if err != nil {
		l.Errorf("invalid userId format: %s", userId)
		return nil, fmt.Errorf("invalid userId format: %s", userId)
	}

	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	l.Debugf("GetUserProfileById called with UserId: %s", userId)

	collection := r.userCollection
	pipeline := mongo.Pipeline{
		// 匹配用户
		{{"$match", bson.D{{"_id", uid}}}},
		// 构造 official（去掉前缀），并保留常用字段
		{{"$project", bson.D{
			{"official", bson.D{
				{"$arrayToObject", bson.D{
					{"$map", bson.D{
						{"input", bson.D{
							{"$filter", bson.D{
								{"input", bson.D{{"$objectToArray", "$$ROOT"}}},
								{"as", "kv"},
								{"cond", bson.D{{"$regexMatch", bson.D{
									{"input", "$$kv.k"},
									{"regex", "^official__"},
								}}}},
							}},
						}},
						{"as", "kv"},
						{"in", bson.D{
							{
								"k", bson.D{{"$substrCP",
									bson.A{
										"$$kv.k", len("official__"),
										bson.D{
											{"$subtract", bson.A{
												bson.D{{"$strLenCP", "$$kv.k"}}, len("official__")},
											},
										},
									},
								}},
							},
							{"v", "$$kv.v"},
						}},
					}},
				}},
			}},
			{"_id", 1},
			{"email", 1},
			{"created_at", 1},
			{"updated_at", 1},
		}}},
	}
	cur, err := collection.Aggregate(ctx, pipeline)
	if err != nil {
		l.Errorf("failed to aggregate user profile: %v", err)
		return nil, fmt.Errorf("failed to aggregate user profile: %w", err)
	}
	defer func(cur *mongo.Cursor, ctx context.Context) {
		err := cur.Close(ctx)
		if err != nil {
			l.Errorf("failed to close cursor: %v", err)
		}
	}(cur, ctx)

	if !cur.Next(ctx) {
		if err := cur.Err(); err != nil {
			l.Errorf("cursor error: %v", err)
			return nil, fmt.Errorf("cursor error: %w", err)
		}
		return nil, biz.UserNotFoundError
	}

	var doc bson.M
	if err := cur.Decode(&doc); err != nil {
		l.Errorf("decode error: %v", err)
		return nil, fmt.Errorf("decode error: %w", err)
	}
	userProfile := biz.UserProfile{
		OfficialAttrs: map[string]string{},
	}

	if userId, ok := doc["_id"].(primitive.ObjectID); ok {
		userProfile.UserId = userId.Hex()
	} else {
		return nil, fmt.Errorf("invalid userId format in db")
	}
	if email, ok := doc["email"].(string); ok {
		userProfile.Email = email
	} else {
		return nil, fmt.Errorf("invalid email format in db")
	}
	if createdAt, ok := doc["created_at"].(primitive.DateTime); ok {
		userProfile.CreatedAt = createdAt.Time().Unix()
	} else {
		return nil, fmt.Errorf("invalid created_at format in db")
	}
	if updatedAt, ok := doc["updated_at"].(primitive.DateTime); ok {
		userProfile.UpdatedAt = updatedAt.Time().Unix()
	} else {
		return nil, fmt.Errorf("invalid updated_at format in db")
	}

	official, ok := doc["official"].(bson.M)
	if !ok {
		return &userProfile, nil
	}
	for k, v := range official {
		strValue, ok := v.(string)
		if !ok {
			continue
		}
		userProfile.OfficialAttrs[k] = strValue
	}
	return &userProfile, nil
}

// UpdateUserProfile updates/sets official__* attributes on the user document.
// Behavior:
//   - Validates userId and that the total size of provided attrs does not exceed
//     the configured memory limitation (officialInfoMemoryLimitation).
//   - Verifies the user exists and is not deleted, then sets updated_at and the
//     provided `official__<key>` fields atomically with $set.
//
// Parameters:
// - ctx: context for cancellation/timeouts.
// - userId: hex string of the user's ObjectID.
// - attrs: map of key->value which will be stored under fields prefixed by `official__`.
// Returns:
//   - error: biz.UserNotFoundError if user missing; biz.OfficialInfoMemoryLimitationExceededError
//     if the attrs exceed configured limit; wrapped DB errors for other failures.
func (r *userRepo) UpdateUserProfile(ctx context.Context, userId string, attrs map[string]string) error {
	l := log.NewHelper(log.WithContext(ctx, r.log.Logger()))

	uid, err := primitive.ObjectIDFromHex(userId)
	if err != nil {
		l.Errorf("invalid userId format: %s", userId)
		return fmt.Errorf("invalid userId format: %s", userId)
	}

	if count := int64(func(m map[string]string) int {
		total := 0
		for k, v := range m {
			total += len(k) + len(v)
		}
		return total
	}(attrs)); count > r.officialInfoMemoryLimitation {
		l.Errorf("official info memory limitation exceeded: %d > %d", count, r.officialInfoMemoryLimitation)
		return biz.OfficialInfoMemoryLimitationExceededError
	}

	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	l.Debugf("UpdateUserProfile called with UserId: %s", userId)

	collection := r.userCollection
	filter := bson.M{"_id": uid}

	// 这个判断不是必要的 这种情况不太可能出现
	var result struct {
		DeletedAt *time.Time `bson:"deleted_at"`
	}
	err = collection.FindOne(ctx, filter).Decode(&result)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return biz.UserNotFoundError
		}
		l.Errorf("failed to find user: %v", err)
		return fmt.Errorf("failed to find user: %w", err)
	} else if result.DeletedAt != nil {
		return biz.UserHasBeenDeletedError
	}

	set := bson.M{
		"updated_at": time.Now(),
	}
	for k, v := range attrs {
		set["official__"+k] = v
	}
	update := bson.M{
		"$set": set,
	}
	_, err = collection.UpdateOne(ctx, filter, update)
	if err != nil {
		l.Errorf("failed to update user profile: %v", err)
		return fmt.Errorf("failed to update user profile: %w", err)
	}
	return nil
}

// GetUserProfileKeysById returns the list of keys under `official__*` for a user.
// Behavior:
//   - Uses an aggregation pipeline to extract the document's keys that start with
//     the prefix "official__" and returns those keys with the prefix removed.
//   - Returns a structure containing BaseKeys (fixed list) and ExtraProfileKeys
//     (derived from the document).
//   - If the user doesn't exist, returns biz.UserNotFoundError.
//
// Parameters:
// - ctx: context for cancellation/timeouts.
// - userId: hex string of the user's ObjectID.
// Returns:
// - *biz.UserProfileKeys: contains BaseKeys and any ExtraProfileKeys found.
// - error: biz.UserNotFoundError when not found; wrapped errors for DB failures.
func (r *userRepo) GetUserProfileKeysById(ctx context.Context, userId string) (*biz.UserProfileKeys, error) {
	l := log.NewHelper(log.WithContext(ctx, r.log.Logger()))

	uid, err := primitive.ObjectIDFromHex(userId)
	if err != nil {
		l.Errorf("invalid userId format: %s", userId)
		return nil, fmt.Errorf("invalid userId format: %s", userId)
	}

	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	l.Debugf("GetUserProfileKeysById called with UserId: %s", userId)

	prefix := "official__"
	collection := r.userCollection
	pipeline := mongo.Pipeline{
		{{"$match", bson.D{{"_id", uid}}}},
		{{"$project", bson.D{
			{"keys", bson.D{
				{"$map", bson.D{
					// 先过滤出以 official__ 开头的键
					{"input", bson.D{
						{"$filter", bson.D{
							{"input", bson.D{{"$objectToArray", "$$ROOT"}}},
							{"as", "kv"},
							{"cond", bson.D{{"$regexMatch", bson.D{
								{"input", "$$kv.k"},
								{"regex", "^" + prefix},
							}}}},
						}},
					}},
					{"as", "kv"},
					// 只保留 key
					{"in", "$$kv.k"},
				}},
			}},
		}}},
	}
	cur, err := collection.Aggregate(ctx, pipeline)
	if err != nil {
		l.Errorf("failed to aggregate error: %v", err)
		return nil, fmt.Errorf("aggregate error: %w", err)
	}

	defer func(cur *mongo.Cursor, ctx context.Context) {
		err := cur.Close(ctx)
		if err != nil {
			l.Errorf("failed to close cursor: %v", err)
		}
	}(cur, ctx)

	if !cur.Next(ctx) {
		if err := cur.Err(); err != nil {
			l.Errorf("cursor error: %v", err)
			return nil, fmt.Errorf("cursor error: %w", err)
		}
		// 找不到用户
		return nil, biz.UserNotFoundError
	}

	var doc struct {
		Keys []string `bson:"keys"`
	}
	if err := cur.Decode(&doc); err != nil {
		return nil, fmt.Errorf("decode error: %w", err)
	}

	res := make([]string, 0, len(doc.Keys))
	for _, k := range doc.Keys {
		if len(k) >= len(prefix) && k[:len(prefix)] == prefix {
			res = append(res, k[len(prefix):])
		}
	}
	return &biz.UserProfileKeys{
		BaseKeys:         []string{"userId", "email", "created_at", "updated_at"},
		ExtraProfileKeys: res,
	}, nil
}

// UpdateUserConsent records or updates the user's consent for a client application.
// Behavior:
//   - Validates userId and that the user exists and is not deleted.
//   - Fetches client info via appUsecase.Repo.GetClientInfo and verifies the client
//     exists and the provided clientVersion matches the client metadata.
//   - Validates that each provided optional scope is allowed by the client's
//     configured OptionalScope. If invalid, returns a BadRequest error.
//   - Upserts a document into `user_consents` keyed by {user_id, client_id}
//     storing optional_scope, granted_at and agreed_version.
//
// Parameters:
// - ctx: context for cancellation/timeouts.
// - userId: hex string of the user's ObjectID.
// - clientId: client identifier.
// - clientVersion: version string to validate against the client's metadata.
// - optionalScopes: list of optional scopes the user agreed to.
// Returns:
//   - error: biz.UserNotFoundError if user missing; kratos BadRequest/InternalServer
//     errors for invalid client/version or scope; wrapped DB errors for write failures.
func (r *userRepo) UpdateUserConsent(ctx context.Context, userId string, clientId string, clientVersion string, optionalScopes []string) error {
	l := log.NewHelper(log.WithContext(ctx, r.log.Logger()))

	uid, err := primitive.ObjectIDFromHex(userId)
	if err != nil {
		l.Errorf("invalid userId format: %s", userId)
		return fmt.Errorf("invalid userId format: %s", userId)
	}

	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	l.Debugf("UpdateUserConsent called with UserId: %s", userId)

	collection := r.userCollection
	filter := bson.M{"_id": uid}

	// 这个判断不是必要的 这种情况不太可能出现
	var result struct {
		DeletedAt *time.Time `bson:"deleted_at"`
	}
	err = collection.FindOne(ctx, filter).Decode(&result)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return biz.UserNotFoundError
		}
		l.Errorf("failed to find user: %v", err)
		return fmt.Errorf("failed to find user: %w", err)
	} else if result.DeletedAt != nil {
		return biz.UserHasBeenDeletedError
	}

	clientInfo, err := r.appUsecase.Repo.GetClientInfo(ctx, clientId)
	if err != nil {
		l.Errorf("failed to get client info: %v", err)
		return err
	}
	if clientInfo == nil {
		l.Errorf("client not found: %s", clientId)
		return kratosErrors.InternalServer("", "client not found with no error: "+clientId)
	}
	if clientInfo.Version != clientVersion {
		l.Errorf("client version mismatch: %s != %s", clientInfo.Version, clientVersion)
		return kratosErrors.BadRequest("", "client version mismatch: "+clientVersion)
	}
	scopeSet := make(map[string]struct{}, len(clientInfo.OptionalScope))
	for _, v := range clientInfo.OptionalScope {
		scopeSet[v] = struct{}{}
	}
	for _, v := range optionalScopes {
		if _, ok := scopeSet[v]; !ok {
			l.Errorf("invalid optional scope: %s", v)
			return kratosErrors.BadRequest("", "invalid optional scope: "+v)
		}
	}

	collection = r.userConsentsCollection
	filter = bson.M{"user_id": userId, "client_id": clientId}

	update := bson.M{
		"$set": bson.M{
			"optional_scope": optionalScopes,
			"granted_at":     time.Now(),
			"agreed_version": clientInfo.Version,
		},
	}
	opts := options.Update().SetUpsert(true)
	_, err = collection.UpdateOne(ctx, filter, update, opts)
	if err != nil {
		l.Errorf("failed to update user consent: %v", err)
		return err
	}
	return nil
}
