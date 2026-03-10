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
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

type userRepo struct {
	data                         *Data
	log                          *log.Helper
	appCenterUtil                *util.AppCenterUtil
	userCollection               *mongo.Collection
	userConsentsCollection       *mongo.Collection
	sha256Util                   *util.Sha256Util
	officialInfoMemoryLimitation int64
}

func NewUserRepo(data *Data, c *conf.Data, logger log.Logger, appCenterUtil *util.AppCenterUtil, sha256Util *util.Sha256Util) biz.UserRepo {
	dbName := c.GetMongodb().GetDatabase()
	usersCollection := data.mongo.Database(dbName).Collection("user")
	userConsentsCollection := data.mongo.Database(dbName).Collection("user_consents")
	return &userRepo{
		data:                         data,
		log:                          log.NewHelper(logger),
		appCenterUtil:                appCenterUtil,
		userCollection:               usersCollection,
		userConsentsCollection:       userConsentsCollection,
		sha256Util:                   sha256Util,
		officialInfoMemoryLimitation: c.GetMongodb().GetLimitations().GetUser().GetOfficialMemLimit() * 1024,
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
func (r *userRepo) UpdateUserPassword(ctx context.Context, uid string, oldPassword string, newPassword string) error {
	l := log.NewHelper(log.WithContext(ctx, r.log.Logger()))

	oldPassword = r.sha256Util.HashPassword(oldPassword)
	newPassword = r.sha256Util.HashPassword(newPassword)
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	l.Debugf("UpdateUserPassword called with UserId: %s", uid)

	collection := r.userCollection
	filter := bson.M{"uid": uid, "password": oldPassword}

	var result struct {
		Version   int        `bson:"version"`
		DeletedAt *time.Time `bson:"deleted_at"`
	}
	err := collection.FindOne(ctx, filter).Decode(&result)
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
			"version":    util.NextJWTVersion(result.Version),
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
func (r *userRepo) DeleteUserAccount(ctx context.Context, uid string) error {
	l := log.NewHelper(log.WithContext(ctx, r.log.Logger()))

	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	l.Debugf("DeleteUserAccount called with UserId: %s", uid)

	collection := r.userCollection
	filter := bson.M{"uid": uid}

	var result struct {
		DeletedAt *time.Time `bson:"deleted_at"`
		Version   int        `bson:"version"`
	}
	err := collection.FindOne(ctx, filter).Decode(&result)
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
			"version":    util.NextJWTVersion(result.Version),
		},
	}
	_, err = collection.UpdateOne(ctx, filter, update)
	if err != nil {
		l.Errorf("failed to delete user account: %v", err)
		return fmt.Errorf("failed to delete user account: %w", err)
	}
	return nil
}

// GetUserProfileByIdWithFilter is an extended version of GetUserProfileById that allows filtering official attributes by a provided list of keys.
// Behavior:
//   - Accepts an additional parameter `keys` which is a list of official attribute keys to include in the result.
//   - When `keys` is provided, only includes those keys in the OfficialAttrs map of the returned UserProfile.
//   - If `keys` is nil, behaves the same as GetUserProfileById and includes all official attributes.
//
// Parameters:
// - ctx: context for cancellation/timeouts.
// - uid: user identifier as a hex string.
// - keys: optional list of official attribute keys to include; if nil, includes all.
// Returns:
// - *biz.UserProfile: populated profile with filtered official attributes when the user exists.
// - error: biz.UserNotFoundError if the user doesn't exist; wrapped errors for DB/decoding issues.
func (r *userRepo) GetUserProfileByIdWithFilter(ctx context.Context, uid string, keys []string) (*biz.UserProfile, error) {
	l := log.NewHelper(log.WithContext(ctx, r.log.Logger()))

	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	l.Debugf("GetUserProfileByIdWithFilter called with UserId: %s", uid)

	collection := r.userCollection

	var doc bson.M
	proj := options.FindOne().SetProjection(bson.M{"profile": 1, "uid": 1, "email": 1, "created_at": 1, "updated_at": 1})
	if err := collection.FindOne(ctx, bson.M{"uid": uid}, proj).Decode(&doc); err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return nil, biz.UserNotFoundError
		}
		l.Errorf("failed to find user profile: %v", err)
		return nil, fmt.Errorf("failed to find user profile: %w", err)
	}
	return r.parseDocToUserProfile(uid, doc, keys)
}

func (r *userRepo) parseDocToUserProfile(uid string, doc bson.M, keys []string) (*biz.UserProfile, error) {
	l := log.NewHelper(log.WithContext(context.Background(), r.log.Logger()))
	var filterKeys map[string]any
	if keys != nil {
		filterKeys = make(map[string]any, len(keys))
		for _, k := range keys {
			filterKeys[k] = nil
		}
	}

	userProfile := biz.UserProfile{
		OfficialAttrs: map[string]string{},
	}

	if userIdVal, ok := doc["uid"].(string); ok {
		userProfile.UserId = userIdVal
	} else {
		return nil, fmt.Errorf("invalid userId format in db")
	}
	if email, ok := doc["email"].(string); ok {
		userProfile.Email = email
	} else {
		return nil, fmt.Errorf("invalid email format in db")
	}
	if createdAt, ok := doc["created_at"].(bson.DateTime); ok {
		userProfile.CreatedAt = createdAt.Time()
	} else {
		return nil, fmt.Errorf("invalid created_at format in db")
	}
	if updatedAt, ok := doc["updated_at"].(bson.DateTime); ok {
		userProfile.UpdatedAt = updatedAt.Time()
	} else {
		return nil, fmt.Errorf("invalid updated_at format in db")
	}

	// Extract profile fields. profile may be absent or not an object.
	if profileRaw, ok := doc["profile"]; ok {
		// If profile exists it MUST be bson.D per new requirement; otherwise return internal error
		if profileRaw == nil {
			// present but nil, treat as empty
		} else if profD, ok := profileRaw.(bson.D); ok {
			if filterKeys == nil {
				for _, kv := range profD {
					if strVal, ok := kv.Value.(string); ok {
						userProfile.OfficialAttrs[kv.Key] = strVal
					} else {
						log.Warnf("profile field has unexpected type for user %s: %T", uid, profileRaw)
					}
				}
			} else {
				for _, kv := range profD {
					if strVal, ok := kv.Value.(string); ok {
						if _, needed := filterKeys[kv.Key]; needed {
							userProfile.OfficialAttrs[kv.Key] = strVal
						}
					} else {
						log.Warnf("profile field has unexpected type for user %s: %T", uid, profileRaw)
					}
				}
			}
		} else {
			l.Errorf("profile field has unexpected type for user %s: %T", uid, profileRaw)
			return nil, kratosErrors.InternalServer("", fmt.Sprintf("invalid profile type for user %s: %T", uid, profileRaw))
		}
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
func (r *userRepo) UpdateUserProfile(ctx context.Context, uid string, attrs map[string]string) error {
	l := log.NewHelper(log.WithContext(ctx, r.log.Logger()))

	if count, err := func(m map[string]string) (int, error) {
		total := 0
		for k, v := range m {
			total += len(k) + len(v)
			if !util.IsASCIIAlphaNumDashUnderscore(k) {
				return 0, kratosErrors.BadRequest("", "invalid key format: "+k)
			}
		}
		return total, nil
	}(attrs); int64(count) > r.officialInfoMemoryLimitation || err != nil {
		if err != nil {
			l.Errorf("invalid attrs: %v", err)
			return err
		}
		l.Errorf("official info memory limitation exceeded: %d > %d", count, r.officialInfoMemoryLimitation)
		return biz.OfficialInfoMemoryLimitationExceededError
	}

	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	l.Debugf("UpdateUserProfile called with UserId: %s", uid)

	if err := r.UserExists(ctx, uid); err != nil {
		return err
	}

	set := bson.M{
		"updated_at": time.Now(),
	}
	for k, v := range attrs {
		set["profile."+k] = v
	}
	update := bson.M{
		"$set": set,
	}
	collection := r.userCollection
	filter := bson.M{"uid": uid}
	_, err := collection.UpdateOne(ctx, filter, update)
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
func (r *userRepo) GetUserProfileKeysById(ctx context.Context, uid string) (*biz.UserProfileKeys, error) {
	l := log.NewHelper(log.WithContext(ctx, r.log.Logger()))

	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	l.Debugf("GetUserProfileKeysById called with UserId: %s", uid)

	collection := r.userCollection
	// Read the `profile` sub-document and return its keys. If profile is missing
	// or not an object, return only the BaseKeys.
	var doc struct {
		Profile interface{} `bson:"profile"`
	}
	proj := options.FindOne().SetProjection(bson.M{"profile": 1})
	if err := collection.FindOne(ctx, bson.M{"uid": uid}, proj).Decode(&doc); err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return nil, biz.UserNotFoundError
		}
		l.Errorf("failed to find user profile keys: %v", err)
		return nil, fmt.Errorf("aggregate error: %w", err)
	}

	res := make([]string, 0)
	// If profile is absent (nil), just return empty ExtraProfileKeys. If present it MUST be bson.D.
	if doc.Profile == nil {
		// nothing to do
	} else if profD, ok := doc.Profile.(bson.D); ok {
		for _, kv := range profD {
			res = append(res, kv.Key)
		}
	} else {
		l.Errorf("profile field has unexpected type for user %s: %T", uid, doc.Profile)
		return nil, kratosErrors.InternalServer("", fmt.Sprintf("invalid profile type for user %s: %T", uid, doc.Profile))
	}

	return &biz.UserProfileKeys{
		BaseKeys:         []string{"userId", "email", "created_at", "updated_at"},
		ExtraProfileKeys: res,
	}, nil
}

// UpdateUserConsent records or updates the user's consent for a client application.
// Behavior:
//   - Validates userId and that the user exists and is not deleted.
//   - Fetches client info via appCenterUtil.Repo.GetApplicationInfo and verifies the client
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
func (r *userRepo) UpdateUserConsent(ctx context.Context, uid string, clientId string, clientVersion int32, status string, optionalScopes []string, doCheck bool) error {

	l := log.NewHelper(log.WithContext(ctx, r.log.Logger()))

	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	l.Debugf("UpdateUserConsent called with UserId: %s", uid)

	collection := r.userCollection

	if err := r.UserExists(ctx, uid); err != nil {
		return err
	}

	// 这里err需要进一步细分
	// 可预期的err 包括 用户不允许使用该应用 / 是否可使用该应用的该类型 / 版本不匹配
	// 其中 版本不匹配时 需要检查 看能否自动升级... 以及和前端进行再协调
	var applicationVersionInfo *util.ApplicationVersionInfo
	// 当且仅当oauth2 已经仔细检查过权限的情况下 为了节省性能 直接更新
	if doCheck {
		var allowed bool
		var err error

		allowed, applicationVersionInfo, err = r.appCenterUtil.GetApplicationVersionInfoWithUserCheck(ctx, clientId, uid, clientVersion)
		if err != nil {
			l.Errorf("failed to get client info: %v", err)
			return err
		}
		if applicationVersionInfo == nil {
			l.Errorf("client not found: %s", clientId)
			return kratosErrors.InternalServer("", "client not found with no error: "+clientId)
		}
		if !allowed {
			l.Errorf("user %s is not allowed to use client %s", uid, clientId)
		}
		scopeSet := make(map[string]struct{}, len(applicationVersionInfo.OptionalScope))
		for _, v := range applicationVersionInfo.OptionalScope {
			scopeSet[v] = struct{}{}
		}
		for _, v := range optionalScopes {
			if _, ok := scopeSet[v]; !ok {
				l.Errorf("invalid optional scope: %s", v)
				return kratosErrors.BadRequest("", "invalid optional scope: "+v)
			}
		}
		status = applicationVersionInfo.Status
	} else {
		applicationVersionInfo = &util.ApplicationVersionInfo{
			Status:          status,
			InternalVersion: clientVersion,
		}
	}

	collection = r.userConsentsCollection
	filter := bson.M{"user_id": uid, "client_id": clientId, "type": applicationVersionInfo.Status}

	update := bson.M{
		"$set": bson.M{
			"optional_scope": optionalScopes,
			"granted_at":     time.Now(),
			"agreed_version": applicationVersionInfo.InternalVersion,
		},
	}
	opts := options.UpdateOne().SetUpsert(true)
	_, err := collection.UpdateOne(ctx, filter, update, opts)
	if err != nil {
		l.Errorf("failed to update user consent: %v", err)
		return err
	}

	if applicationVersionInfo.Status == "STABLE" || applicationVersionInfo.Status == "GREY" {
		eraseStatus := "GREY"
		if applicationVersionInfo.Status == "GREY" {
			eraseStatus = "STABLE"
		}
		filter = bson.M{"user_id": uid, "client_id": clientId, "type": eraseStatus}
		err = collection.FindOneAndDelete(ctx, filter).Err()
		if err != nil {
			if errors.Is(err, mongo.ErrNoDocuments) {
				l.Debugf("no user consent found to erase for user %s and client %s with status %s", uid, clientId, eraseStatus)
				return nil
			}
			l.Errorf("failed to erase user consent: %v", err)
			return err
		}
	}

	return nil
}

func (r *userRepo) SetUserDeveloperId(ctx context.Context, uid string, developerId string) error {
	l := log.NewHelper(log.WithContext(ctx, r.log.Logger()))

	if developerId == "" {
		l.Errorf("developerId cannot be empty")
		return kratosErrors.BadRequest("", "developerId cannot be empty")
	}
	for c := range developerId {
		if !((developerId[c] >= 'a' && developerId[c] <= 'z') || (developerId[c] >= 'A' && developerId[c] <= 'Z') ||
			(developerId[c] >= '0' && developerId[c] <= '9') ||
			developerId[c] == '-' || developerId[c] == '_') {
			l.Errorf("invalid developerId format: %s", developerId)
			return kratosErrors.BadRequest("", "invalid developerId format: "+developerId)
		}
	}

	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	l.Debugf("SetUserDeveloperId called with UserId: %s", uid)

	if err := r.UserExists(ctx, uid); err != nil {
		return err
	}
	filter := bson.M{"uid": uid}
	var result struct {
		DeveloperId           *string    `bson:"claim.developer_id"`
		LastUpdateDeveloperId *time.Time `bson:"claim.developer_id_updated_at"`
	}
	err := r.userCollection.FindOne(ctx, filter).Decode(&result)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return biz.UserNotFoundError
		}
	}
	if result.DeveloperId != nil {
		if result.LastUpdateDeveloperId != nil {
			if time.Since(*result.LastUpdateDeveloperId) < 30*24*time.Hour {
				l.Infof("developerId can only be updated once every 30 days")
				return kratosErrors.BadRequest("", "developerId can only be updated once every 30 days")
			}
		} else {
			l.Errorf("missing developer_id_updated_at for user with existing developerId: %s", uid)
		}
	}

	update := bson.M{
		"$set": bson.M{
			"claim.developer_id":            developerId,
			"claim.developer_id_updated_at": time.Now(),
			"updated_at":                    time.Now(),
		},
	}
	_, err = r.userCollection.UpdateOne(ctx, bson.M{"uid": uid}, update)
	if err != nil {
		if isDuplicateKeyError(err) {
			// 返回业务友好错误（你可以定义 biz.DeveloperIdAlreadyExistsError）
			return kratosErrors.New(409, "", "developer id already in use")
		}
		l.Errorf("failed to set user developer id: %v", err)
		return fmt.Errorf("failed to set user developer id: %w", err)
	}
	return nil
}

// RevokeUserConsent
// 简介：原子性地撤销用户对某客户端的同意，清空 token_id 并从 Redis 中移除对应允许的 JTI。
// 行为说明：
// - 根据 status 决定操作范围：
//   - TEST：仅操作 type=TEST 的文档，清空其 token_id 并删除对应 Redis JTI。
//   - STABLE/GREY：操作所有 type 为 STABLE 或 GREY 的文档，清空 token_id 并删除对应 Redis JTI。
//   - 其他值：直接返回 InvalidArgument 错误。
//
// - 使用 FindOneAndUpdate（TEST）或 Find+BulkWrite（STABLE/GREY）原子地读取并清空 token_id。
// 参数：
// - ctx: 上下文，用于超时和取消控制。
// - userId: 用户标识。
// - clientId: 客户端标识。
// - status: 操作类型，仅接受 TEST / STABLE / GREY。
// 返回值：
// - error: 参数非法返回 InvalidArgument；找不到文档返回 NotFound；其他错误返回相应错误，成功返回 nil。
func (r *userRepo) RevokeUserConsent(ctx context.Context, userId string, clientId string, status string) error {
	l := log.NewHelper(log.WithContext(ctx, r.log.Logger()))

	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	l.Debugf("RevokeUserConsent userId: %s, clientId: %s, status: %s", userId, clientId, status)

	// 校验 status
	if status != "TEST" && status != "STABLE" && status != "GREY" {
		return kratosErrors.BadRequest("400", "invalid status, must be one of: TEST, STABLE, GREY")
	}

	collection := r.userConsentsCollection
	baseFilter := bson.M{
		"user_id":   userId,
		"client_id": clientId,
	}

	if status == "TEST" {
		// TEST：只操作 type=TEST 的单条文档
		filter := bson.M{
			"user_id":   userId,
			"client_id": clientId,
			"type":      "TEST",
		}
		update := bson.M{"$set": bson.M{"token_id": []string{}}}
		opts := options.FindOneAndUpdate().SetReturnDocument(options.Before)

		var oldDoc struct {
			TokenID []string `bson:"token_id"`
		}
		res := collection.FindOneAndUpdate(ctx, filter, update, opts)
		if err := res.Err(); err != nil {
			if errors.Is(err, mongo.ErrNoDocuments) {
				l.Errorf("RevokeUserConsent TEST FindOneAndUpdate no document: %v", err)
				return kratosErrors.NotFound("404", "user consent not found")
			}
			l.Errorf("RevokeUserConsent TEST FindOneAndUpdate error: %v", err)
			return err
		}
		if err := res.Decode(&oldDoc); err != nil {
			l.Errorf("RevokeUserConsent TEST decode error: %v", err)
			return err
		}

		if len(oldDoc.TokenID) > 0 {
			if err := r.RemoveOAuthJTIsFormRedis(ctx, oldDoc.TokenID); err != nil {
				l.Errorf("RevokeUserConsent TEST RemoveOAuthJTIsFormRedis error: %v", err)
				return err
			}
		}
		return nil
	}

	// STABLE / GREY：找出所有 type 为 STABLE 或 GREY 的文档，收集 JTI 后批量清空
	baseFilter["type"] = bson.M{"$in": []string{"STABLE", "GREY"}}

	cursor, err := collection.Find(ctx, baseFilter)
	if err != nil {
		l.Errorf("RevokeUserConsent STABLE/GREY Find error: %v", err)
		return err
	}
	defer func(cursor *mongo.Cursor, ctx context.Context) {
		_ = cursor.Close(ctx)
	}(cursor, ctx)

	var oldDocs []struct {
		ID      interface{} `bson:"_id"`
		TokenID []string    `bson:"token_id"`
	}
	if err := cursor.All(ctx, &oldDocs); err != nil {
		l.Errorf("RevokeUserConsent STABLE/GREY decode error: %v", err)
		return err
	}
	if len(oldDocs) == 0 {
		return kratosErrors.NotFound("404", "user consent not found")
	}

	// 收集所有需要删除的 JTI
	var allJTIs []string
	for _, doc := range oldDocs {
		allJTIs = append(allJTIs, doc.TokenID...)
	}

	// 批量清空 token_id
	ids := make([]interface{}, 0, len(oldDocs))
	for _, doc := range oldDocs {
		ids = append(ids, doc.ID)
	}
	_, err = collection.UpdateMany(ctx,
		bson.M{"_id": bson.M{"$in": ids}},
		bson.M{"$set": bson.M{"token_id": []string{}}},
	)
	if err != nil {
		l.Errorf("RevokeUserConsent STABLE/GREY UpdateMany error: %v", err)
		return err
	}

	// 删除 Redis 中对应的 JTI
	if len(allJTIs) > 0 {
		if err := r.RemoveOAuthJTIsFormRedis(ctx, allJTIs); err != nil {
			l.Errorf("RevokeUserConsent STABLE/GREY RemoveOAuthJTIsFormRedis error: %v", err)
			return err
		}
	}
	return nil
}

func isDuplicateKeyError(err error) bool {
	var mongoErr mongo.WriteException
	if errors.As(err, &mongoErr) {
		for _, we := range mongoErr.WriteErrors {
			if we.Code == 11000 {
				return true
			}
		}
	}
	return false
}

func (r *userRepo) UserExists(ctx context.Context, uid string) error {
	l := log.NewHelper(log.WithContext(ctx, r.log.Logger()))

	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	collection := r.userCollection
	filter := bson.M{"uid": uid}

	var result struct {
		DeletedAt *time.Time `bson:"deleted_at"`
	}
	err := collection.FindOne(ctx, filter).Decode(&result)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return biz.UserNotFoundError
		}
		l.Errorf("failed to find user: %v", err)
		return fmt.Errorf("failed to find user: %w", err)
	} else if result.DeletedAt != nil {
		return biz.UserHasBeenDeletedError
	}
	return nil
}

// RemoveOAuthJTIsFormRedis
// 简介：从 Redis 中删除给定的一组 JTI 对应的允许键，撤销允许。
// 行为说明：
// - 使用 Redis pipeline 批量执行 DEL 操作删除每个 allowed_tokens:<jti> 键。
// - 跳过空字符串。
// 参数：
// - ctx: 上下文。
// - jtis: 要删除的 JTI 列表。
// 返回值：
// - error: Redis 删除失败时返回错误，成功返回 nil。
func (r *userRepo) RemoveOAuthJTIsFormRedis(ctx context.Context, jtis []string) error {
	l := log.NewHelper(log.WithContext(ctx, r.log.Logger()))

	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	l.Debugf("RemoveOAuthJTIsFormRedis jtis: %+v", jtis)

	pipe := r.data.redis.Pipeline()
	for _, id := range jtis {
		if id == "" {
			continue
		}
		key := GetRedisKey("allowed_tokens", id)
		pipe.Del(ctx, key)
	}
	_, err := pipe.Exec(ctx)
	return err
}
