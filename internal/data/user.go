package data

import (
	"context"
	"fmt"
	v1 "iwut-auth-center/api/gen/go/auth_center/v1/error_reason"
	"iwut-auth-center/internal/biz"
	"iwut-auth-center/internal/conf"
	"iwut-auth-center/internal/util"
	"strings"
	"time"

	"github.com/go-kratos/kratos/v2/errors"
	"github.com/go-kratos/kratos/v2/log"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

type userRepo struct {
	data                   *Data
	log                    *log.Helper
	userCollection         *mongo.Collection
	userConsentsCollection *mongo.Collection
	sha256Util             *util.Sha256Util
}

func NewUserRepo(data *Data, c *conf.Data, logger log.Logger, sha256Util *util.Sha256Util) biz.UserRepo {
	dbName := c.GetMongodb().GetDatabase()
	usersCollection := data.mongo.Database(dbName).Collection("user")
	userConsentsCollection := data.mongo.Database(dbName).Collection("user_consents")
	return &userRepo{
		data:                   data,
		log:                    log.NewHelper(logger),
		userCollection:         usersCollection,
		userConsentsCollection: userConsentsCollection,
		sha256Util:             sha256Util,
	}
}

// ---- User CRUD ----

func (r *userRepo) UpdateUserPassword(ctx context.Context, uid string, oldPassword string, newPassword string) error {
	l := log.NewHelper(log.WithContext(ctx, r.log.Logger()))

	oldPassword = r.sha256Util.HashPassword(oldPassword)
	newPassword = r.sha256Util.HashPassword(newPassword)
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	l.Debugf("UpdateUserPassword called with UserID: %s", uid)

	collection := r.userCollection
	filter := bson.M{"uid": uid, "password": oldPassword}

	var result struct {
		Version   int        `bson:"version"`
		DeletedAt *time.Time `bson:"deleted_at"`
	}
	err := collection.FindOne(ctx, filter).Decode(&result)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return errors.NotFound(v1.ErrorReason_USER_NOT_FOUND.String(), "user not found")
		}
		l.Errorf("failed to find user: %v", err)
		return fmt.Errorf("failed to find user: %w", err)
	} else if result.DeletedAt != nil {
		return errors.New(410, v1.ErrorReason_USER_DELETED.String(), "user has been deleted")
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

func (r *userRepo) DeleteUserAccount(ctx context.Context, uid string) error {
	l := log.NewHelper(log.WithContext(ctx, r.log.Logger()))

	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	l.Debugf("DeleteUserAccount called with UserID: %s", uid)

	collection := r.userCollection
	filter := bson.M{"uid": uid}

	var result struct {
		DeletedAt *time.Time `bson:"deleted_at"`
		Version   int        `bson:"version"`
	}
	err := collection.FindOne(ctx, filter).Decode(&result)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return errors.NotFound(v1.ErrorReason_USER_NOT_FOUND.String(), "user not found")
		}
		l.Errorf("failed to find user: %v", err)
		return fmt.Errorf("failed to find user: %w", err)
	} else if result.DeletedAt != nil {
		return errors.New(410, v1.ErrorReason_USER_DELETED.String(), "user has been deleted")
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
			return errors.NotFound(v1.ErrorReason_USER_NOT_FOUND.String(), "user not found")
		}
		l.Errorf("failed to find user: %v", err)
		return fmt.Errorf("failed to find user: %w", err)
	} else if result.DeletedAt != nil {
		return errors.New(410, v1.ErrorReason_USER_DELETED.String(), "user has been deleted")
	}
	return nil
}

// ---- User Profile ----

func (r *userRepo) GetUserProfileWithFilter(ctx context.Context, uid string, keys []string) (*biz.UserProfile, error) {
	l := log.NewHelper(log.WithContext(ctx, r.log.Logger()))

	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	l.Debugf("GetUserProfileWithFilter called with UserID: %s", uid)

	collection := r.userCollection

	var doc bson.M
	proj := options.FindOne().SetProjection(bson.M{"profile": 1, "uid": 1, "email": 1, "created_at": 1, "updated_at": 1})
	if err := collection.FindOne(ctx, bson.M{"uid": uid}, proj).Decode(&doc); err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return nil, errors.NotFound(v1.ErrorReason_USER_NOT_FOUND.String(), "user not found")
		}
		l.Errorf("failed to find user profile: %v", err)
		return nil, fmt.Errorf("failed to find user profile: %w", err)
	}
	return r.parseDocToUserProfile(uid, doc, keys)
}

func (r *userRepo) parseDocToUserProfile(uid string, doc bson.M, keys []string) (*biz.UserProfile, error) {
	l := log.NewHelper(log.WithContext(context.Background(), r.log.Logger()))

	userProfile := biz.UserProfile{
		OfficialAttrs: map[string]any{},
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

	if _, ok := doc["profile"]; !ok {
		return &userProfile, nil
	}
	profileMap, err := util.ConvertBSONValueToGOType(doc["profile"])
	if err != nil {
		l.Errorf("failed to convert profile to type: %v", err)
		return nil, fmt.Errorf("failed to convert profile to type: %w", err)
	}
	if profileMap == nil {
		return &userProfile, nil
	}
	if _, ok := profileMap.(map[string]any); !ok {
		return nil, fmt.Errorf("profile field has unexpected type for user %s: %T", uid, profileMap)
	}
	if keys == nil {
		userProfile.OfficialAttrs = profileMap.(map[string]any)
		return &userProfile, nil
	}

	src := profileMap.(map[string]any)
	dst := map[string]any{}

	for _, key := range keys {
		parts := strings.Split(key, ".")
		val, found, err := getByPath(src, parts)
		if err != nil {
			return nil, fmt.Errorf("invalid key %q: %w", key, err)
		}
		if !found {
			continue
		}
		setByPath(dst, parts, val)
	}
	userProfile.OfficialAttrs = dst

	return &userProfile, nil
}

func getByPath(root map[string]any, parts []string) (any, bool, error) {
	cur := root
	for i, p := range parts {
		v, ok := cur[p]
		if !ok {
			return nil, false, nil
		}
		if i == len(parts)-1 {
			return v, true, nil
		}
		next, ok := v.(map[string]any)
		if !ok {
			return nil, false, fmt.Errorf("key %q is not an object", strings.Join(parts[:i+1], "."))
		}
		cur = next
	}
	return nil, false, nil
}

func setByPath(root map[string]any, parts []string, v any) {
	cur := root
	for i, p := range parts {
		if i == len(parts)-1 {
			cur[p] = v
			return
		}
		next, ok := cur[p].(map[string]any)
		if !ok || next == nil {
			next = map[string]any{}
			cur[p] = next
		}
		cur = next
	}
}

func (r *userRepo) UpdateUserProfile(ctx context.Context, uid string, profileFields map[string]any) error {
	l := log.NewHelper(log.WithContext(ctx, r.log.Logger()))

	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	l.Debugf("UpdateUserProfile called with UserID: %s", uid)

	set := bson.M{
		"updated_at": time.Now(),
	}
	for k, v := range profileFields {
		set["profile."+k] = v
	}
	update := bson.M{"$set": set}

	collection := r.userCollection
	filter := bson.M{"uid": uid}
	err := collection.FindOneAndUpdate(ctx, filter, update).Err()
	if err != nil {
		l.Errorf("failed to update user profile: %v", err)
		return fmt.Errorf("failed to update user profile: %w", err)
	}
	return nil
}

func (r *userRepo) GetUserProfileKeys(ctx context.Context, uid string) (*biz.UserProfileKeys, error) {
	l := log.NewHelper(log.WithContext(ctx, r.log.Logger()))

	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	l.Debugf("GetUserProfileKeys called with UserID: %s", uid)

	collection := r.userCollection
	var doc struct {
		Profile interface{} `bson:"profile"`
	}
	proj := options.FindOne().SetProjection(bson.M{"profile": 1})
	if err := collection.FindOne(ctx, bson.M{"uid": uid}, proj).Decode(&doc); err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return nil, errors.NotFound(v1.ErrorReason_USER_NOT_FOUND.String(), "user not found")
		}
		l.Errorf("failed to find user profile keys: %v", err)
		return nil, fmt.Errorf("aggregate error: %w", err)
	}

	res := make([]string, 0)
	if doc.Profile == nil {
		// nothing to do
	} else if profD, ok := doc.Profile.(bson.D); ok {
		for _, kv := range profD {
			res = append(res, kv.Key)
		}
	} else {
		l.Errorf("profile field has unexpected type for user %s: %T", uid, doc.Profile)
		return nil, fmt.Errorf("profile field has unexpected type for user %s: %T", uid, doc.Profile)
	}

	return &biz.UserProfileKeys{
		BaseKeys:         []string{"userId", "email", "created_at", "updated_at"},
		ExtraProfileKeys: res,
	}, nil
}

func (r *userRepo) GetUserClaimsWithFilter(ctx context.Context, uid string, keys []string) (map[string]any, error) {
	l := log.NewHelper(log.WithContext(ctx, r.log.Logger()))
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	l.Debugf("GetUserClaimsWithFilter called with UserID: %s", uid)

	collection := r.userCollection
	var doc bson.M
	proj := options.FindOne().SetProjection(bson.M{"claim": 1})
	if err := collection.FindOne(ctx, bson.M{"uid": uid}, proj).Decode(&doc); err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return nil, errors.NotFound(v1.ErrorReason_USER_NOT_FOUND.String(), "user not found")
		}
		l.Errorf("failed to find user claims: %v", err)
		return nil, fmt.Errorf("aggregate error: %w", err)
	}
	ans := make(map[string]any, len(keys))
	for _, key := range keys {
		ans[key] = nil
	}
	valueParse := func(value any) any {
		if val, ok := value.(bson.DateTime); ok {
			return val.Time().Format(time.RFC3339Nano)
		}
		return value
	}
	if claim, ok := doc["claim"]; ok {
		if claim == nil {
			// present but nil, treat as empty
		} else if profD, ok := claim.(bson.D); ok {
			if keys == nil {
				for _, kv := range profD {
					ans[kv.Key] = valueParse(kv.Value)
				}
			} else {
				for _, kv := range profD {
					if _, needed := ans[kv.Key]; needed {
						ans[kv.Key] = valueParse(kv.Value)
					}
				}
			}
		} else {
			l.Errorf("invalid profile type for user %s: %T", uid, claim)
			return nil, errors.InternalServer("invalid profile type for user: %s", uid)
		}
	}
	return ans, nil
}

// ---- Developer ID ----

func (r *userRepo) GetDeveloperIdInfo(ctx context.Context, uid string) (*string, *time.Time, error) {
	l := log.NewHelper(log.WithContext(ctx, r.log.Logger()))

	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	filter := bson.M{"uid": uid}
	var result struct {
		DeveloperId           *string    `bson:"claim.developer_id"`
		LastUpdateDeveloperId *time.Time `bson:"claim.developer_id_updated_at"`
	}
	err := r.userCollection.FindOne(ctx, filter).Decode(&result)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return nil, nil, errors.NotFound(v1.ErrorReason_USER_NOT_FOUND.String(), "user not found")
		}
		l.Errorf("GetDeveloperIdInfo FindOne error: %v", err)
		return nil, nil, fmt.Errorf("failed to get developer id info: %w", err)
	}
	return result.DeveloperId, result.LastUpdateDeveloperId, nil
}

func (r *userRepo) UpdateDeveloperId(ctx context.Context, uid string, developerId string) error {
	l := log.NewHelper(log.WithContext(ctx, r.log.Logger()))

	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	update := bson.M{
		"$set": bson.M{
			"claim.developer_id":            developerId,
			"claim.developer_id_updated_at": time.Now(),
			"updated_at":                    time.Now(),
		},
	}
	_, err := r.userCollection.UpdateOne(ctx, bson.M{"uid": uid}, update)
	if err != nil {
		if isDuplicateKeyError(err) {
			return errors.New(409, v1.ErrorReason_DEVELOPER_ID_ALREADY_EXIST.String(), "developer id already in use")
		}
		l.Errorf("failed to set user developer id: %v", err)
		return fmt.Errorf("failed to set user developer id: %w", err)
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

// ---- User Consent ----

func (r *userRepo) UpsertUserConsent(ctx context.Context, uid string, clientId string, status string, internalVersion int32, optionalScopes []string) error {
	l := log.NewHelper(log.WithContext(ctx, r.log.Logger()))

	collection := r.userConsentsCollection
	filter := bson.M{"user_id": uid, "client_id": clientId, "type": status}

	update := bson.M{
		"$set": bson.M{
			"optional_scope": optionalScopes,
			"granted_at":     time.Now(),
			"agreed_version": internalVersion,
		},
	}
	opts := options.UpdateOne().SetUpsert(true)
	_, err := collection.UpdateOne(ctx, filter, update, opts)
	if err != nil {
		l.Errorf("failed to upsert user consent: %v", err)
		return err
	}
	return nil
}

func (r *userRepo) DeleteUserConsentByStatus(ctx context.Context, uid string, clientId string, status string) error {
	l := log.NewHelper(log.WithContext(ctx, r.log.Logger()))

	collection := r.userConsentsCollection
	filter := bson.M{"user_id": uid, "client_id": clientId, "type": status}
	err := collection.FindOneAndDelete(ctx, filter).Err()
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			l.Debugf("no user consent found to delete for user %s, client %s, status %s", uid, clientId, status)
			return nil
		}
		l.Errorf("failed to delete user consent: %v", err)
		return err
	}
	return nil
}

// ---- Revoke Consent ----

func (r *userRepo) RevokeUserConsent(ctx context.Context, userId string, clientId string, status string) error {
	l := log.NewHelper(log.WithContext(ctx, r.log.Logger()))

	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	l.Debugf("RevokeUserConsent userId: %s, clientId: %s, status: %s", userId, clientId, status)

	if status != "TEST" && status != "STABLE" && status != "GREY" {
		return errors.BadRequest("400", "invalid status, must be one of: TEST, STABLE, GREY")
	}

	collection := r.userConsentsCollection
	baseFilter := bson.M{
		"user_id":   userId,
		"client_id": clientId,
	}

	if status == "TEST" {
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
				return errors.NotFound(v1.ErrorReason_USER_CONSENT_NOT_FOUND.String(), "user consent not found")
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
		return errors.NotFound(v1.ErrorReason_USER_CONSENT_NOT_FOUND.String(), "user consent not found")
	}

	var allJTIs []string
	for _, doc := range oldDocs {
		allJTIs = append(allJTIs, doc.TokenID...)
	}

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

	if len(allJTIs) > 0 {
		if err := r.RemoveOAuthJTIsFormRedis(ctx, allJTIs); err != nil {
			l.Errorf("RevokeUserConsent STABLE/GREY RemoveOAuthJTIsFormRedis error: %v", err)
			return err
		}
	}
	return nil
}

// ---- Redis JTI Operations ----

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
