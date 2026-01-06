package data

import (
	"context"
	"errors"
	"fmt"
	"iwut-auth-center/internal/biz"
	"iwut-auth-center/internal/conf"
	"iwut-auth-center/internal/util"
	"time"

	"github.com/go-kratos/kratos/v2/log"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
)

type userRepo struct {
	data                         *Data
	log                          *log.Helper
	userCollection               *mongo.Collection
	sha256Util                   *util.Sha256Util
	officialInfoMemoryLimitation int64
}

func NewUserRepo(data *Data, c *conf.Data, logger log.Logger, sha256Util *util.Sha256Util) biz.UserRepo {
	dbName := c.GetMongodb().GetDatabase()
	usersCollection := data.mongo.Database(dbName).Collection("user")
	return &userRepo{
		data:                         data,
		log:                          log.NewHelper(logger),
		userCollection:               usersCollection,
		sha256Util:                   sha256Util,
		officialInfoMemoryLimitation: c.GetMongodb().GetLimitations().GetUser().GetOfficialMemLimit(),
	}
}

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
