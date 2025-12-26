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
	uid, err := primitive.ObjectIDFromHex(userId)
	if err != nil {
		r.log.Errorf("invalid userId format: %s", userId)
		return fmt.Errorf("invalid userId format: %s", userId)
	}
	oldPassword = r.sha256Util.HashPassword(oldPassword)
	newPassword = r.sha256Util.HashPassword(newPassword)
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	reqId := util.RequestIDFrom(ctx)
	r.log.Debugf("RequestID: %s, UpdateUserPassword called with UserId: %s", reqId, userId)

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
		r.log.Errorf("failed to find user: %v, traceId: %s", err, reqId)
		return fmt.Errorf("failed to find user: %w, traceId: %s", err, reqId)
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
		r.log.Errorf("failed to update user password: %v, traceId: %s", err, reqId)
		return fmt.Errorf("failed to update user password: %w, traceId: %s", err, reqId)
	}
	return nil
}

func (r *userRepo) DeleteUserAccount(ctx context.Context, userId string) error {
	uid, err := primitive.ObjectIDFromHex(userId)
	if err != nil {
		r.log.Errorf("invalid userId format: %s", userId)
		return fmt.Errorf("invalid userId format: %s", userId)
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	reqId := util.RequestIDFrom(ctx)
	r.log.Debugf("RequestID: %s, DeleteUserAccount called with UserId: %s", reqId, userId)

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
		r.log.Errorf("failed to find user: %v, traceId: %s", err, reqId)
		return fmt.Errorf("failed to find user: %w, traceId: %s", err, reqId)
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
		r.log.Errorf("failed to delete user account: %v, traceId: %s", err, reqId)
		return fmt.Errorf("failed to delete user account: %w, traceId: %s", err, reqId)
	}
	return nil
}

func (r *userRepo) GetUserProfileById(ctx context.Context, userId string) (*biz.UserProfile, error) {
	uid, err := primitive.ObjectIDFromHex(userId)
	if err != nil {
		r.log.Errorf("invalid userId format: %s", userId)
		return nil, fmt.Errorf("invalid userId format: %s", userId)
	}

	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	reqId := util.RequestIDFrom(ctx)
	r.log.Debugf("RequestID: %s, GetUserProfileById called with UserId: %s", reqId, userId)

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
		r.log.Errorf("failed to aggregate user profile: %v, traceId: %s", err, reqId)
		return nil, fmt.Errorf("failed to aggregate user profile: %w, traceId: %s", err, reqId)
	}
	defer func(cur *mongo.Cursor, ctx context.Context) {
		err := cur.Close(ctx)
		if err != nil {
			r.log.Errorf("failed to close cursor: %v, traceId: %s", err, reqId)
		}
	}(cur, ctx)

	if !cur.Next(ctx) {
		if err := cur.Err(); err != nil {
			r.log.Errorf("cursor error: %v, traceId: %s", err, reqId)
			return nil, fmt.Errorf("cursor error: %w, traceId: %s", err, reqId)
		}
		return nil, biz.UserNotFoundError
	}

	var doc bson.M
	if err := cur.Decode(&doc); err != nil {
		r.log.Errorf("decode error: %v, traceId: %s", err, reqId)
		return nil, fmt.Errorf("decode error: %w, traceId: %s", err, reqId)
	}
	userProfile := biz.UserProfile{
		OfficialAttrs: map[string]string{},
	}

	if userId, ok := doc["_id"].(primitive.ObjectID); ok {
		userProfile.UserId = userId.Hex()
	} else {
		return nil, fmt.Errorf("invalid userId format in db, traceId: %s", reqId)
	}
	if email, ok := doc["email"].(string); ok {
		userProfile.Email = email
	} else {
		return nil, fmt.Errorf("invalid email format in db, traceId: %s", reqId)
	}
	if createdAt, ok := doc["created_at"].(primitive.DateTime); ok {
		userProfile.CreatedAt = createdAt.Time().Unix()
	} else {
		return nil, fmt.Errorf("invalid created_at format in db, traceId: %s", reqId)
	}
	if updatedAt, ok := doc["updated_at"].(primitive.DateTime); ok {
		userProfile.UpdatedAt = updatedAt.Time().Unix()
	} else {
		return nil, fmt.Errorf("invalid updated_at format in db, traceId: %s", reqId)
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
	uid, err := primitive.ObjectIDFromHex(userId)
	if err != nil {
		r.log.Errorf("invalid userId format: %s", userId)
		return fmt.Errorf("invalid userId format: %s", userId)
	}

	count := len(attrs)
	if int64(count) > r.officialInfoMemoryLimitation {
		r.log.Errorf("official info memory limitation exceeded: %d > %d", count, r.officialInfoMemoryLimitation)
		return biz.OfficialInfoMemoryLimitationExceededError
	}

	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	reqId := util.RequestIDFrom(ctx)
	r.log.Debugf("RequestID: %s, UpdateUserProfile called with UserId: %s", reqId, userId)

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
		r.log.Errorf("failed to find user: %v, traceId: %s", err, reqId)
		return fmt.Errorf("failed to find user: %w, traceId: %s", err, reqId)
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
		r.log.Errorf("failed to update user profile: %v, traceId: %s", err, reqId)
		return fmt.Errorf("failed to update user profile: %w, traceId: %s", err, reqId)
	}
	return nil
}
